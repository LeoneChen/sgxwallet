#pragma once

static void harness_trustedEncryptKey(void) {
    int errStatus = 0;
    char err_string[1024] = {0};
    char key[1024] = {0};
    g_fdp->ConsumeData((uint8_t*)key, 1023);
    key[1023] = '\0';
    uint8_t encrypted_key[1024] = {0};
    uint64_t enc_len = 0;
    trustedEncryptKey(__g_harness_eid, &errStatus, err_string, key, encrypted_key, &enc_len);
}

static void harness_trustedDecryptKey(void) {
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_key[1024] = {0};
    g_fdp->ConsumeData(encrypted_key, 1024);
    uint64_t enc_len = g_fdp->ConsumeIntegral<uint64_t>();
    char key[1024] = {0};
    trustedDecryptKey(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len, key);
}

// DISABLED: high byte consumption (1023/1032 bytes), redundant with minimal/deep harnesses
// HARNESS_REGISTER(harness_trustedEncryptKey, 60)
// HARNESS_REGISTER(harness_trustedDecryptKey, 50)
