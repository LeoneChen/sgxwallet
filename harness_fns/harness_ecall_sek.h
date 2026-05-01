#pragma once

static void harness_trustedGenerateSEK(void) {
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_SEK[1024] = {0};
    uint64_t enc_len = 0;
    char hex_SEK[65] = {0};
    trustedGenerateSEK(__g_harness_eid, &errStatus, err_string, encrypted_SEK, &enc_len, hex_SEK);
}

static void harness_trustedSetSEK(void) {
    int errStatus = 0;
    char err_string[1024] = {0};
    // Use fuzz data (error path testing)
    uint8_t encrypted_SEK[1024] = {0};
    g_fdp->ConsumeData(encrypted_SEK, 1024);
    trustedSetSEK(__g_harness_eid, &errStatus, err_string, encrypted_SEK);
}

static void harness_trustedSetSEK_valid(void) {
    // Generate SEK locally, then use it for trustedSetSEK success path
    // Note: CALL_ONCE means this only works on first invocation per enclave
    pre_harness_init();  // Initialize enclave (curve)
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_SEK[1024] = {0};
    uint64_t enc_len = 0;
    char hex_SEK[65] = {0};
    trustedGenerateSEK(__g_harness_eid, &errStatus, err_string, encrypted_SEK, &enc_len, hex_SEK);
    if (errStatus != 0 || enc_len == 0) return;  // CALL_ONCE already used or failed
    trustedSetSEK(__g_harness_eid, &errStatus, err_string, encrypted_SEK);
}

// PATH_C: backup restore path. Use a valid external 32-byte SEK hex string,
// matching SEKManager::check_and_set_SEK(), without first calling GenerateSEK.
static void harness_setsek_backup_path(void) {
    pre_harness_init();  // Initialize enclave (curve)
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t backup_encrypted_SEK[1024] = {0};
    uint64_t backup_enc_len = 0;
    char hex_SEK[65] = "00112233445566778899aabbccddeeff";
    trustedSetSEKBackup(__g_harness_eid, &errStatus, err_string, backup_encrypted_SEK, &backup_enc_len, hex_SEK);
}

// PATH_A continued: GenerateSEK → EncryptKey (tests AES_key set by GenerateSEK)
static void harness_encrypt_after_generate_sek(void) {
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_SEK[1024] = {0};
    uint64_t enc_len = 0;
    char hex_SEK[65] = {0};
    trustedGenerateSEK(__g_harness_eid, &errStatus, err_string, encrypted_SEK, &enc_len, hex_SEK);
    if (errStatus != 0 || enc_len == 0) return;
    // Now AES_key is set by GenerateSEK, test EncryptKey
    char key[32] = "testkey1234567890abcdef";
    uint8_t enc_key[1024] = {0};
    uint64_t enc_key_len = 0;
    trustedEncryptKey(__g_harness_eid, &errStatus, err_string, key, enc_key, &enc_key_len);
    if (errStatus != 0 || enc_key_len == 0) return;
    // Also test DecryptKey roundtrip
    char decrypted[1024] = {0};
    trustedDecryptKey(__g_harness_eid, &errStatus, err_string, enc_key, enc_key_len, decrypted);
}

// SEK path harnesses — registered here (included early after harness_micro.h)
// These test different SEK initialization paths within a single enclave lifecycle
HARNESS_REGISTER(harness_trustedSetSEK_valid, 75)
HARNESS_REGISTER(harness_setsek_backup_path, 70)
HARNESS_REGISTER(harness_encrypt_after_generate_sek, 80)

// DISABLED: redundant with pre_harness_init() which can be called by harnesses that need SEK
// HARNESS_REGISTER(harness_trustedGenerateSEK, 20)
// DISABLED: uses raw fuzz data → sgx_unseal_data almost always fails, not useful
// HARNESS_REGISTER(harness_trustedSetSEK, 20)
// HARNESS_REGISTER(harness_trustedSetSEKBackup, 25)
