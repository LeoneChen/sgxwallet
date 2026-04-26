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
    // Use the globally-generated valid SEK from customized_harness()
    // This tests the success path with properly formatted encrypted SEK
    int errStatus = 0;
    char err_string[1024] = {0};
    trustedSetSEK(__g_harness_eid, &errStatus, err_string, g_encrypted_SEK);
}

static void harness_trustedSetSEKBackup(void) {
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_SEK[1024] = {0};
    uint64_t enc_len = 0;
    char SEK_hex[256] = {0};
    g_fdp->ConsumeData((uint8_t*)SEK_hex, 255);
    SEK_hex[255] = '\0';
    trustedSetSEKBackup(__g_harness_eid, &errStatus, err_string, encrypted_SEK, &enc_len, SEK_hex);
}

// DISABLED: redundant with customized_harness() which already calls trustedGenerateSEK every iteration
// HARNESS_REGISTER(harness_trustedGenerateSEK, 20)
// DISABLED: trustedSetSEK and trustedSetSEKBackup still use CALL_ONCE with abort().
// In SGX simulation mode static variables persist across enclave instances,
// so any harness calling these after the first iteration triggers abort.
// Re-enable after PATCHING path fixes CALL_ONCE to early-return.
// HARNESS_REGISTER(harness_trustedSetSEK, 20)
// HARNESS_REGISTER(harness_trustedSetSEK_valid, 75)
// HARNESS_REGISTER(harness_trustedSetSEKBackup, 25)
