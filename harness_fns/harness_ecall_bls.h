#pragma once

static void harness_trustedCreateBlsKey(void) {
    int errStatus = 0;
    char err_string[1024] = {0};
    char s_shares[6145] = {0};
    g_fdp->ConsumeData((uint8_t*)s_shares, 6144);
    s_shares[6144] = '\0';
    uint8_t encrypted_key[1024] = {0};
    g_fdp->ConsumeData(encrypted_key, 1024);
    uint64_t key_len = g_fdp->ConsumeIntegral<uint64_t>();
    uint8_t encr_bls_key[1024] = {0};
    uint64_t enc_bls_key_len = 0;
    trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string, s_shares, encrypted_key,
                        key_len, encr_bls_key, &enc_bls_key_len);
}

static void harness_trustedCreateBlsKeyV2(void) {
    int errStatus = 0;
    char err_string[1024] = {0};
    char s_shares[6145] = {0};
    g_fdp->ConsumeData((uint8_t*)s_shares, 6144);
    s_shares[6144] = '\0';
    uint8_t encrypted_key[1024] = {0};
    g_fdp->ConsumeData(encrypted_key, 1024);
    uint64_t key_len = g_fdp->ConsumeIntegral<uint64_t>();
    uint8_t encr_bls_key[1024] = {0};
    uint64_t enc_bls_key_len = 0;
    trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string, s_shares, encrypted_key,
                          key_len, encr_bls_key, &enc_bls_key_len);
}

static void harness_trustedBlsSignMessage(void) {
    // Need valid encrypted key; generate one first
    int errStatus = 0;
    char errString[1024] = {0};
    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, errString, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) {
        return;
    }

    char err_string[256] = {0};
    // hashX/hashY must be all-digit decimal strings for enclave_sign validation
    char hashX[80] = {0};
    int hashXLen = g_fdp->ConsumeIntegralInRange<int>(1, 77);
    for (int i = 0; i < hashXLen; i++) {
        hashX[i] = '0' + (g_fdp->ConsumeIntegral<uint8_t>() % 10);
    }
    hashX[hashXLen] = '\0';

    char hashY[80] = {0};
    int hashYLen = g_fdp->ConsumeIntegralInRange<int>(1, 77);
    for (int i = 0; i < hashYLen; i++) {
        hashY[i] = '0' + (g_fdp->ConsumeIntegral<uint8_t>() % 10);
    }
    hashY[hashYLen] = '\0';

    char signature[1024] = {0};
    trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string, encryptedKey, encLen,
                          hashX, hashY, signature);
}

static void harness_trustedGetBlsPubKey(void) {
    // Need valid encrypted key; generate one first
    int errStatus = 0;
    char errString[1024] = {0};
    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, errString, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0) {
        return;
    }

    char err_string[1024] = {0};
    char bls_pub_key[320] = {0};
    trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string, encryptedKey, encLen, bls_pub_key);
}

static void harness_trustedGetDecryptionShare(void) {
    // Need valid encrypted key; generate one first
    int errStatus = 0;
    char errString[1024] = {0};
    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, errString, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) {
        return;
    }

    char err_string[1024] = {0};
    // public_decryption_value must be 4 colon-separated decimal numbers for getDecryptionShare
    char public_decryption_value[400] = {0};
    int pos = 0;
    for (int part = 0; part < 4; part++) {
        int len = g_fdp->ConsumeIntegralInRange<int>(1, 77);
        for (int i = 0; i < len; i++) {
            public_decryption_value[pos++] = '0' + (g_fdp->ConsumeIntegral<uint8_t>() % 10);
        }
        if (part < 3) {
            public_decryption_value[pos++] = ':';
        }
    }
    public_decryption_value[pos] = '\0';

    char decrption_share[320] = {0};
    trustedGetDecryptionShare(__g_harness_eid, &errStatus, err_string, encryptedKey,
                              public_decryption_value, encLen, decrption_share);
}

static void harness_trustedGenerateBLSKey(void) {
    int errStatus = 0;
    char errString[1024] = {0};
    int isExportable = g_fdp->ConsumeIntegralInRange<int>(0, 1);
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, errString, &isExportable, encryptedKey, &encLen);
}

static void harness_malformed_bls_sign(void) {
    // Generate valid BLS key, then pass hashX/hashY with non-digit characters
    // to trigger error paths in enclave_sign (libff digit validation)
    int errStatus = 0;
    char errString[1024] = {0};
    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, errString, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) return;

    char hashX[80] = {0};
    g_fdp->ConsumeData((uint8_t*)hashX, 77);
    hashX[77] = '\0';
    // Inject non-digit characters to guarantee isAllDigits failure
    for (int i = 0; i < 5; i++) {
        int pos = g_fdp->ConsumeIntegralInRange<int>(0, 76);
        hashX[pos] = 'a' + (hashX[pos] % 26);
    }

    char hashY[80] = {0};
    g_fdp->ConsumeData((uint8_t*)hashY, 77);
    hashY[77] = '\0';
    for (int i = 0; i < 5; i++) {
        int pos = g_fdp->ConsumeIntegralInRange<int>(0, 76);
        hashY[pos] = 'a' + (hashY[pos] % 26);
    }

    char signature[1024] = {0};
    trustedBlsSignMessage(__g_harness_eid, &errStatus, errString, encryptedKey, encLen,
                          hashX, hashY, signature);
}

// DISABLED: high byte consumption (166-7176 bytes), redundant with minimal/deep harnesses
// HARNESS_REGISTER(harness_trustedCreateBlsKey, 60)
// HARNESS_REGISTER(harness_trustedCreateBlsKeyV2, 70)
// HARNESS_REGISTER(harness_trustedBlsSignMessage, 65)
// HARNESS_REGISTER(harness_trustedGetDecryptionShare, 35)
// DISABLED: redundant with bls_success_path/bls_full_lifecycle (cum_before > 3000, wastes selection probability)
// HARNESS_REGISTER(harness_trustedGetBlsPubKey, 35)
// DISABLED: redundant with minimal_bls_create/bls_success_path (cum_before > 3000, wastes selection probability)
// HARNESS_REGISTER(harness_trustedGenerateBLSKey, 60)
// DISABLED: redundant with harness_bls_sign_invalid_hash in error_paths.h (earlier, same error path)
// HARNESS_REGISTER(harness_malformed_bls_sign, 40)
