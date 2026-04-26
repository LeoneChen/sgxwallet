#pragma once

// ============================================================================
// Micro + Early Minimal Harnesses — Zero byte consumption, placed early in registry
// Targets under-covered functions with both success-path and error-path hits.
// Designed to be selectable even with 1-byte seeds.
// ============================================================================

static void harness_minimal_bls_sign(void) {
    // Minimal BLS sign: generate key, sign with tiny fixed hash
    // Consumes ZERO fuzz bytes beyond weight selection — works with 1-byte seeds
    int errStatus = 0;
    char err_string[1024] = {0};

    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) return;

    char hashX[4] = "123";
    char hashY[4] = "456";
    char signature[1024] = {0};
    trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string, encryptedKey, encLen,
                          hashX, hashY, signature);
}

static void harness_minimal_ecdsa_sign(void) {
    // Minimal ECDSA sign: generate key, sign with tiny fixed hash
    // Consumes ZERO fuzz bytes beyond weight selection — works with 1-byte seeds
    int errStatus = 0;
    char err_string[1024] = {0};

    int is_exportable = 0;
    uint8_t encrypted_key[1024] = {0};
    uint64_t enc_len = 0;
    char pub_x[1024] = {0};
    char pub_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            encrypted_key, &enc_len, pub_x, pub_y);
    if (errStatus != 0 || enc_len == 0) return;

    char hash[65] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    char sig_r[1024] = {0};
    char sig_s[1024] = {0};
    uint8_t sig_v = 0;
    trustedEcdsaSign(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len,
                     hash, sig_r, sig_s, &sig_v, 16);
}

static void harness_micro_get_public_ecdsa_valid(void) {
    // Minimal success-path harness for trustedGetPublicEcdsaKey
    int errStatus = 0;
    char err_string[1024] = {0};
    int is_exportable = 0;
    uint8_t encrypted_key[1024] = {0};
    uint64_t enc_len = 0;
    char pub_x[1024] = {0};
    char pub_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            encrypted_key, &enc_len, pub_x, pub_y);
    if (errStatus != 0 || enc_len == 0) return;
    char pk_x[1024] = {0};
    char pk_y[1024] = {0};
    trustedGetPublicEcdsaKey(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len, pk_x, pk_y);
}

static void harness_micro_get_bls_pub_valid(void) {
    // Minimal success-path harness for trustedGetBlsPubKey
    int errStatus = 0;
    char err_string[1024] = {0};
    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) return;
    char bls_pub[320] = {0};
    trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string, encryptedKey, encLen, bls_pub);
}

static void harness_micro_dkg_t_zero(void) {
    // _t=0 triggers gen_dkg_poly failure (empty polynomial) → CHECK_STATUS error path
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, 0);
}

static void harness_micro_public_shares_t_zero(void) {
    // _t=0 triggers CHECK_STATE(_t > 0) error path in trustedGetPublicShares
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_dkg_secret[3072] = {0};
    char public_shares[10000] = {0};
    trustedGetPublicShares(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, 0, public_shares, 0);
}

static void harness_micro_get_public_ecdsa_zero_len(void) {
    // enc_len=0 triggers AES decrypt / validation error path
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_key[1024] = {0};
    char pub_x[1024] = {0};
    char pub_y[1024] = {0};
    trustedGetPublicEcdsaKey(__g_harness_eid, &errStatus, err_string, encrypted_key, 0, pub_x, pub_y);
}

static void harness_micro_get_bls_pub_zero_len(void) {
    // encLen=0 triggers validation error path
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encryptedKey[1024] = {0};
    char bls_pub[320] = {0};
    trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string, encryptedKey, 0, bls_pub);
}

static void harness_micro_decrypt_dkg_zero_len(void) {
    // enc_len=0 triggers CHECK_STATE / AES decrypt error path
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint8_t decrypted[3072] = {0};
    trustedDecryptDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, 0, decrypted);
}

static void harness_micro_minimal_encrypt(void) {
    // Minimal harness for trustedEncryptKey with a fixed small key
    // Consumes zero fuzz bytes to work with tiny seeds
    int errStatus = 0;
    char err_string[1024] = {0};
    char key[32] = "testkey";
    uint8_t encrypted_key[1024] = {0};
    uint64_t enc_len = 0;
    trustedEncryptKey(__g_harness_eid, &errStatus, err_string, key, encrypted_key, &enc_len);
}

static void harness_micro_ecdsa_exportable(void) {
    // Minimal harness: generate EXPORTABLE ECDSA key to cover the is_exportable branch
    // Consumes zero fuzz bytes
    int errStatus = 0;
    char err_string[1024] = {0};
    int is_exportable = 1;
    uint8_t encrypted_key[1024] = {0};
    uint64_t enc_len = 0;
    char pub_x[1024] = {0};
    char pub_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            encrypted_key, &enc_len, pub_x, pub_y);
}

static void harness_micro_bls_exportable(void) {
    // Minimal harness: generate EXPORTABLE BLS key to cover the isExportable branch
    // Consumes zero fuzz bytes
    int errStatus = 0;
    char err_string[1024] = {0};
    int isExportable = 1;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable, encryptedKey, &encLen);
}

static void harness_micro_encrypt_max_length_key(void) {
    // Trigger decryptedKeyLen == MAX_KEY_LENGTH (128) branch in trustedEncryptKey
    int errStatus = 0;
    char err_string[1024] = {0};
    char key[129] = {0};
    memset(key, 'A', 128);
    uint8_t encrypted_key[1024] = {0};
    uint64_t enc_len = 0;
    trustedEncryptKey(__g_harness_eid, &errStatus, err_string, key, encrypted_key, &enc_len);
}

static void harness_micro_dkg_verify_empty(void) {
    // Empty inputs trigger early validation error paths in trustedDkgVerify
    int errStatus = 0;
    char err_string[1024] = {0};
    int result = 0;
    uint8_t key[1] = {0};
    trustedDkgVerify(__g_harness_eid, &errStatus, err_string, "", "",
                     key, 0, 1, 0, &result);
}

static void harness_micro_dkg_verify_v2_empty(void) {
    // Empty inputs trigger early validation error paths in trustedDkgVerifyV2
    int errStatus = 0;
    char err_string[1024] = {0};
    int result = 0;
    uint8_t key[1] = {0};
    trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string, "", "",
                       key, 0, 1, 0, &result);
}

HARNESS_REGISTER(harness_minimal_bls_sign, 70)
HARNESS_REGISTER(harness_minimal_ecdsa_sign, 70)
HARNESS_REGISTER(harness_micro_get_public_ecdsa_valid, 65)
HARNESS_REGISTER(harness_micro_get_bls_pub_valid, 65)
HARNESS_REGISTER(harness_micro_dkg_t_zero, 60)
HARNESS_REGISTER(harness_micro_public_shares_t_zero, 60)
HARNESS_REGISTER(harness_micro_get_public_ecdsa_zero_len, 55)
HARNESS_REGISTER(harness_micro_get_bls_pub_zero_len, 55)
HARNESS_REGISTER(harness_micro_decrypt_dkg_zero_len, 55)
HARNESS_REGISTER(harness_micro_minimal_encrypt, 70)
HARNESS_REGISTER(harness_micro_ecdsa_exportable, 85)
HARNESS_REGISTER(harness_micro_bls_exportable, 85)
HARNESS_REGISTER(harness_micro_encrypt_max_length_key, 50)
HARNESS_REGISTER(harness_micro_dkg_verify_empty, 55)
HARNESS_REGISTER(harness_micro_dkg_verify_v2_empty, 55)
