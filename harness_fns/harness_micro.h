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
    pre_harness_init(); // ensure enclave is initialized (curve, SEK)
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
    pre_harness_init(); // ensure enclave is initialized (curve, SEK)
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
    pre_harness_init(); // ensure enclave is initialized (curve, SEK)
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
    pre_harness_init(); // ensure enclave is initialized (curve, SEK)
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

static void harness_micro_ecdsa_bad_hash_fixed(void) {
    pre_harness_init();
    // Zero-consumption: generate valid key, sign with fixed non-hex hash
    // Triggers "invalid message hash" error path (mpz_set_str returns -1)
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
    char hash[65] = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
    char sig_r[1024] = {0};
    char sig_s[1024] = {0};
    uint8_t sig_v = 0;
    trustedEcdsaSign(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len,
                     hash, sig_r, sig_s, &sig_v, 16);
}

static void harness_micro_ecdsa_corrupt_key_fixed(void) {
    pre_harness_init();
    // Zero-consumption: generate valid key, corrupt byte 0, sign with valid hash
    // Triggers AES decrypt failure or "invalid secret key" path
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
    // Flip first byte — guaranteed corruption of AES-GCM ciphertext
    encrypted_key[0] ^= 0xFF;
    char hash[65] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    char sig_r[1024] = {0};
    char sig_s[1024] = {0};
    uint8_t sig_v = 0;
    trustedEcdsaSign(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len,
                     hash, sig_r, sig_s, &sig_v, 16);
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
HARNESS_REGISTER(harness_micro_ecdsa_bad_hash_fixed, 50)
HARNESS_REGISTER(harness_micro_ecdsa_corrupt_key_fixed, 50)

static void harness_micro_bls_sign_invalid_hash_fixed(void) {
    // Zero-consumption: generate valid BLS key, sign with non-digit hash
    // Triggers enclave_sign "Non-digit characters" → false → !enclave_sign error branch
    // in trustedBlsSignMessage (covers 2 uncovered edges)
    int errStatus = 0;
    char err_string[1024] = {0};

    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) return;

    char hashX[4] = "xyz";
    char hashY[4] = "abc";
    char signature[1024] = {0};
    trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string, encryptedKey, encLen,
                          hashX, hashY, signature);
}

static void harness_micro_bls_corrupt_key_sign_fixed(void) {
    // Zero-consumption: generate valid BLS key, corrupt byte 0, sign with valid digit hash
    // Triggers keyFromString failure in enclave_sign → false → !enclave_sign error branch
    // + strnlen(sig) < 10 check in trustedBlsSignMessage (covers 2 uncovered edges)
    int errStatus = 0;
    char err_string[1024] = {0};

    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) return;

    encryptedKey[0] ^= 0xFF;
    char hashX[8] = "12345";
    char hashY[8] = "67890";
    char signature[1024] = {0};
    trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string, encryptedKey, encLen,
                          hashX, hashY, signature);
}

HARNESS_REGISTER(harness_micro_bls_sign_invalid_hash_fixed, 50)
HARNESS_REGISTER(harness_micro_bls_corrupt_key_sign_fixed, 50)

// Zero-consumption error-path micro harnesses for corrupted-key scenarios
// These target AES_decrypt failure branches in enclave functions

static void harness_micro_bls_pub_corrupt_key_fixed(void) {
    // Generate valid BLS key, corrupt it, call GetBlsPubKey
    // Triggers AES_decrypt failure → CHECK_STATUS2 branch in trustedGetBlsPubKey
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) return;
    // Corrupt the encrypted key to trigger AES_decrypt failure
    encryptedKey[0] ^= 0xFF;
    encryptedKey[1] ^= 0xAA;
    char bls_pub[320] = {0};
    trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string, encryptedKey, encLen, bls_pub);
}

static void harness_micro_decryption_share_corrupt_key_fixed(void) {
    // Generate valid BLS key, corrupt it, call GetDecryptionShare
    // Triggers AES_decrypt failure → CHECK_STATUS2 branch in trustedGetDecryptionShare
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) return;
    // Corrupt the encrypted key
    encryptedKey[0] ^= 0xFF;
    encryptedKey[1] ^= 0xAA;
    char public_decryption_value[129] = {0};
    memset(public_decryption_value, '1', 128);
    char decryption_share[320] = {0};
    trustedGetDecryptionShare(__g_harness_eid, &errStatus, err_string, encryptedKey,
                               public_decryption_value, encLen, decryption_share);
}

static void harness_micro_public_shares_corrupt_dkg_fixed(void) {
    // Generate valid DKG secret, corrupt it, call GetPublicShares with valid _t
    // Triggers AES_decrypt failure → CHECK_STATUS2 branch in trustedGetPublicShares
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, 2);
    if (errStatus != 0 || enc_len == 0) return;
    // Corrupt the encrypted DKG secret
    encrypted_dkg_secret[0] ^= 0xFF;
    encrypted_dkg_secret[1] ^= 0xAA;
    char public_shares[10000] = {0};
    trustedGetPublicShares(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len, public_shares, 2);
}

static void harness_micro_secret_share_corrupt_poly_fixed(void) {
    // Generate valid DKG secret, corrupt it, call GetEncryptedSecretShare
    // Triggers trustedSetEncryptedDkgPoly failure → CHECK_STATUS2 branch
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, 2);
    if (errStatus != 0 || enc_len == 0) return;
    // Corrupt the encrypted poly
    encrypted_dkg_secret[0] ^= 0xFF;
    encrypted_dkg_secret[1] ^= 0xAA;
    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    char pub_keyB[129] = {0};
    memset(pub_keyB, '1', 128);
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, 2, 3, 1);
}

HARNESS_REGISTER(harness_micro_bls_pub_corrupt_key_fixed, 50)
HARNESS_REGISTER(harness_micro_decryption_share_corrupt_key_fixed, 50)
HARNESS_REGISTER(harness_micro_public_shares_corrupt_dkg_fixed, 50)
HARNESS_REGISTER(harness_micro_secret_share_corrupt_poly_fixed, 50)

// V2 variant: corrupt DKG poly → GetEncryptedSecretShareV2 error path
// Targets trustedSetEncryptedDkgPoly failure in V2 context
// V2 has additional steps (hash_key, xor_encrypt_v2) vs V1, so separate harness needed
static void harness_micro_secret_share_v2_corrupt_poly_fixed(void) {
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, 2);
    if (errStatus != 0 || enc_len == 0) return;
    // Corrupt the encrypted poly
    encrypted_dkg_secret[0] ^= 0xFF;
    encrypted_dkg_secret[1] ^= 0xAA;
    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    char pub_keyB[129] = {0};
    memset(pub_keyB, '1', 128);
    trustedGetEncryptedSecretShareV2(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                     encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, 2, 3, 1);
}

HARNESS_REGISTER(harness_micro_secret_share_v2_corrupt_poly_fixed, 50)

// Burst harness: sign 2000 times to trigger sigCounter % 1000 == 0 path
// in trustedEcdsaSign, which calls signature_verify.
static void harness_ecdsa_sign_burst(void) {
    pre_harness_init();
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

    char hash[65] = "1234567890123456789012345678901234567890123456789012345678901234";
    char sig_r[1024] = {0};
    char sig_s[1024] = {0};
    uint8_t sig_v = 0;

    for (int i = 0; i < 2000; i++) {
        trustedEcdsaSign(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len,
                         hash, sig_r, sig_s, &sig_v, 16);
        if (errStatus != 0) break;
    }
}

// Burst harness: moved to front to ensure visibility with small seeds
// Triggers sigCounter % 1000 == 0 path in trustedEcdsaSign
HARNESS_REGISTER(harness_ecdsa_sign_burst, 30)  // Reduced from 75: 2000-loop burst is very slow

// ============================================================================
// DecryptionShare micro harness — zero byte consumption
// Only harness targeting getDecryptionShare with valid G2 point at low cum_before.
// Replaces harness_bls_decrypt_with_valid_g2 (cum=2610, invisible to corpus).
// getDecryptionShare has only 2 hits / 34% edges — needs valid G2 to reach multiplication.
// ============================================================================
static void harness_micro_decryption_share_valid_g2(void) {
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};

    // Step 1: Generate BLS key (provides valid encryptedPrivateKey)
    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) return;

    // Step 2: Generate DKG secret to obtain a valid G2 point via s_shareG2
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t dkg_enc_len = 0;
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &dkg_enc_len, 2);
    if (errStatus != 0 || dkg_enc_len == 0) return;

    char pub_keyB[129] = "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc";
    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, dkg_enc_len,
                                   encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, 2, 3, 1);
    if (errStatus != 0 || strlen(s_shareG2) == 0) return;

    // Step 3: Pass valid G2 point to GetDecryptionShare
    char decrption_share[320] = {0};
    trustedGetDecryptionShare(__g_harness_eid, &errStatus, err_string, encryptedKey,
                              s_shareG2, encLen, decrption_share);
}
HARNESS_REGISTER(harness_micro_decryption_share_valid_g2, 55)

// ============================================================================
// NULL-parameter micro harnesses — zero byte consumption
// Test CHECK_STATE(param) guards by passing NULL, unlocking error-path edges.
// Each harness targets ONE ECall's NULL-check branches.
// ============================================================================

// trustedGenerateEcdsaKey: 3 NULL checks (encryptedPrivateKey, pub_key_x, pub_key_y)
// Currently 5/13 edges (38%). NULL checks should unlock 3 error-path edges.
static void harness_micro_null_ecdsa_key(void) {
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    int is_exportable = 0;
    uint64_t enc_len = 0;
    // Pass NULL pub_key_x — triggers CHECK_STATE(pub_key_x) failure
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
        &is_exportable, (uint8_t[1024]){0}, &enc_len, NULL, (char[65]){0});
}

// trustedEncryptKey: 2 NULL checks (key, encryptedPrivateKey)
// Currently 2/8 edges (25%). NULL key should unlock error-path.
static void harness_micro_null_encrypt_key(void) {
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    uint64_t enc_len = 0;
    // Pass NULL key — triggers CHECK_STATE(key) failure
    trustedEncryptKey(__g_harness_eid, &errStatus, err_string,
        NULL, (uint8_t[1024]){0}, &enc_len);
}

// trustedDecryptKey: 2 NULL checks (encryptedPrivateKey, key)
// Currently 4/9 edges (44%). NULL checks should unlock 2 edges.
static void harness_micro_null_decrypt_key(void) {
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    uint64_t enc_len = 0;
    // Pass NULL encryptedPrivateKey — triggers CHECK_STATE(encryptedPrivateKey) failure
    trustedDecryptKey(__g_harness_eid, &errStatus, err_string,
        NULL, enc_len, (char[1024]){0});
}

// trustedGenDkgSecret: 1 NULL check (encrypted_dkg_secret)
// Currently 2/7 edges (28%). NULL check unlocks 1 edge.
static void harness_micro_null_dkg_secret(void) {
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    uint64_t enc_len = 0;
    // Pass NULL encrypted_dkg_secret — triggers CHECK_STATE failure
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
        NULL, &enc_len, 2);
}

// trustedGetEncryptedSecretShare: 4 NULL checks (encrypted_skey, result_str, s_shareG2, pub_keyB)
// Currently 5/13 edges (38%). NULL checks should unlock 4 edges.
static void harness_micro_null_secret_share(void) {
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    uint64_t dec_len = 0;
    uint8_t encrypted_poly[3050] = {0};
    // Pass NULL encrypted_skey — triggers CHECK_STATE(encrypted_skey) failure
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string,
        encrypted_poly, sizeof(encrypted_poly),
        NULL, &dec_len, (char[193]){0}, (char[320]){0}, (char[65]){0}, 2, 3, 0);
}

// trustedGetEncryptedSecretShareV2: 4 NULL checks
// Currently 3/14 edges (21%). NULL checks should unlock 4 edges.
static void harness_micro_null_secret_share_v2(void) {
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    uint64_t dec_len = 0;
    uint8_t encrypted_poly[3050] = {0};
    // Pass NULL encrypted_skey — triggers CHECK_STATE(encrypted_skey) failure
    trustedGetEncryptedSecretShareV2(__g_harness_eid, &errStatus, err_string,
        encrypted_poly, sizeof(encrypted_poly),
        NULL, &dec_len, (char[193]){0}, (char[320]){0}, (char[65]){0}, 2, 3, 0);
}

// trustedDkgVerify: 3 NULL checks (public_shares, s_share, encryptedPrivateKey)
// Currently 4/9 edges (44%). NULL checks should unlock 3 edges.
static void harness_micro_null_dkg_verify(void) {
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    int result = 0;
    // Pass NULL public_shares — triggers CHECK_STATE(public_shares) failure
    trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
        NULL, "abc", (uint8_t[1024]){0}, 100, 2, 0, &result);
}

// trustedDkgVerifyV2: 3 NULL checks
// Currently 4/10 edges (40%). NULL checks should unlock 3 edges.
static void harness_micro_null_dkg_verify_v2(void) {
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    int result = 0;
    // Pass NULL public_shares — triggers CHECK_STATE(public_shares) failure
    trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string,
        NULL, "abc", (uint8_t[1024]){0}, 100, 2, 0, &result);
}

// trustedEcdsaSign: 4 CHECK_STATE (encryptedPrivateKey, hash, sigR, sigS)
// Currently 5/13 edges (38%). NULL hash triggers CHECK_STATE(hash) failure path.
static void harness_micro_null_ecdsa_sign_hash(void) {
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    int is_exportable = 0;
    uint64_t enc_len = 0;
    char pub_x[1024] = {0};
    char pub_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            (uint8_t[1024]){0}, &enc_len, pub_x, pub_y);
    if (errStatus != 0 || enc_len == 0) return;
    char sig_r[1024] = {0};
    char sig_s[1024] = {0};
    uint8_t sig_v = 0;
    // Pass NULL hash — triggers CHECK_STATE(hash) failure
    trustedEcdsaSign(__g_harness_eid, &errStatus, err_string, (uint8_t[1024]){0}, enc_len,
                     NULL, sig_r, sig_s, &sig_v, 16);
}

// trustedBlsSignMessage: 4 CHECK_STATE (encryptedPrivateKey, _hashX, _hashY, signature)
// Currently 3/9 edges (33%). NULL hashX triggers CHECK_STATE(_hashX) failure path.
static void harness_micro_null_bls_sign_hash(void) {
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable,
                          (uint8_t[1024]){0}, &encLen);
    if (errStatus != 0 || encLen == 0) return;
    char signature[1024] = {0};
    // Pass NULL _hashX — triggers CHECK_STATE(_hashX) failure
    trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string, (uint8_t[1024]){0}, encLen,
                          NULL, "456", signature);
}

// trustedGetPublicEcdsaKey: 3 CHECK_STATE (encryptedPrivateKey, pub_key_x, pub_key_y)
// Currently 2/11 edges (18%). NULL pub_key_x triggers CHECK_STATE failure.
static void harness_micro_null_get_public_ecdsa(void) {
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    int is_exportable = 0;
    uint64_t enc_len = 0;
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            (uint8_t[1024]){0}, &enc_len, (char[65]){0}, (char[65]){0});
    if (errStatus != 0 || enc_len == 0) return;
    // Pass NULL pub_key_x — triggers CHECK_STATE(pub_key_x) failure
    trustedGetPublicEcdsaKey(__g_harness_eid, &errStatus, err_string,
                             (uint8_t[1024]){0}, enc_len, NULL, (char[1024]){0});
}

// trustedGetBlsPubKey: 3 CHECK_STATE (encryptedPrivateKey, bls_pub_key)
// Currently 3/6 edges (50%). NULL bls_pub_key triggers CHECK_STATE failure.
static void harness_micro_null_get_bls_pub(void) {
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable,
                          (uint8_t[1024]){0}, &encLen);
    if (errStatus != 0 || encLen == 0) return;
    // Pass NULL bls_pub_key — triggers CHECK_STATE failure
    trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string, (uint8_t[1024]){0}, encLen, NULL);
}

// trustedGetDecryptionShare: CHECK_STATE guards
// Currently 2/6 edges (33%). NULL share triggers failure.
static void harness_micro_null_decryption_share(void) {
    pre_harness_init();
    int errStatus = 0;
    char err_string[1024] = {0};
    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable,
                          (uint8_t[1024]){0}, &encLen);
    if (errStatus != 0 || encLen == 0) return;
    // Pass NULL decrption_share — triggers CHECK_STATE failure
    trustedGetDecryptionShare(__g_harness_eid, &errStatus, err_string, (uint8_t[1024]){0},
                              "1:2:3:4", encLen, NULL);
}

// Register all NULL-check micro harnesses with moderate weight
// These are zero-consumption, execute quickly, and unlock error-path edges
HARNESS_REGISTER(harness_micro_null_ecdsa_key, 40)
HARNESS_REGISTER(harness_micro_null_encrypt_key, 40)
HARNESS_REGISTER(harness_micro_null_decrypt_key, 40)
HARNESS_REGISTER(harness_micro_null_dkg_secret, 40)
HARNESS_REGISTER(harness_micro_null_secret_share, 40)
HARNESS_REGISTER(harness_micro_null_secret_share_v2, 40)
HARNESS_REGISTER(harness_micro_null_dkg_verify, 40)
HARNESS_REGISTER(harness_micro_null_dkg_verify_v2, 40)
HARNESS_REGISTER(harness_micro_null_ecdsa_sign_hash, 40)
HARNESS_REGISTER(harness_micro_null_bls_sign_hash, 40)
HARNESS_REGISTER(harness_micro_null_get_public_ecdsa, 40)
HARNESS_REGISTER(harness_micro_null_get_bls_pub, 40)
HARNESS_REGISTER(harness_micro_null_decryption_share, 40)
