#pragma once

// Error-path harnesses: construct valid state, corrupt it, trigger error handling

static void harness_corrupted_bls_key(void) {
    int errStatus = 0;
    char err_string[1024] = {0};

    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0 || encLen > 1000) return;

    int num_corruptions = g_fdp->ConsumeIntegralInRange<int>(1, 8);
    for (int i = 0; i < num_corruptions; i++) {
        int pos = g_fdp->ConsumeIntegralInRange<int>(0, (int)encLen - 1);
        encryptedKey[pos] ^= 0xFF;
    }

    char hashX[4] = "123";
    char hashY[4] = "456";
    char signature[1024] = {0};
    trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string, encryptedKey, encLen,
                          hashX, hashY, signature);

    char public_decryption_value[20] = "1:2:3:4";
    char decrption_share[320] = {0};
    trustedGetDecryptionShare(__g_harness_eid, &errStatus, err_string, encryptedKey,
                              public_decryption_value, encLen, decrption_share);

    char bls_pub_key[320] = {0};
    trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string, encryptedKey, encLen, bls_pub_key);
}

static void harness_bls_create_empty_shares(void) {
    int errStatus = 0;
    char err_string[1024] = {0};

    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) return;

    uint8_t encr_bls_key[1024] = {0};
    uint64_t enc_bls_key_len = 0;
    trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string, "", encryptedKey, encLen, encr_bls_key, &enc_bls_key_len);

    uint8_t encr_bls_key_v2[1024] = {0};
    uint64_t enc_bls_key_len_v2 = 0;
    trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string, "", encryptedKey, encLen, encr_bls_key_v2, &enc_bls_key_len_v2);
}

static void harness_dkg_t_greater_n(void) {
    int errStatus = 0;
    char err_string[1024] = {0};

    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    uint8_t _t = g_fdp->ConsumeIntegralInRange<uint8_t>(3, 5);
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, _t);
    if (errStatus != 0 || enc_len == 0) return;

    char pub_keyB[129] = "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc";
    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = (uint8_t)(_t - 1);
    uint8_t ind = 1;

    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, (uint8_t)_t, _n, ind);

    trustedGetEncryptedSecretShareV2(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                     encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, (uint8_t)_t, _n, ind);
}

static void harness_corrupted_dkg_verify(void) {
    int errStatus = 0;
    char err_string[1024] = {0};

    char pub_keyB[129] = "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc";

    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    uint8_t _t = g_fdp->ConsumeIntegralInRange<uint8_t>(2, 4);
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, _t);
    if (errStatus != 0 || enc_len == 0) return;

    char public_shares[10000] = {0};
    trustedGetPublicShares(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len, public_shares, _t);

    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = (uint8_t)(_t + 1);
    uint8_t ind = 1;
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, (uint8_t)_t, _n, ind);
    if (strlen(result_str) < 128 || dec_len == 0) return;

    if (g_fdp->ConsumeProbability<double>() < 0.5) {
        // Corrupt result_str to trigger session_key_recover / xor_decrypt errors
        int num_corruptions = g_fdp->ConsumeIntegralInRange<int>(1, 10);
        for (int i = 0; i < num_corruptions; i++) {
            int pos = g_fdp->ConsumeIntegralInRange<int>(0, 191);
            result_str[pos] = 'g' + (result_str[pos] % 10);
        }
    } else {
        // Corrupt public_shares to trigger Verification errors (invalid G2 points)
        int num_corruptions = g_fdp->ConsumeIntegralInRange<int>(1, 20);
        for (int i = 0; i < num_corruptions; i++) {
            int pos = g_fdp->ConsumeIntegralInRange<int>(0, 9999);
            public_shares[pos] = 'g' + (public_shares[pos] % 10);
        }
    }

    int result = 0;
    int _ind = g_fdp->ConsumeIntegral<int>();
    trustedDkgVerify(__g_harness_eid, &errStatus, err_string, public_shares, result_str,
                     encrypted_skey, dec_len, (unsigned)_t, _ind, &result);

    trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string, public_shares, result_str,
                       encrypted_skey, dec_len, (unsigned)_t, _ind, &result);
}

static void harness_setsek_invalid(void) {
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t invalid_sek[1024] = {0};
    g_fdp->ConsumeData(invalid_sek, 512);
    trustedSetSEK(__g_harness_eid, &errStatus, err_string, invalid_sek);
}

static void harness_bls_sign_invalid_hash(void) {
    // Trigger non-digit hash validation error in enclave_sign
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

static void harness_ecdsa_sign_invalid_hash(void) {
    // Trigger invalid message hash error in trustedEcdsaSign (mpz_set_str fails)
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

    char hash[32] = "xyz";
    char sig_r[1024] = {0};
    char sig_s[1024] = {0};
    uint8_t sig_v = 0;
    int base = 16;
    trustedEcdsaSign(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len,
                     hash, sig_r, sig_s, &sig_v, base);
}

static void harness_ecdsa_sign_invalid_key(void) {
    // Trigger invalid secret key error in trustedEcdsaSign (mpz_set_str fails)
    // Encrypt a non-hex key via trustedEncryptKey, then pass to trustedEcdsaSign
    int errStatus = 0;
    char err_string[1024] = {0};

    char key[32] = "xyz";
    uint8_t encrypted_key[1024] = {0};
    uint64_t enc_len = 0;
    trustedEncryptKey(__g_harness_eid, &errStatus, err_string, key, encrypted_key, &enc_len);
    if (errStatus != 0 || enc_len == 0) return;

    char hash[32] = "1234";
    char sig_r[1024] = {0};
    char sig_s[1024] = {0};
    uint8_t sig_v = 0;
    int base = 16;
    trustedEcdsaSign(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len,
                     hash, sig_r, sig_s, &sig_v, base);
}

static void harness_create_bls_corrupted_share(void) {
    // Trigger mpz_set_str error in trustedCreateBlsKey by corrupting share data
    int errStatus = 0;
    char err_string[1024] = {0};

    int is_exportable = 0;
    uint8_t encrypted_ecdsa_key[1024] = {0};
    uint64_t ecdsa_enc_len = 0;
    char pub_x[1024] = {0};
    char pub_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            encrypted_ecdsa_key, &ecdsa_enc_len, pub_x, pub_y);
    if (errStatus != 0 || ecdsa_enc_len == 0) return;

    char pub_keyB[129] = "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc";

    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, 3);
    if (errStatus != 0 || enc_len == 0) return;

    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, 3, 4, 1);
    if (strlen(result_str) < 128 || dec_len == 0) return;

    // Corrupt first 64 chars (encr_sshare region) to make xor_decrypt produce non-hex
    for (int i = 0; i < 64; i++) {
        result_str[i] = 'g';
    }

    uint8_t encr_bls_key[1024] = {0};
    uint64_t enc_bls_key_len = 0;
    trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string, result_str,
                        encrypted_ecdsa_key, ecdsa_enc_len, encr_bls_key, &enc_bls_key_len);
}

static void harness_create_bls_corrupted_share_v2(void) {
    // V2 variant: trigger mpz_set_str error in trustedCreateBlsKeyV2
    int errStatus = 0;
    char err_string[1024] = {0};

    int is_exportable = 0;
    uint8_t encrypted_ecdsa_key[1024] = {0};
    uint64_t ecdsa_enc_len = 0;
    char pub_x[1024] = {0};
    char pub_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            encrypted_ecdsa_key, &ecdsa_enc_len, pub_x, pub_y);
    if (errStatus != 0 || ecdsa_enc_len == 0) return;

    char pub_keyB[129] = "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc";

    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, 3);
    if (errStatus != 0 || enc_len == 0) return;

    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    trustedGetEncryptedSecretShareV2(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                     encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, 3, 4, 1);
    if (strlen(result_str) < 128 || dec_len == 0) return;

    for (int i = 0; i < 64; i++) {
        result_str[i] = 'g';
    }

    uint8_t encr_bls_key[1024] = {0};
    uint64_t enc_bls_key_len = 0;
    trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string, result_str,
                          encrypted_ecdsa_key, ecdsa_enc_len, encr_bls_key, &enc_bls_key_len);
}

HARNESS_REGISTER(harness_corrupted_bls_key, 55)
HARNESS_REGISTER(harness_bls_create_empty_shares, 50)
HARNESS_REGISTER(harness_dkg_t_greater_n, 55)
HARNESS_REGISTER(harness_corrupted_dkg_verify, 55)
// HARNESS_REGISTER(harness_setsek_invalid, 50)  // DISABLED: triggers CALL_ONCE abort
HARNESS_REGISTER(harness_bls_sign_invalid_hash, 55)
HARNESS_REGISTER(harness_ecdsa_sign_invalid_hash, 55)
HARNESS_REGISTER(harness_ecdsa_sign_invalid_key, 55)
HARNESS_REGISTER(harness_create_bls_corrupted_share, 55)
HARNESS_REGISTER(harness_create_bls_corrupted_share_v2, 55)
