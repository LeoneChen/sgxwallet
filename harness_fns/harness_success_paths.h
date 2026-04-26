#pragma once

// Success-path harnesses: generate valid keys/state first, then exercise
// dependent ECalls. These complement the existing error-path harnesses.

static void harness_ecdsa_success_path(void) {
    int errStatus = 0;
    char err_string[1024] = {0};

    // Step 1: Generate valid ECDSA key
    int is_exportable = 0;
    uint8_t encrypted_key[1024] = {0};
    uint64_t enc_len = 0;
    char pub_key_x[1024] = {0};
    char pub_key_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            encrypted_key, &enc_len, pub_key_x, pub_key_y);
    if (errStatus != 0 || enc_len == 0) return;

    // Step 2: Get public key with valid encrypted key
    char pk_x[1024] = {0};
    char pk_y[1024] = {0};
    trustedGetPublicEcdsaKey(__g_harness_eid, &errStatus, err_string, encrypted_key,
                             enc_len, pk_x, pk_y);

    // Step 3: Sign with valid key (if fuzz data remains)
    if (g_fdp->remaining_bytes() > 0) {
        char hash[256] = {0};
        if (g_fdp->remaining_bytes() >= 64) {
            g_fdp->ConsumeData((uint8_t*)hash, 64);
        } else {
            g_fdp->ConsumeData((uint8_t*)hash, g_fdp->remaining_bytes());
        }
        hash[64] = '\0';
        char sig_r[1024] = {0};
        char sig_s[1024] = {0};
        uint8_t sig_v = 0;
        int base = g_fdp->ConsumeIntegralInRange<int>(0, 16);
        trustedEcdsaSign(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len,
                         hash, sig_r, sig_s, &sig_v, base);
    }
}

static void harness_bls_success_path(void) {
    int errStatus = 0;
    char err_string[1024] = {0};

    // Step 1: Generate valid BLS key
    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) return;

    // Step 2: Get BLS pub key
    char bls_pub_key[320] = {0};
    trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string, encryptedKey, encLen, bls_pub_key);

    // Step 3: Sign with valid key
    if (g_fdp->remaining_bytes() > 0) {
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

    // Step 4: Get decryption share with valid key
    if (g_fdp->remaining_bytes() > 0) {
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
}

static void harness_encrypt_roundtrip(void) {
    int errStatus = 0;
    char err_string[1024] = {0};

    // Step 1: Encrypt a key
    char key[1024] = {0};
    size_t key_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 128);
    g_fdp->ConsumeData((uint8_t*)key, key_len);
    key[key_len] = '\0';

    uint8_t encrypted_key[1024] = {0};
    uint64_t enc_len = 0;
    trustedEncryptKey(__g_harness_eid, &errStatus, err_string, key, encrypted_key, &enc_len);
    if (errStatus != 0 || enc_len == 0) return;

    // Step 2: Decrypt it
    char decrypted[1024] = {0};
    trustedDecryptKey(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len, decrypted);
}

static void harness_dkg_decrypt_path(void) {
    int errStatus = 0;
    char err_string[1024] = {0};

    // Step 1: Generate DKG secret
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    size_t _t = g_fdp->ConsumeIntegralInRange<size_t>(1, 16);
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, _t);
    if (errStatus != 0 || enc_len == 0) return;

    // Step 2: Decrypt it with valid data
    uint8_t decrypted_dkg_secret[3072] = {0};
    trustedDecryptDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len, decrypted_dkg_secret);
}

static void harness_dkg_full_workflow(void) {
    int errStatus = 0;
    char err_string[1024] = {0};

    // Step 1: Generate caller ECDSA key (needed for pub_keyB and verification)
    int is_exportable = 1;
    uint8_t caller_encrypted_key[1024] = {0};
    uint64_t caller_enc_len = 0;
    char caller_pub_x[1024] = {0};
    char caller_pub_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            caller_encrypted_key, &caller_enc_len, caller_pub_x, caller_pub_y);
    if (errStatus != 0 || caller_enc_len == 0) return;

    // Build valid 128-char hex pub_keyB from caller's public key
    char pub_keyB[129] = {0};
    int pub_x_len = strlen(caller_pub_x);
    int pub_y_len = strlen(caller_pub_y);
    if (pub_x_len >= 64 && pub_y_len >= 64) {
        memcpy(pub_keyB, caller_pub_x, 64);
        memcpy(pub_keyB + 64, caller_pub_y, 64);
        pub_keyB[128] = '\0';
    } else {
        // Fallback: use fuzz data but ensure hex and length
        g_fdp->ConsumeData((uint8_t*)pub_keyB, 128);
        for (int i = 0; i < 128; i++) {
            pub_keyB[i] = "0123456789abcdef"[pub_keyB[i] % 16];
        }
        pub_keyB[128] = '\0';
    }

    // Step 2: Generate DKG secret
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    uint8_t _t = g_fdp->ConsumeIntegralInRange<uint8_t>(2, 4);
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, _t);
    if (errStatus != 0 || enc_len == 0) return;

    // Step 3: Get public shares
    char public_shares[10000] = {0};
    trustedGetPublicShares(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len, public_shares, _t);

    // Convert decimal public_shares to hex format expected by trustedDkgVerify
    char public_shares_hex[10000] = {0};
    convert_public_shares_dec_to_hex(public_shares, public_shares_hex, sizeof(public_shares_hex));

    // Step 4: Decrypt DKG secret
    uint8_t decrypted_dkg_secret[3072] = {0};
    trustedDecryptDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len, decrypted_dkg_secret);

    // Step 5: Get encrypted secret share with VALID caller pub_keyB
    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = (uint8_t)(_t + 1);
    uint8_t ind = 1;
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, (uint8_t)_t, _n, ind);

    // Step 6: DKG Verify with the SAME encrypted_skey that generated the share
    // CRITICAL: encrypted_skey from GetEncryptedSecretShare must be passed, not caller_encrypted_key
    if (strlen(result_str) >= 128 && dec_len > 0) {
        int result = 0;
        int _ind = g_fdp->ConsumeIntegral<int>();
        trustedDkgVerify(__g_harness_eid, &errStatus, err_string, public_shares_hex, result_str,
                         encrypted_skey, dec_len, (unsigned)_t, _ind, &result);
    }
}

static void harness_bls_create_key_path(void) {
    int errStatus = 0;
    char err_string[1024] = {0};

    // Step 1: Generate caller ECDSA key
    int is_exportable = 1;
    uint8_t caller_encrypted_key[1024] = {0};
    uint64_t caller_enc_len = 0;
    char caller_pub_x[1024] = {0};
    char caller_pub_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            caller_encrypted_key, &caller_enc_len, caller_pub_x, caller_pub_y);
    if (errStatus != 0 || caller_enc_len == 0) return;

    // Build valid 128-char hex pub_keyB
    char pub_keyB[129] = {0};
    if (strlen(caller_pub_x) >= 64 && strlen(caller_pub_y) >= 64) {
        memcpy(pub_keyB, caller_pub_x, 64);
        memcpy(pub_keyB + 64, caller_pub_y, 64);
        pub_keyB[128] = '\0';
    } else {
        g_fdp->ConsumeData((uint8_t*)pub_keyB, 128);
        for (int i = 0; i < 128; i++) {
            pub_keyB[i] = "0123456789abcdef"[pub_keyB[i] % 16];
        }
        pub_keyB[128] = '\0';
    }

    // Step 2: Generate DKG secret
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    uint8_t _t = g_fdp->ConsumeIntegralInRange<uint8_t>(2, 4);
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, _t);
    if (errStatus != 0 || enc_len == 0) return;

    // Step 3: Get encrypted secret share
    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = (uint8_t)(_t + 1);
    uint8_t ind = 1;
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, (uint8_t)_t, _n, ind);

    // Step 4: Create BLS key with valid s_shares
    // CRITICAL: pass caller_encrypted_key (ECDSA key from step 1) as encryptedPrivateKey.
    // trustedCreateBlsKey AES-decrypts this to get skey for session_key_recover.
    if (strlen(result_str) >= 128 && dec_len > 0 && caller_enc_len > 0) {
        uint8_t encr_bls_key[1024] = {0};
        uint64_t enc_bls_key_len = 0;
        trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string, result_str,
                            caller_encrypted_key, caller_enc_len, encr_bls_key, &enc_bls_key_len);
    }
}

static void harness_bls_create_key_v2_path(void) {
    int errStatus = 0;
    char err_string[1024] = {0};

    // Step 1: Generate caller ECDSA key
    int is_exportable = 1;
    uint8_t caller_encrypted_key[1024] = {0};
    uint64_t caller_enc_len = 0;
    char caller_pub_x[1024] = {0};
    char caller_pub_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            caller_encrypted_key, &caller_enc_len, caller_pub_x, caller_pub_y);
    if (errStatus != 0 || caller_enc_len == 0) return;

    // Build valid 128-char hex pub_keyB
    char pub_keyB[129] = {0};
    if (strlen(caller_pub_x) >= 64 && strlen(caller_pub_y) >= 64) {
        memcpy(pub_keyB, caller_pub_x, 64);
        memcpy(pub_keyB + 64, caller_pub_y, 64);
        pub_keyB[128] = '\0';
    } else {
        g_fdp->ConsumeData((uint8_t*)pub_keyB, 128);
        for (int i = 0; i < 128; i++) {
            pub_keyB[i] = "0123456789abcdef"[pub_keyB[i] % 16];
        }
        pub_keyB[128] = '\0';
    }

    // Step 2: Generate DKG secret
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    uint8_t _t = g_fdp->ConsumeIntegralInRange<uint8_t>(2, 4);
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, _t);
    if (errStatus != 0 || enc_len == 0) return;

    // Step 3: Get encrypted secret share V2
    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = (uint8_t)(_t + 1);
    uint8_t ind = 1;
    trustedGetEncryptedSecretShareV2(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                     encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, (uint8_t)_t, _n, ind);

    // Step 4: Create BLS key V2 with valid s_shares
    // CRITICAL: pass caller_encrypted_key (ECDSA key from step 1) as encryptedPrivateKey.
    if (strlen(result_str) >= 128 && dec_len > 0 && caller_enc_len > 0) {
        uint8_t encr_bls_key[1024] = {0};
        uint64_t enc_bls_key_len = 0;
        trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string, result_str,
                              caller_encrypted_key, caller_enc_len, encr_bls_key, &enc_bls_key_len);
    }
}

static void harness_dkg_verify_v2_path(void) {
    int errStatus = 0;
    char err_string[1024] = {0};

    // Step 1: Generate caller ECDSA key
    int is_exportable = 1;
    uint8_t caller_encrypted_key[1024] = {0};
    uint64_t caller_enc_len = 0;
    char caller_pub_x[1024] = {0};
    char caller_pub_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            caller_encrypted_key, &caller_enc_len, caller_pub_x, caller_pub_y);
    if (errStatus != 0 || caller_enc_len == 0) return;

    // Build valid 128-char hex pub_keyB
    char pub_keyB[129] = {0};
    if (strlen(caller_pub_x) >= 64 && strlen(caller_pub_y) >= 64) {
        memcpy(pub_keyB, caller_pub_x, 64);
        memcpy(pub_keyB + 64, caller_pub_y, 64);
        pub_keyB[128] = '\0';
    } else {
        g_fdp->ConsumeData((uint8_t*)pub_keyB, 128);
        for (int i = 0; i < 128; i++) {
            pub_keyB[i] = "0123456789abcdef"[pub_keyB[i] % 16];
        }
        pub_keyB[128] = '\0';
    }

    // Step 2: Generate DKG secret
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    uint8_t _t = g_fdp->ConsumeIntegralInRange<uint8_t>(2, 4);
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, _t);
    if (errStatus != 0 || enc_len == 0) return;

    // Step 3: Get public shares
    char public_shares[10000] = {0};
    trustedGetPublicShares(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len, public_shares, _t);

    // Convert decimal public_shares to hex format expected by trustedDkgVerifyV2
    char public_shares_hex[10000] = {0};
    convert_public_shares_dec_to_hex(public_shares, public_shares_hex, sizeof(public_shares_hex));

    // Step 4: Get encrypted secret share V2
    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = (uint8_t)(_t + 1);
    uint8_t ind = 1;
    trustedGetEncryptedSecretShareV2(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                     encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, (uint8_t)_t, _n, ind);

    // Step 5: DKG Verify V2 with valid data
    // CRITICAL: pass encrypted_skey (from GetEncryptedSecretShareV2) as the private key.
    if (strlen(result_str) >= 128 && dec_len > 0) {
        int result = 0;
        int _ind = g_fdp->ConsumeIntegral<int>();
        trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string, public_shares_hex, result_str,
                           encrypted_skey, dec_len, (unsigned)_t, _ind, &result);
    }
}

// DISABLED: triggers CALL_ONCE abort in simulation mode\n// static void harness_setsek_success_path(void) {
//     int errStatus = 0;
//     char err_string[1024] = {0};
// 
//     // Step 1: Set SEK with the globally-generated valid encrypted SEK
//     trustedSetSEK(__g_harness_eid, &errStatus, err_string, g_encrypted_SEK);
// 
//     // Step 2: Set SEK backup with hex
//     if (strlen(g_hex_SEK) > 0) {
//         uint8_t out_encrypted_SEK[1024] = {0};
//         uint64_t out_enc_len = 0;
//         trustedSetSEKBackup(__g_harness_eid, &errStatus, err_string, out_encrypted_SEK, &out_enc_len, g_hex_SEK);
//     }
// }

static void harness_bls_full_lifecycle(void) {
    // Deep BLS workflow: Generate → GetPubKey → Sign → DecryptShare
    int errStatus = 0;
    char err_string[1024] = {0};

    // Step 1: Generate valid BLS key
    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) return;

    // Step 2: Get BLS pub key
    char bls_pub_key[320] = {0};
    trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string, encryptedKey, encLen, bls_pub_key);

    // Step 3: Sign with fuzzed hash
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

    // Step 4: Get decryption share with fuzzed public_decryption_value
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

static void harness_minimal_bls_create_v2(void) {
    // Minimal chain: DKG secret -> encrypted share V2 -> create BLS key V2
    int errStatus = 0;
    char err_string[1024] = {0};

    char pub_keyB[129] = "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc";

    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    uint8_t _t = g_fdp->ConsumeIntegralInRange<uint8_t>(2, 4);
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, _t);
    if (errStatus != 0 || enc_len == 0) return;

    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = (uint8_t)(_t + 1);
    uint8_t ind = 1;
    trustedGetEncryptedSecretShareV2(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                     encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, (uint8_t)_t, _n, ind);

    if (strlen(result_str) >= 128 && dec_len > 0) {
        // Generate a valid ECDSA key to use as encryptedPrivateKey for CreateBlsKeyV2
        int errStatus2 = 0;
        char err_string2[1024] = {0};
        int is_exportable = 0;
        uint8_t encrypted_ecdsa_key[1024] = {0};
        uint64_t ecdsa_enc_len = 0;
        char pub_x[1024] = {0};
        char pub_y[1024] = {0};
        trustedGenerateEcdsaKey(__g_harness_eid, &errStatus2, err_string2, &is_exportable,
                                encrypted_ecdsa_key, &ecdsa_enc_len, pub_x, pub_y);
        if (errStatus2 == 0 && ecdsa_enc_len > 0) {
            uint8_t encr_bls_key[1024] = {0};
            uint64_t enc_bls_key_len = 0;
            trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string, result_str,
                                  encrypted_ecdsa_key, ecdsa_enc_len, encr_bls_key, &enc_bls_key_len);
        }
    }
}

static void harness_minimal_dkg_verify_v2(void) {
    // Minimal chain: DKG secret -> public shares -> GetEncryptedSecretShareV2 -> DkgVerifyV2
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

    // Convert decimal public_shares to hex format expected by trustedDkgVerifyV2
    char public_shares_hex[10000] = {0};
    convert_public_shares_dec_to_hex(public_shares, public_shares_hex, sizeof(public_shares_hex));

    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = (uint8_t)(_t + 1);
    uint8_t ind = 1;
    trustedGetEncryptedSecretShareV2(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                     encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, (uint8_t)_t, _n, ind);

    if (strlen(result_str) >= 128 && dec_len > 0) {
        int result = 0;
        int _ind = g_fdp->ConsumeIntegral<int>();
        trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string, public_shares_hex, result_str,
                           encrypted_skey, dec_len, (unsigned)_t, _ind, &result);
    }
}

static void harness_decrypt_nonexportable_ecdsa(void) {
    // Pass an encrypted ECDSA key (NON_EXPORTABLE) to trustedDecryptKey
    // to trigger the exportable != EXPORTABLE branch
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

    char key[1024] = {0};
    trustedDecryptKey(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len, key);
}

static void harness_decrypt_nonexportable_bls(void) {
    // Pass an encrypted BLS key (NON_EXPORTABLE) to trustedDecryptKey
    // to trigger the exportable != EXPORTABLE branch
    int errStatus = 0;
    char err_string[1024] = {0};

    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) return;

    char key[1024] = {0};
    trustedDecryptKey(__g_harness_eid, &errStatus, err_string, encryptedKey, encLen, key);
}


// Minimal focused harnesses that consume little fuzz data and maximize success rate

static void harness_minimal_dkg_share(void) {
    // Minimal DKG: generate secret + get encrypted share with fixed valid pub_keyB
    int errStatus = 0;
    char err_string[1024] = {0};

    // Fixed valid 128-char hex pub_keyB (a valid secp256k1 point is not required for gen_session_key,
    // but it must be 128 hex chars for length check)
    char pub_keyB[129] = "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc";

    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    uint8_t _t = g_fdp->ConsumeIntegralInRange<uint8_t>(2, 4);
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, _t);
    if (errStatus != 0 || enc_len == 0) return;

    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = (uint8_t)(_t + 1);
    uint8_t ind = 1;
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, (uint8_t)_t, _n, ind);
}

static void harness_minimal_dkg_share_v2(void) {
    // V2 variant with hash_key + xor_encrypt_v2 path
    int errStatus = 0;
    char err_string[1024] = {0};

    char pub_keyB[129] = "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc";

    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    uint8_t _t = g_fdp->ConsumeIntegralInRange<uint8_t>(2, 4);
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, _t);
    if (errStatus != 0 || enc_len == 0) return;

    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = (uint8_t)(_t + 1);
    uint8_t ind = 1;
    trustedGetEncryptedSecretShareV2(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                     encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, (uint8_t)_t, _n, ind);
}

static void harness_minimal_bls_create(void) {
    // Minimal chain: DKG secret -> encrypted share -> create BLS key
    // CRITICAL: must pass encrypted_skey (the key generated by GetEncryptedSecretShare)
    // to CreateBlsKey, NOT a newly generated dummy key.
    int errStatus = 0;
    char err_string[1024] = {0};

    char pub_keyB[129] = "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc";

    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    uint8_t _t = g_fdp->ConsumeIntegralInRange<uint8_t>(2, 4);
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, _t);
    if (errStatus != 0 || enc_len == 0) return;

    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = (uint8_t)(_t + 1);
    uint8_t ind = 1;
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, (uint8_t)_t, _n, ind);

    if (strlen(result_str) >= 128 && dec_len > 0) {
        // Generate a valid ECDSA key to use as encryptedPrivateKey for CreateBlsKey
        int errStatus2 = 0;
        char err_string2[1024] = {0};
        int is_exportable = 0;
        uint8_t encrypted_ecdsa_key[1024] = {0};
        uint64_t ecdsa_enc_len = 0;
        char pub_x[1024] = {0};
        char pub_y[1024] = {0};
        trustedGenerateEcdsaKey(__g_harness_eid, &errStatus2, err_string2, &is_exportable,
                                encrypted_ecdsa_key, &ecdsa_enc_len, pub_x, pub_y);
        if (errStatus2 == 0 && ecdsa_enc_len > 0) {
            uint8_t encr_bls_key[1024] = {0};
            uint64_t enc_bls_key_len = 0;
            trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string, result_str,
                                encrypted_ecdsa_key, ecdsa_enc_len, encr_bls_key, &enc_bls_key_len);
        }
    }
}

static void harness_minimal_dkg_verify(void) {
    // Minimal chain: DKG secret -> public shares -> verify
    // CRITICAL: must pass encrypted_skey (from GetEncryptedSecretShare) to DkgVerify,
    // NOT caller_encrypted_key. DkgVerify needs the key that generated the share.
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

    // Convert decimal public_shares to hex format expected by trustedDkgVerify
    char public_shares_hex[10000] = {0};
    convert_public_shares_dec_to_hex(public_shares, public_shares_hex, sizeof(public_shares_hex));

    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = (uint8_t)(_t + 1);
    uint8_t ind = 1;
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, (uint8_t)_t, _n, ind);

    if (strlen(result_str) >= 128 && dec_len > 0) {
        int result = 0;
        int _ind = g_fdp->ConsumeIntegral<int>();
        trustedDkgVerify(__g_harness_eid, &errStatus, err_string, public_shares_hex, result_str,
                         encrypted_skey, dec_len, (unsigned)_t, _ind, &result);
    }
}


static void harness_dkg_invalid_pubkey(void) {
    // Call trustedGetEncryptedSecretShare with a malformed pub_keyB
    // to trigger is_hex() check failure in the enclave
    int errStatus = 0;
    char err_string[1024] = {0};

    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    uint8_t _t = g_fdp->ConsumeIntegralInRange<uint8_t>(2, 4);
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, _t);
    if (errStatus != 0 || enc_len == 0) return;

    char pub_keyB[129] = {0};
    g_fdp->ConsumeData((uint8_t*)pub_keyB, 128);
    pub_keyB[128] = '\0';
    // Ensure it's NOT valid hex by injecting non-hex chars
    for (int i = 0; i < 10; i++) {
        int pos = g_fdp->ConsumeIntegralInRange<int>(0, 127);
        char c = pub_keyB[pos];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            // Already non-hex, keep it
        } else {
            pub_keyB[pos] = 'g' + (c % 10);
        }
    }

    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = (uint8_t)(_t + 1);
    uint8_t ind = 1;
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, (uint8_t)_t, _n, ind);
}

// ============================================================================
// DEEP PATH HARNESSSES - Guaranteed valid inputs to reach internal code
// These bypass fuzz data for validation-critical inputs to maximize coverage
// ============================================================================

static void harness_deep_bls_sign(void) {
    // Generate BLS key, then sign with VALID digit-only hashes
    // Goal: Reach deep enclave_sign code, not just validation failures
    int errStatus = 0;
    char err_string[1024] = {0};

    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) return;

    // Use fixed valid decimal strings for hashX/hashY (guaranteed to pass isAllDigits)
    // These are valid 77-digit numbers that won't overflow bigint<4>
    char hashX[80] = "12345678901234567890123456789012345678901234567890123456789012345678901234567";
    char hashY[80] = "98765432109876543210987654321098765432109876543210987654321098765432109876543";

    char signature[1024] = {0};
    trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string, encryptedKey, encLen,
                          hashX, hashY, signature);
}

static void harness_deep_create_bls_key(void) {
    // Full valid chain: ECDSA key -> DKG secret -> encrypted share -> CreateBlsKey
    // trustedCreateBlsKey needs a valid encrypted ECDSA private key (not a DKG share)
    int errStatus = 0;
    char err_string[1024] = {0};

    // Step 1: Generate valid ECDSA key (needed as encryptedPrivateKey for CreateBlsKey)
    int is_exportable = 0;
    uint8_t encrypted_ecdsa_key[1024] = {0};
    uint64_t ecdsa_enc_len = 0;
    char pub_x[1024] = {0};
    char pub_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            encrypted_ecdsa_key, &ecdsa_enc_len, pub_x, pub_y);
    if (errStatus != 0 || ecdsa_enc_len == 0) return;

    // Fixed valid 128-char hex pub_keyB
    char pub_keyB[129] = "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc";

    // Step 2: Generate DKG secret
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, 3);
    if (errStatus != 0 || enc_len == 0) return;

    // Step 3: Get encrypted secret share
    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = 4;
    uint8_t ind = 1;
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, 3, _n, ind);

    // Step 4: Create BLS key with valid ECDSA key and DKG shares
    if (strlen(result_str) >= 128) {
        uint8_t encr_bls_key[1024] = {0};
        uint64_t enc_bls_key_len = 0;
        trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string, result_str,
                            encrypted_ecdsa_key, ecdsa_enc_len, encr_bls_key, &enc_bls_key_len);
    }
}

static void harness_deep_create_bls_key_v2(void) {
    // V2 variant: ECDSA key -> DKG secret -> GetEncryptedSecretShareV2 -> CreateBlsKeyV2
    // trustedCreateBlsKeyV2 also needs a valid encrypted ECDSA private key
    int errStatus = 0;
    char err_string[1024] = {0};

    // Step 1: Generate valid ECDSA key
    int is_exportable = 0;
    uint8_t encrypted_ecdsa_key[1024] = {0};
    uint64_t ecdsa_enc_len = 0;
    char pub_x[1024] = {0};
    char pub_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            encrypted_ecdsa_key, &ecdsa_enc_len, pub_x, pub_y);
    if (errStatus != 0 || ecdsa_enc_len == 0) return;

    char pub_keyB[129] = "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc";

    // Step 2: Generate DKG secret
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, 3);
    if (errStatus != 0 || enc_len == 0) return;

    // Step 3: Get encrypted secret share V2
    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = 4;
    uint8_t ind = 1;
    trustedGetEncryptedSecretShareV2(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                     encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, 3, _n, ind);

    // Step 4: Create BLS key V2 with valid ECDSA key and DKG shares
    if (strlen(result_str) >= 128) {
        uint8_t encr_bls_key[1024] = {0};
        uint64_t enc_bls_key_len = 0;
        trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string, result_str,
                              encrypted_ecdsa_key, ecdsa_enc_len, encr_bls_key, &enc_bls_key_len);
    }
}

static void harness_deep_decrypt_key(void) {
    // Generate EXPORTABLE key, encrypt it, then decrypt
    // This exercises the full encrypt/decrypt roundtrip with valid data
    int errStatus = 0;
    char err_string[1024] = {0};

    // Encrypt a test key
    char key[32] = "testkey123";
    uint8_t encrypted_key[1024] = {0};
    uint64_t enc_len = 0;
    trustedEncryptKey(__g_harness_eid, &errStatus, err_string, key, encrypted_key, &enc_len);
    if (errStatus != 0 || enc_len == 0) return;

    // Decrypt it back
    char decrypted[1024] = {0};
    trustedDecryptKey(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len, decrypted);
}

static void harness_deep_decrypt_dkg(void) {
    // Generate DKG secret with valid parameters, then decrypt it
    int errStatus = 0;
    char err_string[1024] = {0};

    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    // Use fixed reasonable _t value
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, 3);
    if (errStatus != 0 || enc_len == 0) return;

    // Decrypt with valid encrypted data
    uint8_t decrypted_dkg_secret[3072] = {0};
    trustedDecryptDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len, decrypted_dkg_secret);
}

// DISABLED: triggers CALL_ONCE abort in simulation mode\n// static void harness_minimal_setsek(void) {
//     // Minimal SetSEK using the globally-generated valid SEK
//     // Consumes ZERO fuzz bytes - ensures SetSEK gets exercised frequently
//     int errStatus = 0;
//     char err_string[1024] = {0};
//     // Use the global SEK that was generated in customized_harness()
//     if (g_enc_len_sek > 0) {
//         trustedSetSEK(__g_harness_eid, &errStatus, err_string, g_encrypted_SEK);
//     }
// }

// DISABLED: triggers CALL_ONCE abort in simulation mode\n// static void harness_minimal_setsek_backup(void) {
//     // Minimal SetSEKBackup using the globally-generated valid hex SEK
//     // Consumes ZERO fuzz bytes
//     int errStatus = 0;
//     char err_string[1024] = {0};
//     uint8_t out_encrypted_SEK[1024] = {0};
//     uint64_t out_enc_len = 0;
//     if (strlen(g_hex_SEK) > 0) {
//         trustedSetSEKBackup(__g_harness_eid, &errStatus, err_string,
//                             out_encrypted_SEK, &out_enc_len, g_hex_SEK);
//     }
// }

static void harness_bls_decrypt_with_valid_g2(void) {
    // Use a valid G2 point (from calc_secret_shareG2) as public_decryption_value
    // to reach the multiplication branch in getDecryptionShare
    int errStatus = 0;
    char errString[1024] = {0};

    // Step 1: Generate BLS key
    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, errString, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) return;

    // Step 2: Generate DKG secret and get valid G2 point
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t dkg_enc_len = 0;
    uint8_t _t = g_fdp->ConsumeIntegralInRange<uint8_t>(2, 4);
    trustedGenDkgSecret(__g_harness_eid, &errStatus, errString, encrypted_dkg_secret, &dkg_enc_len, _t);
    if (errStatus != 0 || dkg_enc_len == 0) return;

    char pub_keyB[129] = "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc";
    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = (uint8_t)(_t + 1);
    uint8_t ind = 1;
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, errString, encrypted_dkg_secret, dkg_enc_len,
                                   encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, (uint8_t)_t, _n, ind);

    // Step 3: Call GetDecryptionShare with the valid G2 point
    if (strlen(s_shareG2) > 0) {
        char decrption_share[320] = {0};
        trustedGetDecryptionShare(__g_harness_eid, &errStatus, errString, encryptedKey,
                                  s_shareG2, encLen, decrption_share);
    }
}

static void harness_bls_create_multi_share(void) {
    // Generate multiple DKG shares, duplicate them, and pass to CreateBlsKey
    // to exercise the loop in trustedCreateBlsKey
    int errStatus = 0;
    char err_string[1024] = {0};
    char pub_keyB[129] = "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc";

    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    uint8_t _t = g_fdp->ConsumeIntegralInRange<uint8_t>(2, 4);
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, _t);
    if (errStatus != 0 || enc_len == 0) return;

    char all_shares[4096] = {0};
    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;

    // Generate one share
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = (uint8_t)(_t + 1);
    uint8_t ind = 1;
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, (uint8_t)_t, _n, ind);

    if (strlen(result_str) >= 128 && dec_len > 0) {
        // Generate a valid ECDSA key to use as encryptedPrivateKey for CreateBlsKey
        int errStatus2 = 0;
        char err_string2[1024] = {0};
        int is_exportable = 0;
        uint8_t encrypted_ecdsa_key[1024] = {0};
        uint64_t ecdsa_enc_len = 0;
        char pub_x[1024] = {0};
        char pub_y[1024] = {0};
        trustedGenerateEcdsaKey(__g_harness_eid, &errStatus2, err_string2, &is_exportable,
                                encrypted_ecdsa_key, &ecdsa_enc_len, pub_x, pub_y);
        if (errStatus2 != 0 || ecdsa_enc_len == 0) return;

        // Duplicate the same share 2-4 times to exercise the loop
        int copies = g_fdp->ConsumeIntegralInRange<int>(2, 4);
        for (int c = 0; c < copies && strlen(all_shares) + 192 < sizeof(all_shares); c++) {
            strncat(all_shares, result_str, 192);
        }

        uint8_t encr_bls_key[1024] = {0};
        uint64_t enc_bls_key_len = 0;
        trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string, all_shares,
                            encrypted_ecdsa_key, ecdsa_enc_len, encr_bls_key, &enc_bls_key_len);
    }
}

static void harness_bls_short_hash_sign(void) {
    // BLS sign with very short hashes (1-5 digits) to hit edge cases in libff
    int errStatus = 0;
    char err_string[1024] = {0};

    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) return;

    // Try multiple short hash lengths
    char hashX[8] = "1";
    char hashY[8] = "2";
    char signature[1024] = {0};
    trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string, encryptedKey, encLen,
                          hashX, hashY, signature);

    char hashX2[8] = "12345";
    char hashY2[8] = "67890";
    trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string, encryptedKey, encLen,
                          hashX2, hashY2, signature);
}

static void harness_ecdsa_base_variations(void) {
    // ECDSA sign with different base values (2, 10, 16) to exercise mpz_set_str paths
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

    char hash_bin[65] = "1010101010101010101010101010101010101010101010101010101010101010";
    char sig_r[1024] = {0};
    char sig_s[1024] = {0};
    uint8_t sig_v = 0;
    trustedEcdsaSign(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len,
                     hash_bin, sig_r, sig_s, &sig_v, 2);

    char hash_dec[65] = "1234567890123456789012345678901234567890123456789012345678901234";
    trustedEcdsaSign(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len,
                     hash_dec, sig_r, sig_s, &sig_v, 10);

    char hash_hex[65] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    trustedEcdsaSign(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len,
                     hash_hex, sig_r, sig_s, &sig_v, 16);
}

static void harness_ecdsa_sign_burst(void) {
    // Burst harness: sign 1000 times in one iteration to trigger sigCounter % 1000 == 0
    // guard in trustedEcdsaSign, which calls signature_verify. The static counter
    // resets each enclave creation, so this can only be triggered by multiple
    // consecutive signs within a single harness invocation.
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

static void harness_multi_index_dkg_create_bls(void) {
    // Generate DKG secret, get shares for TWO different indices with same pub_keyB,
    // concatenate, and create BLS key. Exercises CreateBlsKey loop with different data.
    int errStatus = 0;
    char err_string[1024] = {0};

    // Generate ECDSA key for encryptedPrivateKey
    int is_exportable = 0;
    uint8_t encrypted_ecdsa_key[1024] = {0};
    uint64_t ecdsa_enc_len = 0;
    char pub_x[1024] = {0};
    char pub_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            encrypted_ecdsa_key, &ecdsa_enc_len, pub_x, pub_y);
    if (errStatus != 0 || ecdsa_enc_len == 0) return;

    // Build pub_keyB from the ECDSA public key
    char pub_keyB[129] = {0};
    if (strlen(pub_x) >= 64 && strlen(pub_y) >= 64) {
        memcpy(pub_keyB, pub_x, 64);
        memcpy(pub_keyB + 64, pub_y, 64);
        pub_keyB[128] = '\0';
    } else {
        memcpy(pub_keyB, "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc", 128);
        pub_keyB[128] = '\0';
    }

    // Generate DKG secret with fixed _t=3
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, 3);
    if (errStatus != 0 || enc_len == 0) return;

    // Get share for ind=1
    uint8_t encrypted_skey1[1024] = {0};
    uint64_t dec_len1 = 0;
    char result_str1[193] = {0};
    char s_shareG2_1[320] = {0};
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey1, &dec_len1, result_str1, s_shareG2_1, pub_keyB, 3, 4, 1);
    if (strlen(result_str1) < 128 || dec_len1 == 0) return;

    // Get share for ind=2 with SAME pub_keyB
    uint8_t encrypted_skey2[1024] = {0};
    uint64_t dec_len2 = 0;
    char result_str2[193] = {0};
    char s_shareG2_2[320] = {0};
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey2, &dec_len2, result_str2, s_shareG2_2, pub_keyB, 3, 4, 2);

    // Concatenate both shares
    char all_shares[385] = {0};
    strncat(all_shares, result_str1, 192);
    if (strlen(result_str2) >= 128) {
        strncat(all_shares, result_str2, 192);
    }

    // Create BLS key with multiple distinct shares
    uint8_t encr_bls_key[1024] = {0};
    uint64_t enc_bls_key_len = 0;
    trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string, all_shares,
                        encrypted_ecdsa_key, ecdsa_enc_len, encr_bls_key, &enc_bls_key_len);
}

static void harness_multi_index_dkg_create_bls_v2(void) {
    // V2 variant: same multi-index approach for CreateBlsKeyV2
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

    char pub_keyB[129] = {0};
    if (strlen(pub_x) >= 64 && strlen(pub_y) >= 64) {
        memcpy(pub_keyB, pub_x, 64);
        memcpy(pub_keyB + 64, pub_y, 64);
        pub_keyB[128] = '\0';
    } else {
        memcpy(pub_keyB, "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc", 128);
        pub_keyB[128] = '\0';
    }

    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, 3);
    if (errStatus != 0 || enc_len == 0) return;

    uint8_t encrypted_skey1[1024] = {0};
    uint64_t dec_len1 = 0;
    char result_str1[193] = {0};
    char s_shareG2_1[320] = {0};
    trustedGetEncryptedSecretShareV2(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                     encrypted_skey1, &dec_len1, result_str1, s_shareG2_1, pub_keyB, 3, 4, 1);
    if (strlen(result_str1) < 128 || dec_len1 == 0) return;

    uint8_t encrypted_skey2[1024] = {0};
    uint64_t dec_len2 = 0;
    char result_str2[193] = {0};
    char s_shareG2_2[320] = {0};
    trustedGetEncryptedSecretShareV2(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                     encrypted_skey2, &dec_len2, result_str2, s_shareG2_2, pub_keyB, 3, 4, 2);

    char all_shares[385] = {0};
    strncat(all_shares, result_str1, 192);
    if (strlen(result_str2) >= 128) {
        strncat(all_shares, result_str2, 192);
    }

    uint8_t encr_bls_key[1024] = {0};
    uint64_t enc_bls_key_len = 0;
    trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string, all_shares,
                          encrypted_ecdsa_key, ecdsa_enc_len, encr_bls_key, &enc_bls_key_len);
}

static void harness_dkg_t_one_boundary(void) {
    // DKG with _t=1 (degree-0 polynomial, special case)
    int errStatus = 0;
    char err_string[1024] = {0};

    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, 1);
    if (errStatus != 0 || enc_len == 0) return;

    char pub_keyB[129] = "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc";

    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, 1, 2, 1);

    char public_shares[10000] = {0};
    trustedGetPublicShares(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len, public_shares, 1);

    if (strlen(result_str) >= 128 && dec_len > 0) {
        int result = 0;
        trustedDkgVerify(__g_harness_eid, &errStatus, err_string, public_shares, result_str,
                         encrypted_skey, dec_len, 1, 1, &result);
    }
}

static void harness_multi_index_3_dkg_create_bls(void) {
    // Generate DKG secret, get shares for THREE different indices with same pub_keyB,
    // concatenate, and create BLS key. Exercises CreateBlsKey loop with 3 iterations.
    int errStatus = 0;
    char err_string[1024] = {0};

    // Generate ECDSA key for encryptedPrivateKey
    int is_exportable = 0;
    uint8_t encrypted_ecdsa_key[1024] = {0};
    uint64_t ecdsa_enc_len = 0;
    char pub_x[1024] = {0};
    char pub_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            encrypted_ecdsa_key, &ecdsa_enc_len, pub_x, pub_y);
    if (errStatus != 0 || ecdsa_enc_len == 0) return;

    // Build pub_keyB from the ECDSA public key
    char pub_keyB[129] = {0};
    if (strlen(pub_x) >= 64 && strlen(pub_y) >= 64) {
        memcpy(pub_keyB, pub_x, 64);
        memcpy(pub_keyB + 64, pub_y, 64);
        pub_keyB[128] = '\0';
    } else {
        memcpy(pub_keyB, "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc", 128);
        pub_keyB[128] = '\0';
    }

    // Generate DKG secret with fixed _t=3
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, 3);
    if (errStatus != 0 || enc_len == 0) return;

    // Get share for ind=1
    uint8_t encrypted_skey1[1024] = {0};
    uint64_t dec_len1 = 0;
    char result_str1[193] = {0};
    char s_shareG2_1[320] = {0};
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey1, &dec_len1, result_str1, s_shareG2_1, pub_keyB, 3, 4, 1);
    if (strlen(result_str1) < 128 || dec_len1 == 0) return;

    // Get share for ind=2 with SAME pub_keyB
    uint8_t encrypted_skey2[1024] = {0};
    uint64_t dec_len2 = 0;
    char result_str2[193] = {0};
    char s_shareG2_2[320] = {0};
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey2, &dec_len2, result_str2, s_shareG2_2, pub_keyB, 3, 4, 2);

    // Get share for ind=3 with SAME pub_keyB
    uint8_t encrypted_skey3[1024] = {0};
    uint64_t dec_len3 = 0;
    char result_str3[193] = {0};
    char s_shareG2_3[320] = {0};
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey3, &dec_len3, result_str3, s_shareG2_3, pub_keyB, 3, 4, 3);

    // Concatenate all three shares
    char all_shares[577] = {0};
    strncat(all_shares, result_str1, 192);
    if (strlen(result_str2) >= 128) {
        strncat(all_shares, result_str2, 192);
    }
    if (strlen(result_str3) >= 128) {
        strncat(all_shares, result_str3, 192);
    }

    // Create BLS key with three distinct shares
    uint8_t encr_bls_key[1024] = {0};
    uint64_t enc_bls_key_len = 0;
    trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string, all_shares,
                        encrypted_ecdsa_key, ecdsa_enc_len, encr_bls_key, &enc_bls_key_len);
}

static void harness_multi_index_3_dkg_create_bls_v2(void) {
    // V2 variant: same 3-share approach for CreateBlsKeyV2
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

    char pub_keyB[129] = {0};
    if (strlen(pub_x) >= 64 && strlen(pub_y) >= 64) {
        memcpy(pub_keyB, pub_x, 64);
        memcpy(pub_keyB + 64, pub_y, 64);
        pub_keyB[128] = '\0';
    } else {
        memcpy(pub_keyB, "abcdef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc", 128);
        pub_keyB[128] = '\0';
    }

    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, 3);
    if (errStatus != 0 || enc_len == 0) return;

    uint8_t encrypted_skey1[1024] = {0};
    uint64_t dec_len1 = 0;
    char result_str1[193] = {0};
    char s_shareG2_1[320] = {0};
    trustedGetEncryptedSecretShareV2(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                     encrypted_skey1, &dec_len1, result_str1, s_shareG2_1, pub_keyB, 3, 4, 1);
    if (strlen(result_str1) < 128 || dec_len1 == 0) return;

    uint8_t encrypted_skey2[1024] = {0};
    uint64_t dec_len2 = 0;
    char result_str2[193] = {0};
    char s_shareG2_2[320] = {0};
    trustedGetEncryptedSecretShareV2(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                     encrypted_skey2, &dec_len2, result_str2, s_shareG2_2, pub_keyB, 3, 4, 2);

    uint8_t encrypted_skey3[1024] = {0};
    uint64_t dec_len3 = 0;
    char result_str3[193] = {0};
    char s_shareG2_3[320] = {0};
    trustedGetEncryptedSecretShareV2(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                     encrypted_skey3, &dec_len3, result_str3, s_shareG2_3, pub_keyB, 3, 4, 3);

    char all_shares[577] = {0};
    strncat(all_shares, result_str1, 192);
    if (strlen(result_str2) >= 128) {
        strncat(all_shares, result_str2, 192);
    }
    if (strlen(result_str3) >= 128) {
        strncat(all_shares, result_str3, 192);
    }

    uint8_t encr_bls_key[1024] = {0};
    uint64_t enc_bls_key_len = 0;
    trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string, all_shares,
                          encrypted_ecdsa_key, ecdsa_enc_len, encr_bls_key, &enc_bls_key_len);
}

HARNESS_REGISTER(harness_minimal_dkg_share, 70)
HARNESS_REGISTER(harness_minimal_dkg_share_v2, 70)
HARNESS_REGISTER(harness_minimal_bls_create, 70)
HARNESS_REGISTER(harness_minimal_dkg_verify, 75)
HARNESS_REGISTER(harness_minimal_bls_create_v2, 70)
HARNESS_REGISTER(harness_minimal_dkg_verify_v2, 75)
// HARNESS_REGISTER(harness_minimal_setsek, 75)  // DISABLED: CALL_ONCE abort
// HARNESS_REGISTER(harness_minimal_setsek_backup, 70)  // DISABLED: CALL_ONCE abort
HARNESS_REGISTER(harness_bls_decrypt_with_valid_g2, 60)
HARNESS_REGISTER(harness_bls_create_multi_share, 60)
HARNESS_REGISTER(harness_decrypt_nonexportable_ecdsa, 65)
HARNESS_REGISTER(harness_decrypt_nonexportable_bls, 65)
HARNESS_REGISTER(harness_encrypt_roundtrip, 65)
// HARNESS_REGISTER(harness_setsek_success_path, 55)  // DISABLED: CALL_ONCE abort
HARNESS_REGISTER(harness_ecdsa_success_path, 55)
HARNESS_REGISTER(harness_bls_success_path, 55)
HARNESS_REGISTER(harness_dkg_decrypt_path, 40)
HARNESS_REGISTER(harness_dkg_full_workflow, 60)
HARNESS_REGISTER(harness_bls_create_key_path, 40)
HARNESS_REGISTER(harness_bls_create_key_v2_path, 40)
HARNESS_REGISTER(harness_dkg_verify_v2_path, 55)
HARNESS_REGISTER(harness_bls_full_lifecycle, 55)
HARNESS_REGISTER(harness_dkg_invalid_pubkey, 50)

// Deep path harnesses: fully valid inputs to penetrate internal validation
HARNESS_REGISTER(harness_deep_bls_sign, 80)
HARNESS_REGISTER(harness_deep_create_bls_key, 80)
HARNESS_REGISTER(harness_deep_create_bls_key_v2, 80)
HARNESS_REGISTER(harness_deep_decrypt_key, 70)
HARNESS_REGISTER(harness_deep_decrypt_dkg, 70)
HARNESS_REGISTER(harness_ecdsa_sign_burst, 40)

// New harnesses for this cycle
HARNESS_REGISTER(harness_bls_short_hash_sign, 60)
HARNESS_REGISTER(harness_ecdsa_base_variations, 55)
// DISABLED: redundant with harness_deep_create_bls_key and harness_bls_create_multi_share
// These exercise the same CreateBlsKey loop with more iterations but do not add new edges.
// HARNESS_REGISTER(harness_multi_index_dkg_create_bls, 65)
// HARNESS_REGISTER(harness_multi_index_dkg_create_bls_v2, 65)
HARNESS_REGISTER(harness_dkg_t_one_boundary, 50)

// DISABLED: 3-share variants redundant with deep_create + multi_share harnesses
// HARNESS_REGISTER(harness_multi_index_3_dkg_create_bls, 65)
// HARNESS_REGISTER(harness_multi_index_3_dkg_create_bls_v2, 65)
