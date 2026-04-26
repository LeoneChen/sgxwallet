#pragma once

static void harness_workflow_ecdsa_lifecycle(void) {
    // Step 1: Init
    trustedEnclaveInit(__g_harness_eid, 2);

    // Step 2: Generate SEK
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_SEK[1024] = {0};
    uint64_t enc_len_sek = 0;
    char hex_SEK[65] = {0};
    trustedGenerateSEK(__g_harness_eid, &errStatus, err_string, encrypted_SEK, &enc_len_sek, hex_SEK);

    // Step 3: Generate ECDSA Key
    int is_exportable = 0;
    uint8_t encrypted_key[1024] = {0};
    uint64_t enc_len_key = 0;
    char pub_key_x[1024] = {0};
    char pub_key_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            encrypted_key, &enc_len_key, pub_key_x, pub_key_y);

    // Step 4: Sign (only if we have remaining fuzz data)
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
        trustedEcdsaSign(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len_key,
                         hash, sig_r, sig_s, &sig_v, 16);
    }
}

static void harness_workflow_bls_lifecycle(void) {
    // Step 1: Init
    trustedEnclaveInit(__g_harness_eid, 2);

    // Step 2: Generate BLS Key
    int errStatus = 0;
    char err_string[1024] = {0};
    int isExportable = 0;
    uint8_t encryptedKey[1024] = {0};
    uint64_t encLen = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string, &isExportable, encryptedKey, &encLen);
    if (errStatus != 0 || encLen == 0) return;

    // Step 3: Get BLS pub key
    char bls_pub_key[320] = {0};
    trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string, encryptedKey, encLen, bls_pub_key);

    // Step 4: Sign (if data remains)
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

    // Step 5: Get decryption share (if data remains)
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

static void harness_workflow_dkg_lifecycle(void) {
    // Step 1: Init
    trustedEnclaveInit(__g_harness_eid, 2);

    // Step 2: Generate caller ECDSA key for valid pub_keyB
    int errStatus = 0;
    char err_string[1024] = {0};
    int is_exportable = 1;
    uint8_t caller_encrypted_key[1024] = {0};
    uint64_t caller_enc_len = 0;
    char caller_pub_x[1024] = {0};
    char caller_pub_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            caller_encrypted_key, &caller_enc_len, caller_pub_x, caller_pub_y);
    if (errStatus != 0 || caller_enc_len == 0) return;

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

    // Step 3: Generate DKG Secret
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    size_t _t = g_fdp->ConsumeIntegralInRange<size_t>(2, 4);
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, _t);
    if (errStatus != 0 || enc_len == 0) return;

    // Step 4: Get Public Shares
    char public_shares[10000] = {0};
    trustedGetPublicShares(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len, public_shares, _t);

    // Convert decimal public_shares to hex format expected by trustedDkgVerify
    char public_shares_hex[10000] = {0};
    convert_public_shares_dec_to_hex(public_shares, public_shares_hex, sizeof(public_shares_hex));

    // Step 5: Decrypt DKG Secret
    uint8_t decrypted_dkg_secret[3072] = {0};
    trustedDecryptDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len, decrypted_dkg_secret);

    // Step 6: Get Secret Share with VALID pub_keyB
    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    uint8_t _n = (uint8_t)(_t + 1);
    uint8_t ind = 1;
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len,
                                   encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, (uint8_t)_t, _n, ind);

    // Step 7: DKG Verify with the SAME encrypted_skey that generated the share
    // CRITICAL: encrypted_skey from GetEncryptedSecretShare must be passed, not caller_encrypted_key
    if (strlen(result_str) >= 192 && dec_len > 0) {
        int result = 0;
        int _ind = g_fdp->ConsumeIntegral<int>();
        trustedDkgVerify(__g_harness_eid, &errStatus, err_string, public_shares_hex, result_str,
                         encrypted_skey, dec_len, (unsigned)_t, _ind, &result);
    }
}

// DISABLED: redundant with success_path/deep harnesses, plus wastes bytes on init/SEK already done by customized_harness()
// HARNESS_REGISTER(harness_workflow_ecdsa_lifecycle, 35)
// HARNESS_REGISTER(harness_workflow_bls_lifecycle, 35)
// HARNESS_REGISTER(harness_workflow_dkg_lifecycle, 50)
