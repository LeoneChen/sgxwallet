#pragma once

// Extreme input harnesses to test boundary conditions and error handling paths

static void harness_edge_empty_strings(void) {
    int errStatus = 0;
    char err_string[1024] = {0};

    // Test ECDSA sign with empty hash
    uint8_t encrypted_key[1024] = {0};
    g_fdp->ConsumeData(encrypted_key, 1024);
    uint64_t enc_len = g_fdp->ConsumeIntegral<uint64_t>();
    char sig_r[1024] = {0};
    char sig_s[1024] = {0};
    uint8_t sig_v = 0;
    trustedEcdsaSign(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len,
                     "", sig_r, sig_s, &sig_v, 16);

    // Test BLS sign with empty hashes
    char sig[1024] = {0};
    trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len,
                          "", "", sig);

    // Test DKG verify with empty strings
    int result = 0;
    uint8_t key[1024] = {0};
    g_fdp->ConsumeData(key, 1024);
    uint64_t key_len = g_fdp->ConsumeIntegral<uint64_t>();
    trustedDkgVerify(__g_harness_eid, &errStatus, err_string, "", "",
                     key, key_len, 1, 0, &result);
}

static void harness_edge_zero_lengths(void) {
    int errStatus = 0;
    char err_string[1024] = {0};

    // Decrypt key with enc_len = 0
    uint8_t encrypted_key[1024] = {0};
    char key[1024] = {0};
    trustedDecryptKey(__g_harness_eid, &errStatus, err_string, encrypted_key, 0, key);

    // Get public ECDSA key with dec_len = 0
    char pub_x[1024] = {0};
    char pub_y[1024] = {0};
    trustedGetPublicEcdsaKey(__g_harness_eid, &errStatus, err_string, encrypted_key, 0, pub_x, pub_y);

    // Get BLS pub key with key_len = 0
    char bls_pub[320] = {0};
    trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string, encrypted_key, 0, bls_pub);

    // Decrypt DKG secret with enc_len = 0
    uint8_t decrypted[3072] = {0};
    trustedDecryptDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_key, 0, decrypted);
}

static void harness_edge_max_values(void) {
    pre_harness_init(); // ensure enclave is initialized (curve, SEK)
    int errStatus = 0;
    char err_string[1024] = {0};

    // DKG with _t = 0 and _t = 16 (boundary values)
    uint8_t encrypted_dkg[3072] = {0};
    uint64_t enc_len = 0;
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg, &enc_len, 0);
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg, &enc_len, 16);

    // Get public shares with _t = 0 and _t = 16
    char public_shares[10000] = {0};
    trustedGetPublicShares(__g_harness_eid, &errStatus, err_string, encrypted_dkg, 0, public_shares, 0);
    trustedGetPublicShares(__g_harness_eid, &errStatus, err_string, encrypted_dkg, 0, public_shares, 16);

    // DKG verify with extreme _ind values
    int result = 0;
    uint8_t key[1024] = {0};
    g_fdp->ConsumeData(key, 1024);
    uint64_t key_len = g_fdp->ConsumeIntegral<uint64_t>();
    char shares[10000] = {0};
    g_fdp->ConsumeData((uint8_t*)shares, 9999);
    shares[9999] = '\0';
    char s_share[512] = {0};
    g_fdp->ConsumeData((uint8_t*)s_share, 511);
    s_share[511] = '\0';
    trustedDkgVerify(__g_harness_eid, &errStatus, err_string, shares, s_share,
                     key, key_len, 1, INT_MIN, &result);
    trustedDkgVerify(__g_harness_eid, &errStatus, err_string, shares, s_share,
                     key, key_len, 1, INT_MAX, &result);
}

// DISABLED: late registry position (cum_before > 2990) makes these invisible to 1-byte seeds
// and rarely selected. Edge/empty/boundary paths already covered by earlier error-path harnesses.
// HARNESS_REGISTER(harness_edge_empty_strings, 15)
// HARNESS_REGISTER(harness_edge_zero_lengths, 15)
// HARNESS_REGISTER(harness_edge_max_values, 15)
