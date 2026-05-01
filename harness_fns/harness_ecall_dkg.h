#pragma once

static void harness_trustedGenDkgSecret(void) {
    pre_harness_init(); // ensure enclave is initialized (curve, SEK)
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_dkg_secret[3072] = {0};
    uint64_t enc_len = 0;
    size_t _t = g_fdp->ConsumeIntegralInRange<size_t>(1, 16);
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, &enc_len, _t);
}

static void harness_trustedDecryptDkgSecret(void) {
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_dkg_secret[3050] = {0};
    g_fdp->ConsumeData(encrypted_dkg_secret, 3050);
    uint64_t enc_len = g_fdp->ConsumeIntegral<uint64_t>();
    uint8_t decrypted_dkg_secret[3072] = {0};
    trustedDecryptDkgSecret(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len, decrypted_dkg_secret);
}

static void harness_trustedGetEncryptedSecretShare(void) {
    pre_harness_init(); // ensure enclave is initialized (curve, SEK)
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_poly[3050] = {0};
    g_fdp->ConsumeData(encrypted_poly, 3050);
    uint64_t enc_len = g_fdp->ConsumeIntegral<uint64_t>();
    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    char pub_keyB[512] = {0};
    g_fdp->ConsumeData((uint8_t*)pub_keyB, 511);
    pub_keyB[511] = '\0';
    uint8_t _t = g_fdp->ConsumeIntegral<uint8_t>();
    uint8_t _n = g_fdp->ConsumeIntegral<uint8_t>();
    uint8_t ind = g_fdp->ConsumeIntegral<uint8_t>();
    trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string, encrypted_poly, enc_len,
                                   encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, _t, _n, ind);
}

static void harness_trustedGetEncryptedSecretShareV2(void) {
    pre_harness_init(); // ensure enclave is initialized (curve, SEK)
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_poly[3050] = {0};
    g_fdp->ConsumeData(encrypted_poly, 3050);
    uint64_t enc_len = g_fdp->ConsumeIntegral<uint64_t>();
    uint8_t encrypted_skey[1024] = {0};
    uint64_t dec_len = 0;
    char result_str[193] = {0};
    char s_shareG2[320] = {0};
    char pub_keyB[512] = {0};
    g_fdp->ConsumeData((uint8_t*)pub_keyB, 511);
    pub_keyB[511] = '\0';
    uint8_t _t = g_fdp->ConsumeIntegral<uint8_t>();
    uint8_t _n = g_fdp->ConsumeIntegral<uint8_t>();
    uint8_t ind = g_fdp->ConsumeIntegral<uint8_t>();
    trustedGetEncryptedSecretShareV2(__g_harness_eid, &errStatus, err_string, encrypted_poly, enc_len,
                                     encrypted_skey, &dec_len, result_str, s_shareG2, pub_keyB, _t, _n, ind);
}

static void harness_trustedGetPublicShares(void) {
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_dkg_secret[3050] = {0};
    g_fdp->ConsumeData(encrypted_dkg_secret, 3050);
    uint64_t enc_len = g_fdp->ConsumeIntegral<uint64_t>();
    char public_shares[10000] = {0};
    unsigned int _t = g_fdp->ConsumeIntegralInRange<unsigned int>(1, 16);
    trustedGetPublicShares(__g_harness_eid, &errStatus, err_string, encrypted_dkg_secret, enc_len, public_shares, _t);
}

static void harness_trustedDkgVerify(void) {
    int errStatus = 0;
    char err_string[1024] = {0};
    char public_shares[10000] = {0};
    g_fdp->ConsumeData((uint8_t*)public_shares, 9999);
    public_shares[9999] = '\0';
    char s_share[512] = {0};
    g_fdp->ConsumeData((uint8_t*)s_share, 511);
    s_share[511] = '\0';
    uint8_t encrypted_key[1024] = {0};
    g_fdp->ConsumeData(encrypted_key, 1024);
    uint64_t key_len = g_fdp->ConsumeIntegral<uint64_t>();
    unsigned int _t = g_fdp->ConsumeIntegralInRange<unsigned int>(1, 16);
    int _ind = g_fdp->ConsumeIntegral<int>();
    int result = 0;
    trustedDkgVerify(__g_harness_eid, &errStatus, err_string, public_shares, s_share,
                     encrypted_key, key_len, _t, _ind, &result);
}

static void harness_trustedDkgVerifyV2(void) {
    pre_harness_init(); // ensure enclave is initialized (curve, SEK)
    int errStatus = 0;
    char err_string[1024] = {0};
    char public_shares[10000] = {0};
    g_fdp->ConsumeData((uint8_t*)public_shares, 9999);
    public_shares[9999] = '\0';
    char s_share[512] = {0};
    g_fdp->ConsumeData((uint8_t*)s_share, 511);
    s_share[511] = '\0';
    uint8_t encrypted_key[1024] = {0};
    g_fdp->ConsumeData(encrypted_key, 1024);
    uint64_t key_len = g_fdp->ConsumeIntegral<uint64_t>();
    unsigned int _t = g_fdp->ConsumeIntegralInRange<unsigned int>(1, 16);
    int _ind = g_fdp->ConsumeIntegral<int>();
    int result = 0;
    trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string, public_shares, s_share,
                       encrypted_key, key_len, _t, _ind, &result);
}

// DISABLED: redundant with minimal/success-path harnesses (cum_before > 3000, wastes selection probability)
// HARNESS_REGISTER(harness_trustedGenDkgSecret, 30)
// DISABLED: high byte consumption (3050-11550 bytes), redundant with minimal/deep harnesses
// HARNESS_REGISTER(harness_trustedDecryptDkgSecret, 25)
// HARNESS_REGISTER(harness_trustedGetEncryptedSecretShare, 30)
// HARNESS_REGISTER(harness_trustedGetEncryptedSecretShareV2, 50)
// HARNESS_REGISTER(harness_trustedGetPublicShares, 25)
// HARNESS_REGISTER(harness_trustedDkgVerify, 65)
// HARNESS_REGISTER(harness_trustedDkgVerifyV2, 75)
