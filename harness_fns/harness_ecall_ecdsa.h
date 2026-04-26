#pragma once

static void harness_trustedGenerateEcdsaKey(void) {
    int errStatus = 0;
    char err_string[1024] = {0};
    int is_exportable = g_fdp->ConsumeIntegralInRange<int>(0, 1);
    uint8_t encrypted_key[1024] = {0};
    uint64_t enc_len = 0;
    char pub_key_x[1024] = {0};
    char pub_key_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            encrypted_key, &enc_len, pub_key_x, pub_key_y);
}

static void harness_trustedGetPublicEcdsaKey(void) {
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_key[1024] = {0};
    g_fdp->ConsumeData(encrypted_key, 1024);
    uint64_t dec_len = g_fdp->ConsumeIntegral<uint64_t>();
    char pub_key_x[1024] = {0};
    char pub_key_y[1024] = {0};
    trustedGetPublicEcdsaKey(__g_harness_eid, &errStatus, err_string, encrypted_key,
                             dec_len, pub_key_x, pub_key_y);
}

static void harness_trustedEcdsaSign(void) {
    int errStatus = 0;
    char err_string[1024] = {0};
    uint8_t encrypted_key[1024] = {0};
    g_fdp->ConsumeData(encrypted_key, 1024);
    uint64_t enc_len = g_fdp->ConsumeIntegral<uint64_t>();
    char hash[256] = {0};
    g_fdp->ConsumeData((uint8_t*)hash, 255);
    hash[255] = '\0';
    char sig_r[1024] = {0};
    char sig_s[1024] = {0};
    uint8_t sig_v = 0;
    int base = g_fdp->ConsumeIntegralInRange<int>(0, 16);
    trustedEcdsaSign(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len,
                     hash, sig_r, sig_s, &sig_v, base);
}

static void harness_corrupted_key_ecdsa(void) {
    // Generate valid ECDSA key, then corrupt encrypted bytes before signing
    // to trigger AES decrypt failure or invalid secret key path
    int errStatus = 0;
    char err_string[1024] = {0};
    int is_exportable = 0;
    uint8_t encrypted_key[1024] = {0};
    uint64_t enc_len = 0;
    char pub_x[1024] = {0};
    char pub_y[1024] = {0};
    trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string, &is_exportable,
                            encrypted_key, &enc_len, pub_x, pub_y);
    if (errStatus != 0 || enc_len == 0 || enc_len > 1000) return;

    // Corrupt a few bytes in the middle of the encrypted key
    int num_corruptions = g_fdp->ConsumeIntegralInRange<int>(1, 8);
    for (int i = 0; i < num_corruptions; i++) {
        int pos = g_fdp->ConsumeIntegralInRange<int>(0, (int)enc_len - 1);
        encrypted_key[pos] ^= 0xFF;
    }

    char hash[256] = {0};
    g_fdp->ConsumeData((uint8_t*)hash, 64);
    hash[64] = '\0';
    char sig_r[1024] = {0};
    char sig_s[1024] = {0};
    uint8_t sig_v = 0;
    trustedEcdsaSign(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len,
                     hash, sig_r, sig_s, &sig_v, 16);
}

static void harness_bad_hash_ecdsa(void) {
    // Generate valid ECDSA key, then pass a hash with non-hex characters
    // to trigger mpz_set_str(msgMpz, hash, 16) == -1
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

    char hash[256] = {0};
    g_fdp->ConsumeData((uint8_t*)hash, 64);
    // Inject non-hex characters to guarantee mpz_set_str failure
    for (int i = 0; i < 10; i++) {
        int pos = g_fdp->ConsumeIntegralInRange<int>(0, 63);
        hash[pos] = 'g' + (hash[pos] % 10);
    }
    hash[64] = '\0';

    char sig_r[1024] = {0};
    char sig_s[1024] = {0};
    uint8_t sig_v = 0;
    trustedEcdsaSign(__g_harness_eid, &errStatus, err_string, encrypted_key, enc_len,
                     hash, sig_r, sig_s, &sig_v, 16);
}

// DISABLED: redundant with minimal/success-path harnesses (cum_before > 2900, wastes selection probability)
// HARNESS_REGISTER(harness_trustedGenerateEcdsaKey, 35)
// DISABLED: high byte consumption (1032/1291 bytes), redundant with minimal/deep harnesses
// HARNESS_REGISTER(harness_trustedGetPublicEcdsaKey, 30)
// HARNESS_REGISTER(harness_trustedEcdsaSign, 55)
// DISABLED: redundant with earlier error-path harnesses (harness_ecdsa_sign_invalid_hash at cum 2680,
// harness_ecdsa_sign_invalid_key at cum 2735). These late harnesses waste selection probability
// with minimal unique coverage contribution.
// HARNESS_REGISTER(harness_corrupted_key_ecdsa, 45)
// HARNESS_REGISTER(harness_bad_hash_ecdsa, 45)
