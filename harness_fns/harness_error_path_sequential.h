#pragma once

static void harness_error_path_sequential(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, 1);
  if (!err_string) return;

  // Case 0: trustedGetPublicShares: NULL encrypted_dkg_secret → CHECK_STATE line 1004
  {
    char *ps = (char *)calloc(10000, 1);
    if (ps)
      trustedGetPublicShares(__g_harness_eid, &errStatus, err_string,
                             NULL, 0, ps, 1);
  }
  errStatus = 0;
  // Case 1: trustedGetPublicShares: _t=0 → CHECK_STATE(_t > 0) line 1006
  {
    uint8_t *enc = (uint8_t *)calloc(3072, 1);
    char *ps = (char *)calloc(10000, 1);
    if (enc && ps)
      trustedGetPublicShares(__g_harness_eid, &errStatus, err_string,
                             enc, 100, ps, 0);
  }
  errStatus = 0;
  // Case 2: trustedDecryptKey: zero ciphertext → AES_decrypt fail
  {
    uint8_t *enc = (uint8_t *)calloc(1024, 1);
    char *out = (char *)calloc(1024, 1);
    if (enc && out)
      trustedDecryptKey(__g_harness_eid, &errStatus, err_string, enc, 28, out);
  }
  errStatus = 0;
  // Case 3: trustedDecryptDkgSecret: zero bytes → AES_decrypt fail
  {
    uint8_t *enc = (uint8_t *)calloc(3072, 1);
    uint8_t *dec = (uint8_t *)calloc(3072, 1);
    if (enc && dec)
      trustedDecryptDkgSecret(__g_harness_eid, &errStatus, err_string,
                              enc, 28, dec);
  }
  errStatus = 0;
  // Case 4: trustedGenDkgSecret: _t=0 → gen_dkg_poly error path
  {
    uint8_t *enc = (uint8_t *)calloc(3072, 1);
    uint64_t enc_len = 0;
    if (enc)
      trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                          enc, &enc_len, 0);
  }
  errStatus = 0;
  // Case 5: trustedGetPublicShares: valid enc but halved enc_len → AES_decrypt fail
  {
    uint8_t *enc = (uint8_t *)calloc(3072, 1);
    uint64_t enc_len = 0;
    if (enc) {
      trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                          enc, &enc_len, 1);
      if (errStatus == 0 && enc_len > 0) {
        char *ps = (char *)calloc(10000, 1);
        if (ps) {
          errStatus = 0;
          trustedGetPublicShares(__g_harness_eid, &errStatus, err_string,
                                 enc, enc_len / 2, ps, 1);
        }
      }
    }
  }
  errStatus = 0;
  // Case 6: trustedGenDkgSecret: NULL encrypted_dkg_secret → CHECK_STATE line 752
  {
    uint64_t enc_len = 0;
    trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                        NULL, &enc_len, 1);
  }
  errStatus = 0;
  // Case 7: trustedGenerateEcdsaKey: NULL encrypted_key ([out] param; unreachable)
  {
    char *x = (char *)calloc(1024, 1);
    char *y = (char *)calloc(1024, 1);
    int is_exp = 0;
    uint64_t enc_len2 = 0;
    if (x && y)
      trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                              &is_exp, NULL, &enc_len2, x, y);
  }
  errStatus = 0;
  // Case 8: trustedGetPublicEcdsaKey: zero encrypted key → AES_decrypt fail
  {
    uint8_t *enc = (uint8_t *)calloc(1024, 1);
    char *x = (char *)calloc(1024, 1);
    char *y = (char *)calloc(1024, 1);
    if (enc && x && y)
      trustedGetPublicEcdsaKey(__g_harness_eid, &errStatus, err_string,
                               enc, 28, x, y);
  }
  errStatus = 0;
  // Case 9: trustedBlsSignMessage: NULL encrypted key → CHECK_STATE line 708
  {
    char *sig = (char *)calloc(1024, 1);
    if (sig)
      trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                            NULL, 0,
                            "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
                            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                            sig);
  }
  errStatus = 0;
  // Case 10: trustedEcdsaSign: zero encrypted key → AES_decrypt fail
  {
    uint8_t *enc = (uint8_t *)calloc(1024, 1);
    char *sig_r = (char *)calloc(1024, 1);
    char *sig_s = (char *)calloc(1024, 1);
    uint8_t sig_v = 0;
    if (enc && sig_r && sig_s)
      trustedEcdsaSign(__g_harness_eid, &errStatus, err_string,
                       enc, 28,
                       "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
                       sig_r, sig_s, &sig_v, 16);
  }
  errStatus = 0;
  // Case 11: trustedEcdsaSign: NULL encryptedPrivateKey → CHECK_STATE line 519
  {
    char sig_r[1024] = {0};
    char sig_s[1024] = {0};
    uint8_t sig_v = 0;
    trustedEcdsaSign(__g_harness_eid, &errStatus, err_string,
                     NULL, 0,
                     "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
                     sig_r, sig_s, &sig_v, 16);
  }
  errStatus = 0;
  // Case 12: trustedDecryptKey: NULL encryptedPrivateKey → CHECK_STATE
  {
    char out[1024] = {0};
    trustedDecryptKey(__g_harness_eid, &errStatus, err_string, NULL, 0, out);
  }
  errStatus = 0;
  // Case 13: trustedEncryptKey: NULL key_hex → CHECK_STATE line 656
  {
    uint8_t enc[1024] = {0};
    uint64_t enc_len = 0;
    trustedEncryptKey(__g_harness_eid, &errStatus, err_string, NULL, enc, &enc_len);
  }
  errStatus = 0;
  // Case 14: trustedGetPublicEcdsaKey: NULL pub_key_x ([out] param; unreachable)
  {
    uint8_t *enc = (uint8_t *)calloc(1024, 1);
    char *pub_y = (char *)calloc(1024, 1);
    if (enc && pub_y)
      trustedGetPublicEcdsaKey(__g_harness_eid, &errStatus, err_string,
                               enc, 28, NULL, pub_y);
  }
  errStatus = 0;
  // Case 15: trustedGetBlsPubKey: NULL bls_pub_key → NULL output param branch
  {
    uint8_t *enc = (uint8_t *)calloc(1024, 1);
    if (enc)
      trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string, enc, 28, NULL);
  }
  errStatus = 0;
  // Case 16: trustedGetBlsPubKey: zero encrypted_key → AES_decrypt fail
  {
    uint8_t *enc = (uint8_t *)calloc(1024, 1);
    char *bls_pub_key = (char *)calloc(320, 1);
    if (enc && bls_pub_key)
      trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string,
                          enc, 28, bls_pub_key);
  }
  errStatus = 0;
  // Case 17: trustedBlsSignMessage: zero encrypted_key → AES_decrypt fail
  {
    uint8_t *enc = (uint8_t *)calloc(256, 1);
    char *sig = (char *)calloc(1024, 1);
    if (enc && sig)
      trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                            enc, 28,
                            "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
                            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                            sig);
  }
  errStatus = 0;
  // Case 18: trustedGetDecryptionShare: NULL decryption_share → NULL output branch
  {
    uint8_t *enc = (uint8_t *)calloc(1024, 1);
    char *pub_decr = (char *)calloc(320, 1);
    if (enc && pub_decr) {
      memset(pub_decr, 'f', 319);
      trustedGetDecryptionShare(__g_harness_eid, &errStatus, err_string,
                                enc, pub_decr, 28, NULL);
    }
  }
  errStatus = 0;
  // Case 19: trustedGenerateBLSKey: NULL encryptedKey → NULL output param branch
  {
    int isExportable = 0;
    trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string,
                          &isExportable, NULL, NULL);
  }
}

// harness_secretshare_null_paths converted to sequential: all 10 null cases per
// invocation. Previously FDP-switched: expected per-case hits = 120/3357*90/10 < 0.33.
// Sequential: each call covers all 10 cases — lines 853-856/928-931/862/937 always hit.

HARNESS_REGISTER(harness_error_path_sequential, 200)
