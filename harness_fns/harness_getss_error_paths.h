#pragma once

static void harness_getss_error_paths(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // [out] params - allocate for SDK marshalling
  uint8_t *encrypted_skey = (uint8_t *)calloc(1024, 1);
  uint64_t dec_len = 0;
  char *result_str = (char *)calloc(193, 1);
  char *s_shareG2  = (char *)calloc(320, 1);
  if (!encrypted_skey || !result_str || !s_shareG2) return;

  // Garbage encrypted_poly: fuzzer bytes — will fail AES_decrypt in SetEncryptedDkgPoly
  uint8_t *garbage_poly = (uint8_t *)calloc(3050, 1);
  if (!garbage_poly) return;
  if (g_fdp->remaining_bytes() >= 3050)
    g_fdp->ConsumeData(garbage_poly, 3050);

  int op = g_fdp->ConsumeIntegralInRange<int>(0, 1);
  if (op == 0) {
    // line 862: SetEncryptedDkgPoly fails due to garbage encrypted_poly
    char *pub_keyB = (char *)calloc(193, 1);
    if (!pub_keyB) return;
    memset(pub_keyB, 'a', 128);  // valid-length string, irrelevant (fails before line 887)
    trustedGetEncryptedSecretShare(
        __g_harness_eid, &errStatus, err_string,
        garbage_poly, 3050,
        encrypted_skey, &dec_len, result_str, s_shareG2,
        pub_keyB, 1, 1, 1);
  } else {
    // line 889: valid encrypted_poly but short pub_keyB -> gen_session_key fails
    uint8_t *enc_poly = (uint8_t *)calloc(3050, 1);
    uint64_t poly_len = 0;
    int dkg_err = 0;
    char *dkg_err_str = (char *)calloc(1024, 1);
    if (!enc_poly || !dkg_err_str) return;
    trustedGenDkgSecret(__g_harness_eid, &dkg_err, dkg_err_str, enc_poly, &poly_len, 1);
    if (dkg_err != 0) return;

    // pub_keyB length = 2, far below the required 128 hex chars
    char *short_pub = (char *)calloc(8, 1);
    if (!short_pub) return;
    short_pub[0] = 'a'; short_pub[1] = 'b';
    trustedGetEncryptedSecretShare(
        __g_harness_eid, &errStatus, err_string,
        enc_poly, poly_len,
        encrypted_skey, &dec_len, result_str, s_shareG2,
        short_pub, 1, 1, 1);
  }
}

// Covers Verification() error paths with malformed public_shares:
//   line 515-518: ConvertHexToDec returns empty string (invalid hex chars)
//   line 526-528: isG2 validation fails (invalid G2 point)
// Case 0: public_shares with non-hex characters -> ConvertHexToDec returns ""
// Case 1: public_shares with valid hex but invalid G2 coordinates -> isG2 fails
// Case 2: mismatched _t and public_shares length (fewer shares than expected)

HARNESS_REGISTER(harness_getss_error_paths, 50)
