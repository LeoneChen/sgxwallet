#pragma once

static void harness_createbls_v2_2shares(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Step 1: Generate DKG poly with t=1
  uint8_t *enc_poly = (uint8_t *)calloc(3050, 1);
  uint64_t poly_len = 0;
  if (!enc_poly) return;
  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, enc_poly, &poly_len, 1);
  if (errStatus != 0 || poly_len == 0) return;

  // Step 2: Generate ECDSA key as verifier (pub_keyB for GetEncryptedSecretShareV2)
  int is_exportable = 1;
  uint8_t *verifier_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t verifier_enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  char *pub_y = (char *)calloc(1024, sizeof(char));
  if (!verifier_key || !pub_x || !pub_y) return;
  errStatus = 0;
  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, verifier_key, &verifier_enc_len, pub_x, pub_y);
  if (errStatus != 0 || verifier_enc_len == 0) return;

  // pub_keyB = zero-padded pub_x (64 chars) + zero-padded pub_y (64 chars) = 128 chars
  char *pub_keyB = (char *)calloc(129, sizeof(char));
  if (!pub_keyB) return;
  strncpy(pub_keyB, pub_x, 64);
  strncpy(pub_keyB + 64, pub_y, 64);
  pub_keyB[128] = '\0';

  // Step 3: GetEncryptedSecretShareV2 with verifier pub as pub_keyB (t=n=ind=1)
  // result_str = cipher[0..63] + ephemeral_pubX[64..127] + ephemeral_pubY[128..191]
  uint8_t *enc_skey = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t skey_enc_len = 0;
  char *result_str = (char *)calloc(193, sizeof(char));
  char *s_shareG2 = (char *)calloc(320, sizeof(char));
  if (!enc_skey || !result_str || !s_shareG2) return;
  errStatus = 0;
  trustedGetEncryptedSecretShareV2(
      __g_harness_eid, &errStatus, err_string,
      enc_poly, poly_len, enc_skey, &skey_enc_len,
      result_str, s_shareG2, pub_keyB, 1, 1, 1);
  if (errStatus != 0 || skey_enc_len == 0) return;

  // Step 4: Build s_shares = result_str + result_str (384 chars → numShares=2)
  // Both blocks use the same cipher + ephemeral pub coords → session_key_recover succeeds twice.
  char *s_shares = (char *)calloc(6145, sizeof(char));
  if (!s_shares) return;
  strncpy(s_shares, result_str, 192);
  strncpy(s_shares + 192, result_str, 192);
  // s_shares[384] = '\0' from calloc → strlen=384, numShares=2

  // Step 5: CreateBlsKeyV2 → loop runs 2 iterations → back-edge at line 1276 covered.
  uint8_t *encr_bls_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_bls_key_len = 0;
  if (!encr_bls_key) return;
  errStatus = 0;
  trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string,
                        s_shares, verifier_key, verifier_enc_len,
                        encr_bls_key, &enc_bls_key_len);
}

// trustedGetEncryptedSecretShareV2 line 970: calc_secret_share failure (poly.size() != _t).
// harness_calc_secret_share_t_mismatch does this for V1 only; this harness covers the V2 path.
// Strategy: gen poly with t=1 → pass _t=3 to GetEncryptedSecretShareV2 (mismatch: poly has
// 1 coefficient but _t=3) → inside enclave: calc_secret_share(poly, s_share, 3, ...) returns -1
// because SplitStringToFr gives poly.size()=1 ≠ _t=3 → CHECK_STATUS fires → line 970 covered.
// Requires valid pub_keyB (128 chars) so gen_session_key succeeds (line 965 not triggered).

HARNESS_REGISTER(harness_createbls_v2_2shares, 120)
