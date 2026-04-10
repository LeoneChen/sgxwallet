#pragma once

static void harness_getss_v2_mismatched_t(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Gen DKG poly with t=1 (one coefficient)
  uint8_t *enc_poly = (uint8_t *)calloc(3072, 1);  // EDL: [out, count=3072]
  uint64_t poly_len = 0;
  if (!enc_poly) return;
  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, enc_poly, &poly_len, 1);
  if (errStatus != 0 || poly_len == 0) return;

  // Gen ECDSA key → zero-padded pub_x + pub_y = valid 128-char pub_keyB
  int is_exportable = 1;
  uint8_t *ecdsa_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t ecdsa_enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  char *pub_y = (char *)calloc(1024, sizeof(char));
  if (!ecdsa_key || !pub_x || !pub_y) return;
  errStatus = 0;
  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, ecdsa_key, &ecdsa_enc_len, pub_x, pub_y);
  if (errStatus != 0 || ecdsa_enc_len == 0) return;

  char *pub_keyB = (char *)calloc(129, sizeof(char));
  if (!pub_keyB) return;
  strncpy(pub_keyB, pub_x, 64);
  strncpy(pub_keyB + 64, pub_y, 64);
  pub_keyB[128] = '\0';

  // Call V2 with _t=3 but poly has 1 coeff → calc_secret_share fails → line 970 covered.
  uint8_t *enc_skey = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t skey_enc_len = 0;
  char *result_str = (char *)calloc(193, sizeof(char));
  char *s_shareG2 = (char *)calloc(320, sizeof(char));
  if (!enc_skey || !result_str || !s_shareG2) return;
  errStatus = 0;
  trustedGetEncryptedSecretShareV2(
      __g_harness_eid, &errStatus, err_string,
      enc_poly, poly_len, enc_skey, &skey_enc_len,
      result_str, s_shareG2, pub_keyB,
      3 /*_t mismatch*/, 3 /*_n*/, 1 /*ind*/);
}

// trustedGetEncryptedSecretShareV2 line 937: SetEncryptedDkgPoly failure (garbage poly).
// harness_getss_error_paths op=0 covers V1 (line 862); V2 path (line 937) has no equivalent.
// Strategy: pass garbage encrypted_poly → AES_decrypt fails inside SetEncryptedDkgPoly
// → CHECK_STATUS2 at line 937 fires → error branch covered.
// Uses a valid 128-char pub_keyB so gen_session_key won't fire first (line 965).

HARNESS_REGISTER(harness_getss_v2_mismatched_t, 80)
