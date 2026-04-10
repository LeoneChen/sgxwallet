#pragma once

static void harness_calc_secret_share_t_mismatch(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Step 1: Generate DKG poly with t=1 (single coefficient)
  uint8_t *enc_poly = (uint8_t *)calloc(3072, sizeof(uint8_t));
  uint64_t poly_len = 0;
  if (!enc_poly) return;
  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      enc_poly, &poly_len, 1);
  if (errStatus != 0 || poly_len == 0) return;

  // Step 2: Generate ECDSA key to get a valid secp256k1 pubKeyB (128 hex chars)
  int is_exportable = 1;
  uint8_t *ecdsa_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t ecdsa_enc_len = 0;
  char *pub_x = (char *)calloc(65, sizeof(char));
  char *pub_y = (char *)calloc(65, sizeof(char));
  if (!ecdsa_key || !pub_x || !pub_y) return;
  errStatus = 0;
  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, ecdsa_key, &ecdsa_enc_len,
                          pub_x, pub_y);
  if (errStatus != 0 || ecdsa_enc_len == 0) return;

  // Build pubKeyB = pad pub_x to 64 chars + pad pub_y to 64 chars
  char *pub_keyB = (char *)calloc(129, sizeof(char));
  if (!pub_keyB) return;
  int xlen = (int)strnlen(pub_x, 65);
  int ylen = (int)strnlen(pub_y, 65);
  memset(pub_keyB, '0', 128);
  if (xlen <= 64) memcpy(pub_keyB + (64 - xlen), pub_x, xlen);
  if (ylen <= 64) memcpy(pub_keyB + 64 + (64 - ylen), pub_y, ylen);
  pub_keyB[128] = '\0';

  // Step 3: Call GetEncryptedSecretShare with _t=3 but poly has only 1 coeff
  // → inside enclave: calc_secret_share: SplitStringToFr returns 1 element
  //   poly.size()=1 != _t=3 → line 346 covered ✓
  uint8_t *enc_skey = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t dec_len = 0;
  char *result_str = (char *)calloc(193, sizeof(char));
  char *s_shareG2 = (char *)calloc(320, sizeof(char));
  if (!enc_skey || !result_str || !s_shareG2) return;
  errStatus = 0;
  trustedGetEncryptedSecretShare(
      __g_harness_eid, &errStatus, err_string,
      enc_poly, poly_len, enc_skey, &dec_len,
      result_str, s_shareG2, pub_keyB,
      3 /*_t mismatch: poly has 1 coeff*/, 3 /*_n*/, 1 /*ind*/);
}

// Combined pipeline: GenerateEcdsaKey → GetPublicEcdsaKey → EcdsaSign → EncryptKey → DecryptKey
// Targets 4 low-hit ECalls per iteration:
//   trustedGetPublicEcdsaKey (2 hits, 24/70 edges)
//   trustedEcdsaSign         (5 hits, 31/93 edges)
//   trustedEncryptKey        (4 hits, 24/70 edges)
//   trustedDecryptKey        (5 hits, 20/58 edges)

HARNESS_REGISTER(harness_calc_secret_share_t_mismatch, 40)
