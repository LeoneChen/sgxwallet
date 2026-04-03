#pragma once

static void harness_createbls_v2_ecdsa_key(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  int is_exportable = 1;
  uint8_t *ecdsa_key = (uint8_t *)calloc(1024, 1);
  uint64_t ecdsa_enc_len = 0;
  char *pub_x = (char *)calloc(1024, 1);
  char *pub_y = (char *)calloc(1024, 1);
  if (!ecdsa_key || !pub_x || !pub_y) return;
  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, ecdsa_key, &ecdsa_enc_len, pub_x, pub_y);
  if (errStatus != 0 || ecdsa_enc_len == 0) return;

  // 384-char hex string → numShares = strlen/192 = 2 → loop runs 2 iterations.
  // For each block: session_key_recover(skey_hex, block_192_'a', commonKey):
  //   strnlen("aaa...192", 193) = 192 ≥ 192 → passes line 123 check ✓
  //   point_set_hex("aaa...64", "aaa...64") → sets non-curve mpz point (no crash in mpz)
  //   point_multiplication → runs EC scalar mult, returns arbitrary result ✓
  //   common_key set → hash_key → xor_decrypt_v2 → carray2Hex → mpz_set_str ✓
  // Both iterations complete → loop back-edge at line 1276 covered.
  char *secret_shares = (char *)calloc(385, 1);
  if (!secret_shares) return;
  memset(secret_shares, 'a', 384);
  secret_shares[384] = '\0';

  uint8_t *encr_bls_key = (uint8_t *)calloc(1024, 1);
  uint64_t enc_bls_key_len = 0;
  if (!encr_bls_key) return;

  errStatus = 0;
  trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string,
                        secret_shares, ecdsa_key, ecdsa_enc_len,
                        encr_bls_key, &enc_bls_key_len);
}

// trustedDkgVerifyV2 deep paths — hits:2, edges:2/10, lines 1086-1101+ uncovered.
// Root cause: harness_v2_full_roundtrip depends on trustedGetEncryptedSecretShareV2 which
// always fails, so DkgVerifyV2 is only called by the auto-gen _harness with garbage data.
// Bypass: use a valid AES-encrypted ECDSA key as encryptedPrivateKey so AES_decrypt at
// line 1098 succeeds → session_key_recover called with synthetic secretShare.
// session_key_recover fails (synthetic 192-char share, not a real ECDH output) → covers
// CHECK_STATUS at line 1111. publicShares = G2_GEN_HEX for deep Verification() if recovered.

HARNESS_REGISTER(harness_createbls_v2_ecdsa_key, 80)
