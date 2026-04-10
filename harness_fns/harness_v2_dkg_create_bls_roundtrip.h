#pragma once

static void harness_v2_dkg_create_bls_roundtrip(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Step 1: Generate DKG polynomial (t=n=ind=1 for minimal computation)
  uint8_t *encrypted_poly = (uint8_t *)calloc(3072, sizeof(uint8_t));
  uint64_t poly_enc_len = 0;
  if (!encrypted_poly) return;
  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_poly, &poly_enc_len, 1);
  if (errStatus != 0 || poly_enc_len == 0) return;

  // Step 2: Generate verifier ECDSA key → pub_x, pub_y (padded to 64 hex chars)
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

  // Build pub_keyB = pub_x[0:64] + pub_y[0:64] = 128 hex chars
  char *pub_keyB = (char *)calloc(129, sizeof(char));
  if (!pub_keyB) return;
  strncpy(pub_keyB, pub_x, 64);
  strncpy(pub_keyB + 64, pub_y, 64);
  pub_keyB[128] = '\0';

  // Step 3: GetEncryptedSecretShareV2 with verifier pub as pub_keyB (t=n=ind=1)
  // Inside enclave: gen_session_key(ephemeral_skey, verifier_pub) = commonKey
  //   hash_key(commonKey, derivedKey) → V2-specific key derivation
  //   xor_encrypt_v2(derivedKey, s_share, cypher)
  // result_str = cypher[0..63] + ephemeral_pub_x[64..127] + ephemeral_pub_y[128..191]
  uint8_t *encrypted_skey = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t skey_enc_len = 0;
  char *result_str = (char *)calloc(193, sizeof(char));
  char *s_shareG2 = (char *)calloc(320, sizeof(char));
  if (!encrypted_skey || !result_str || !s_shareG2) return;
  errStatus = 0;
  trustedGetEncryptedSecretShareV2(
      __g_harness_eid, &errStatus, err_string,
      encrypted_poly, poly_enc_len, encrypted_skey, &skey_enc_len,
      result_str, s_shareG2, pub_keyB, 1, 1, 1);
  if (errStatus != 0 || skey_enc_len == 0) return;

  // Step 4: DkgVerifyV2 with verifier_key + result_str
  // session_key_recover(verifier_skey, result_str) = commonKey (ECDH inverse)
  // hash_key(commonKey, derivedKey) = same derivedKey as in step 3
  // xor_decrypt_v2(derivedKey, encr_sshare) = actual secret share hex
  // mpz_set_str succeeds → Verification() called
  // Use G2 generator as public_shares so ConvertHexToDec+isG2 passes → deep Verification coverage
  static const char G2_GEN_HEX[257] =
      "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"  // X.c0
      "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"  // X.c1
      "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"  // Y.c0
      "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"; // Y.c1
  char *public_shares = (char *)calloc(10000, sizeof(char));
  int *verify_result = (int *)calloc(1, sizeof(int));
  if (!public_shares || !verify_result) return;
  strncpy(public_shares, G2_GEN_HEX, 256);

  errStatus = 0;
  trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string,
                     public_shares, result_str, verifier_key, verifier_enc_len,
                     1, 1, verify_result);

  // Step 5: CreateBlsKeyV2 with verifier_key and result_str as s_shares (192-char entry)
  // Same ECDH: session_key_recover → hash_key → xor_decrypt_v2 = valid share hex
  // mpz_set_str succeeds → loop body at line 1276 covered → mpz_addmul_ui → AES_encrypt BLS key
  char *s_shares = (char *)calloc(6145, sizeof(char));
  if (!s_shares) return;
  strncpy(s_shares, result_str, 192);
  // s_shares[192] = '\0' from calloc → numShares = 1

  uint8_t *encr_bls_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_bls_key_len = 0;
  if (!encr_bls_key) return;

  errStatus = 0;
  trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string,
                        s_shares, verifier_key, verifier_enc_len,
                        encr_bls_key, &enc_bls_key_len);
}

// Verification() multi-t coverage: exercise loop body for i=1 (t=2) and i=2 (t=3).
// Root cause of UNCOVERED_PC at DKGUtils.cpp:503 (loop body i>0):
//   harness_verification_deep uses hardcoded t=1 → loop runs once (i=0 only)
//   harness_complete_dkg_roundtrip uses t=1..3 but public_shares from GetPublicShares
//     are in DECIMAL format; Verification() calls ConvertHexToDec on them → invalid
//     hex input → ConvertHexToDec returns "" → Verification returns early at ret=2
// Fix: use t=2..3 with 2 or 3 copies of G2_GEN_HEX as public_shares (hex format) +
//   ECDH-valid s_share from GetEncryptedSecretShare(t=2..3), so:
//   - session_key_recover succeeds → xor_decrypt recovers valid share
//   - mpz_set_str succeeds → Verification called with _t=2 or _t=3
//   - Loop runs 2 or 3 times, covering the loop body for i>0

HARNESS_REGISTER(harness_v2_dkg_create_bls_roundtrip, 100)
