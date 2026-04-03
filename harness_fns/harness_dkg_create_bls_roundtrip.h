#pragma once

static void harness_dkg_create_bls_roundtrip(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Step 1: Generate DKG polynomial (t=n=1, ind=1 for minimal computation)
  uint8_t *encrypted_poly = (uint8_t *)calloc(3072, sizeof(uint8_t));
  uint64_t poly_enc_len = 0;
  if (!encrypted_poly) return;
  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_poly, &poly_enc_len, 1);
  if (errStatus != 0 || poly_enc_len == 0) return;

  // Step 2: Generate verifier ECDSA key → pub_x, pub_y (both padded to 64 hex chars)
  int is_exportable = 1;
  uint8_t *verifier_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t verifier_enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  char *pub_y = (char *)calloc(1024, sizeof(char));
  if (!verifier_key || !pub_x || !pub_y) return;
  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, verifier_key, &verifier_enc_len, pub_x, pub_y);
  if (errStatus != 0 || verifier_enc_len == 0) return;

  // Build pub_keyB = pub_x(64 chars) + pub_y(64 chars) = 128 chars
  char *pub_keyB = (char *)calloc(129, sizeof(char));
  if (!pub_keyB) return;
  strncpy(pub_keyB, pub_x, 64);
  strncpy(pub_keyB + 64, pub_y, 64);
  pub_keyB[128] = '\0';

  // Step 3: GetEncryptedSecretShare with verifier_pub as pub_keyB (t=n=ind=1)
  // Inside enclave: common_key = ECDH(ephemeral_skey, verifier_pub)
  // result_str = cypher[0..63] + ephemeral_pub_x[64..127] + ephemeral_pub_y[128..191]
  uint8_t *encrypted_skey = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t skey_enc_len = 0;
  char *result_str = (char *)calloc(193, sizeof(char));
  char *s_shareG2 = (char *)calloc(320, sizeof(char));
  if (!encrypted_skey || !result_str || !s_shareG2) return;
  trustedGetEncryptedSecretShare(
      __g_harness_eid, &errStatus, err_string,
      encrypted_poly, poly_enc_len, encrypted_skey, &skey_enc_len,
      result_str, s_shareG2, pub_keyB, 1, 1, 1);
  if (errStatus != 0 || skey_enc_len == 0) return;

  // Step 4: DkgVerify with verifier_key + result_str as s_share
  // session_key_recover: ECDH(verifier_skey, ephemeral_pub) = same common_key
  // xor_decrypt(common_key, result_str[0..63]) = actual secret share hex
  // mpz_set_str succeeds → Verification() called → covers trustedDkgVerify deep paths
  // public_shares = G2 generator in libff coordinate order (X.c0,X.c1,Y.c0,Y.c1 each 64-hex):
  // prev bug: empty public_shares → Verification returned at ret=2 (empty string check)
  int *verify_result = (int *)calloc(1, sizeof(int));
  char *public_shares = (char *)calloc(10000, sizeof(char));
  if (!verify_result || !public_shares) return;
  static const char G2_GEN_HEX_V1[257] =
      "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"  // X.c0
      "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"  // X.c1
      "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"  // Y.c0
      "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"; // Y.c1
  strncpy(public_shares, G2_GEN_HEX_V1, 256);

  errStatus = 0;
  trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                   public_shares, result_str, verifier_key, verifier_enc_len,
                   1, 1, verify_result);

  // Step 5: CreateBlsKey with verifier_key and result_str as s_shares (one 192-char entry)
  // Same ECDH: session_key_recover recovers same common_key → xor_decrypt = valid share hex
  // mpz_set_str succeeds → loop body line 1174 covered!
  char *s_shares = (char *)calloc(6145, sizeof(char));
  if (!s_shares) return;
  strncpy(s_shares, result_str, 192);
  // s_shares[192] = '\0' from calloc → num_shares = 1

  uint8_t *encr_bls_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_bls_key_len = 0;
  if (!encr_bls_key) return;

  errStatus = 0;
  trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string,
                      s_shares, verifier_key, verifier_enc_len,
                      encr_bls_key, &enc_bls_key_len);
}

// Targeted getDecryptionShare deep coverage via hardcoded alt_bn128 G2 generator:
// trustedGetBlsPubKey/calc_bls_public_key fails before reaching G2 multiply (line 593).
// Fix: bypass trustedGetBlsPubKey entirely; use hardcoded G2 generator string as
// public_decryption_value. getDecryptionShare constructs decryption_value.Z = Fq2::one()
// explicitly (not via G2::one()), so this bypasses the issue.
//   - SplitStringToFq(':') → 4 elements → size()==4 check passes ✓
//   - is_well_formed() → true for BN128 G2 generator ✓
//   - bls_skey * decryption_value → scalar mult → covers getDecryptionShare lines 184-206
//   - Also covers alt_bn128_G2::dbl() additional branches (currently 2/16 edges)
// Previously harness_decryption_share_workflow used random hex without ':' → size()!=4 → returned at line 181

HARNESS_REGISTER(harness_dkg_create_bls_roundtrip, 40)
