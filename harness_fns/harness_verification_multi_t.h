#pragma once

static void harness_verification_multi_t(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // t=2 deterministic: Verification loop runs for i=0,1 → back-edge covered.
  // Cheaper than t=3, no FDP needed; boosts weight budget efficiency.
  unsigned t = 2;

  static const char G2_GEN_HEX[257] =
      "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"  // X.c0
      "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"  // X.c1
      "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"  // Y.c0
      "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"; // Y.c1

  // GenDkgSecret with t=2 or t=3
  uint8_t *encrypted_poly = (uint8_t *)calloc(3072, sizeof(uint8_t));
  uint64_t poly_enc_len = 0;
  if (!encrypted_poly) return;
  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_poly, &poly_enc_len, t);
  if (errStatus != 0 || poly_enc_len == 0) return;

  // Generate verifier ECDSA key for ECDH
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

  char *pub_keyB = (char *)calloc(129, sizeof(char));
  if (!pub_keyB) return;
  strncpy(pub_keyB, pub_x, 64);
  strncpy(pub_keyB + 64, pub_y, 64);
  pub_keyB[128] = '\0';

  // GetEncryptedSecretShare with t (for ECDH-valid result_str)
  uint8_t *encrypted_skey = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t skey_enc_len = 0;
  char *result_str = (char *)calloc(193, sizeof(char));
  char *s_shareG2 = (char *)calloc(320, sizeof(char));
  if (!encrypted_skey || !result_str || !s_shareG2) return;
  errStatus = 0;
  trustedGetEncryptedSecretShare(
      __g_harness_eid, &errStatus, err_string,
      encrypted_poly, poly_enc_len, encrypted_skey, &skey_enc_len,
      result_str, s_shareG2, pub_keyB, (uint8_t)t, (uint8_t)t, 1);
  if (errStatus != 0 || skey_enc_len == 0) return;

  // public_shares = t copies of G2_GEN_HEX (each 256 hex chars, total 256*t bytes)
  // Verification() loop: for i=0..t-1: ConvertHexToDec(G2_GEN_HEX) → valid G2 → loop body
  size_t ps_size = 256 * t + 1;
  char *public_shares = (char *)calloc(ps_size, sizeof(char));
  int *verify_result = (int *)calloc(1, sizeof(int));
  if (!public_shares || !verify_result) return;
  for (unsigned i = 0; i < t; i++)
    strncpy(public_shares + 256 * i, G2_GEN_HEX, 256);

  errStatus = 0;
  trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                   public_shares, result_str, verifier_key, verifier_enc_len,
                   t, 1, verify_result);
}

// Null-check error paths for trustedGetEncryptedSecretShare and V2.
// Covers CHECK_STATE branches at lines 853-856 (V1) and 928-931 (V2)
// and trustedSetEncryptedDkgPoly failure (lines 862, 937).

// Null-check error paths for trustedGenDkgSecret, trustedDecryptDkgSecret,
// trustedGetPublicShares, trustedDkgVerify, trustedDkgVerifyV2,
// trustedCreateBlsKey, and trustedBlsSignMessage.
// Covers CHECK_STATE failure branches (goto clean) at:
//   trustedGenDkgSecret:       line 752  (NULL encrypted_dkg_secret)
//   trustedDecryptDkgSecret:   line 797  (NULL encrypted_dkg_secret)
//                              line 798  (NULL decrypted_dkg_secret)
//   trustedGetPublicShares:    line 1005 (NULL public_shares)
//                              line 1006 (CHECK_STATE(_t > 0), _t==0)
//   trustedDkgVerify:          line 1034 (NULL public_shares)
//                              line 1035 (NULL s_share)
//                              line 1036 (NULL encryptedPrivateKey)
//   trustedDkgVerifyV2:        line 1086 (NULL publicShares)
//                              line 1087 (NULL secretShare)
//                              line 1088 (NULL encryptedPrivateKey)
//   trustedCreateBlsKey:       line 1145 (NULL s_shares)
//                              line 1146 (NULL encryptedPrivateKey)
//                              line 1147 (NULL encr_bls_key)
//   trustedBlsSignMessage:     line 708  (NULL encryptedPrivateKey)
//                              line 709  (NULL _hashX)
//                              line 710  (NULL _hashY)
//                              line 711  (NULL signature)
// All branches consistently uncovered because valid harnesses always
// supply non-NULL arguments. Passing NULL from host is safe: the SGX
// SDK wrapper skips allocation when _tmp_xxx==NULL, passing NULL into
// the enclave, which triggers CHECK_STATE and jumps to clean.

HARNESS_REGISTER(harness_verification_multi_t, 50)
