#pragma once

static void harness_bls_create_and_use(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Generate ECDSA key A: its pubkey coordinates go into s_shares[64:192]
  int is_exp_a = 1;
  uint8_t *ecdsa_key_a = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t ecdsa_enc_len_a = 0;
  char *pub_x_a = (char *)calloc(1024, sizeof(char));
  char *pub_y_a = (char *)calloc(1024, sizeof(char));
  if (!ecdsa_key_a || !pub_x_a || !pub_y_a) return;
  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exp_a, ecdsa_key_a, &ecdsa_enc_len_a, pub_x_a, pub_y_a);
  if (errStatus != 0 || ecdsa_enc_len_a == 0) return;

  // Generate ECDSA key B: its private key decrypted inside enclave for session_key_recover
  int is_exp_b = 1;
  uint8_t *ecdsa_key_b = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t ecdsa_enc_len_b = 0;
  char *pub_x_b = (char *)calloc(1024, sizeof(char));
  char *pub_y_b = (char *)calloc(1024, sizeof(char));
  if (!ecdsa_key_b || !pub_x_b || !pub_y_b) return;
  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exp_b, ecdsa_key_b, &ecdsa_enc_len_b, pub_x_b, pub_y_b);
  if (errStatus != 0 || ecdsa_enc_len_b == 0) return;

  // Build s_shares: pos 0-63 hex pattern, pos 64-127 pub_x_a, pos 128-191 pub_y_a
  char *s_shares = (char *)calloc(6145, sizeof(char));
  if (!s_shares) return;
  static const char hex_pat2[] = "0123456789abcdef";
  for (int i = 0; i < 64; i++) s_shares[i] = hex_pat2[i % 16];
  strncpy(s_shares + 64, pub_x_a, 64);
  strncpy(s_shares + 128, pub_y_a, 64);
  // s_shares[192] = '\0' (calloc) → 1 share iteration

  // CreateBlsKey with ecdsa_key_b as the verifier key
  uint8_t *encr_bls_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_bls_key_len = 0;
  if (!encr_bls_key) return;
  trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string,
                      s_shares, ecdsa_key_b, ecdsa_enc_len_b,
                      encr_bls_key, &enc_bls_key_len);
  if (errStatus != 0 || enc_bls_key_len == 0) return;

  // Sign with BLS key using BN128 G1 generator (1, 2)
  char *signature = (char *)calloc(1024, sizeof(char));
  if (!signature) return;
  errStatus = 0;
  trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                        encr_bls_key, enc_bls_key_len,
                        (char *)"1", (char *)"2", signature);

  // Get BLS public key
  char *bls_pub_key = (char *)calloc(320, sizeof(char));
  if (!bls_pub_key) return;
  errStatus = 0;
  trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string,
                      encr_bls_key, enc_bls_key_len, bls_pub_key);

  // Get decryption share with fuzzed public_decryption_value
  char *pub_dec_val = (char *)calloc(320, sizeof(char));
  char *dec_share = (char *)calloc(320, sizeof(char));
  if (!pub_dec_val || !dec_share) return;
  size_t fill_len2 = g_fdp->remaining_bytes() > 0
                         ? g_fdp->ConsumeIntegralInRange<size_t>(1, 319)
                         : 64;
  fill_hex_string(pub_dec_val, fill_len2);
  errStatus = 0;
  trustedGetDecryptionShare(__g_harness_eid, &errStatus, err_string,
                            encr_bls_key, pub_dec_val, enc_bls_key_len, dec_share);
}

// Targeted DkgVerify + CreateBlsKey deep coverage:
// GenDkgSecret → GenerateEcdsaKey (verifier) → GetEncryptedSecretShare (pub_keyB = verifier pub)
// → DkgVerify (verifier key + result_str) → CreateBlsKey (verifier key + result_str as s_shares)
//
// The ECDH pairing ensures AES_decrypt + session_key_recover succeed inside DkgVerify/CreateBlsKey:
//   GetEncryptedSecretShare: common_key = ECDH(ephemeral_skey, verifier_pub)
//   DkgVerify session_key_recover: common_key = ECDH(verifier_skey, ephemeral_pub) == same key
//   xor_decrypt(common_key, cypher) = actual BN field element hex → mpz_set_str succeeds
//   Verification() is called — covers trustedDkgVerify lines past AES_decrypt (2→9 edges)
//
// CreateBlsKey uses result_str as s_shares (one 192-char entry):
//   Same ECDH recovery → xor_decrypt = valid share → mpz_set_str succeeds
//   Loop body line 1174 and mpz_addmul_ui/mpz_mod covered (7→18 edges)

HARNESS_REGISTER(harness_bls_create_and_use, 60)
