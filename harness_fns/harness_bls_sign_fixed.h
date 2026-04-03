#pragma once

static void harness_bls_sign_fixed(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  int is_exportable = 1;
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  if (!encrypted_key) return;

  trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string,
                        &is_exportable, encrypted_key, &enc_len);
  if (errStatus != 0 || enc_len == 0) return;

  // Fixed decimal coords of the BN128 G1 generator (1, 2): satisfies y^2=x^3+3
  // libff::alt_bn128_Fq takes decimal strings; hex coords would be parsed wrong
  // and off-curve coords cause libff to abort in to_affine_coordinates()
  static const char hashX[] = "1";
  static const char hashY[] = "2";
  char *signature = (char *)calloc(1024, sizeof(char));
  if (!signature) return;

  trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                        encrypted_key, enc_len,
                        (char *)hashX, (char *)hashY, signature);
}

// Complete DKG roundtrip with correct ECDH pairing:
// GenDkgSecret → GetPublicShares → GenerateEcdsaKey (verifier key)
// → GetEncryptedSecretShare (pub_keyB = verifier pubkey) → DkgVerify (verifier privkey)
// Key insight: verifier_skey × ephemeral_pub = ephemeral_skey × verifier_pub (ECDH)
// So DkgVerify with verifier_skey and result_str recovers the correct common_key.

HARNESS_REGISTER(harness_bls_sign_fixed, 15)
