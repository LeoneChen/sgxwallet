#pragma once

static void harness_complete_dkg_roundtrip(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Step 1: Generate DKG polynomial (t=1..3 for speed)
  size_t t = g_fdp->ConsumeIntegralInRange<size_t>(1, 3);
  uint8_t *encrypted_poly = (uint8_t *)calloc(3072, sizeof(uint8_t));
  uint64_t poly_enc_len = 0;
  if (!encrypted_poly) return;
  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_poly, &poly_enc_len, t);
  if (errStatus != 0 || poly_enc_len == 0) return;

  // Step 2: Get real public shares (valid BN128 G2 points)
  char *public_shares = (char *)calloc(10000, sizeof(char));
  if (!public_shares) return;
  trustedGetPublicShares(__g_harness_eid, &errStatus, err_string,
                         encrypted_poly, poly_enc_len, public_shares, (unsigned)t);
  if (errStatus != 0) return;

  // Step 3: Generate ECDSA key (verifier key: its public key = pub_keyB)
  int is_exportable = 1;
  uint8_t *verifier_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t verifier_enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  char *pub_y = (char *)calloc(1024, sizeof(char));
  if (!verifier_key || !pub_x || !pub_y) return;
  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, verifier_key, &verifier_enc_len, pub_x, pub_y);
  if (errStatus != 0 || verifier_enc_len == 0) return;

  // Build pub_keyB = pub_x(64) + pub_y(64) as verifier's public EC point
  char *pub_keyB = (char *)calloc(129, sizeof(char));
  if (!pub_keyB) return;
  strncpy(pub_keyB, pub_x, 64);
  strncpy(pub_keyB + 64, pub_y, 64);
  pub_keyB[128] = '\0';

  // Step 4: GetEncryptedSecretShare with verifier's pubkey as pub_keyB
  // Inside enclave: generates ephemeral ECDSA key, ECDH(ephemeral_skey, verifier_pub) = common_key
  uint8_t *encrypted_skey = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t skey_enc_len = 0;
  char *result_str = (char *)calloc(193, sizeof(char));
  char *s_shareG2 = (char *)calloc(320, sizeof(char));
  if (!encrypted_skey || !result_str || !s_shareG2) return;

  uint8_t n = (uint8_t)g_fdp->ConsumeIntegralInRange<size_t>(t, t + 3);
  uint8_t ind = (uint8_t)g_fdp->ConsumeIntegralInRange<size_t>(1, (size_t)n);

  // Use V1 or V2 based on remaining fuzz data
  bool use_v2 = (g_fdp->remaining_bytes() > 0) && (g_fdp->ConsumeProbability<double>() < 0.5);
  if (!use_v2) {
    trustedGetEncryptedSecretShare(
        __g_harness_eid, &errStatus, err_string,
        encrypted_poly, poly_enc_len, encrypted_skey, &skey_enc_len,
        result_str, s_shareG2, pub_keyB, (uint8_t)t, n, ind);
  } else {
    trustedGetEncryptedSecretShareV2(
        __g_harness_eid, &errStatus, err_string,
        encrypted_poly, poly_enc_len, encrypted_skey, &skey_enc_len,
        result_str, s_shareG2, pub_keyB, (uint8_t)t, n, ind);
  }
  if (errStatus != 0 || skey_enc_len == 0) return;

  // Step 5: DkgVerify with result_str as s_share and verifier's private key
  // ECDH: verifier_skey × ephemeral_pub = ephemeral_skey × verifier_pub → same common_key
  // So xor_decrypt(common_key, cypher) recovers the correct s_share
  int *verify_result = (int *)calloc(1, sizeof(int));
  if (!verify_result) return;

  if (!use_v2) {
    trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                     public_shares, result_str, verifier_key, verifier_enc_len,
                     (unsigned)t, (int)ind, verify_result);
  } else {
    trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string,
                       public_shares, result_str, verifier_key, verifier_enc_len,
                       (unsigned)t, (int)ind, verify_result);
  }
}

// BLS CreateBlsKey → BlsSignMessage + GetBlsPubKey + GetDecryptionShare
// Uses real ECDH-derived BLS key (from CreateBlsKey) rather than GenerateBLSKey
// Covers deeper trustedBlsSignMessage / trustedGetBlsPubKey / trustedGetDecryptionShare paths

HARNESS_REGISTER(harness_complete_dkg_roundtrip, 60)
