#pragma once

static void harness_create_bls_key_v2_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Generate ECDSA key
  int is_exportable = 1;
  uint8_t *ecdsa_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t ecdsa_enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  char *pub_y = (char *)calloc(1024, sizeof(char));
  if (!ecdsa_key || !pub_x || !pub_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, ecdsa_key, &ecdsa_enc_len,
                          pub_x, pub_y);
  if (errStatus != 0 || ecdsa_enc_len == 0) return;

  // Generate s_shares with varied sizes to test boundary conditions
  // Each share block is 192 chars. Vary count 1-16
  int num_shares = g_fdp->ConsumeIntegralInRange<int>(1, 16);
  size_t shares_len = (size_t)192 * num_shares;
  // Allocate full 6145 bytes (matching EDL [in, count=6145]) to avoid over-read
  char *s_shares = (char *)calloc(6145, sizeof(char));
  if (!s_shares) return;

  // Mix valid and invalid hex to trigger mpz_set_str failure path
  if (g_fdp->ConsumeProbability<double>() < 0.6) {
    fill_hex_string(s_shares, shares_len);
  } else {
    fill_mixed_hex_string(s_shares, shares_len);
  }

  uint8_t *encr_bls_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_bls_key_len = 0;
  if (!encr_bls_key) return;

  // ALWAYS call V2
  trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string,
                        s_shares, ecdsa_key, ecdsa_enc_len,
                        encr_bls_key, &enc_bls_key_len);
}

// Workflow 9: GetEncryptedSecretShareV2 dedicated (2/14 edges, hit only once)
// Targets: trustedGetEncryptedSecretShareV2, xor_encrypt_v2, hash_key

HARNESS_REGISTER(harness_create_bls_key_v2_workflow, 50)
