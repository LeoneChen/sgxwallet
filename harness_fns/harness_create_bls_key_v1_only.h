#pragma once

static void harness_create_bls_key_v1_only(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

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

  int num_shares = g_fdp->ConsumeIntegralInRange<int>(1, 16);
  size_t shares_len = (size_t)192 * num_shares;
  // Allocate full 6145 bytes (matching EDL [in, count=6145]) to avoid over-read
  char *s_shares = (char *)calloc(6145, sizeof(char));
  if (!s_shares) return;
  fill_hex_string(s_shares, shares_len);

  uint8_t *encr_bls_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_bls_key_len = 0;
  if (!encr_bls_key) return;

  trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string,
                      s_shares, ecdsa_key, ecdsa_enc_len,
                      encr_bls_key, &enc_bls_key_len);
}

// Dedicated: DkgVerify V1 (0/80 edges, completely uncovered)

HARNESS_REGISTER(harness_create_bls_key_v1_only, 25)
