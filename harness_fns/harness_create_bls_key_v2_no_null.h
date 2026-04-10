#pragma once

// Target: trustedCreateBlsKeyV2 with [in, count=6145] const char* s_shares
// Strategy: fill all 6145 bytes with no \0

static void harness_create_bls_key_v2_no_null(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  uint8_t *encrypted_key = (uint8_t *)calloc(1024, 1);
  uint64_t enc_len = 0;
  char *pub_x = (char *)calloc(1024, 1);
  char *pub_y = (char *)calloc(1024, 1);
  if (!encrypted_key || !pub_x || !pub_y) return;

  int is_exportable = 1;
  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, encrypted_key, &enc_len,
                          pub_x, pub_y);
  if (errStatus != 0 || enc_len == 0) return;

  // Fill all 6145 bytes, no \0
  char *s_shares = (char *)malloc(6145);
  if (!s_shares) return;
  auto bytes = g_fdp->ConsumeBytes<uint8_t>(6145);
  memcpy(s_shares, bytes.data(), bytes.size());
  for (size_t i = bytes.size(); i < 6145; i++)
    s_shares[i] = 'a';
  for (int i = 0; i < 6145; i++)
    if (s_shares[i] == '\0') s_shares[i] = 'a';

  uint8_t *encr_bls_key = (uint8_t *)calloc(1024, 1);
  uint64_t enc_bls_key_len = 0;
  if (!encr_bls_key) return;

  errStatus = 0;
  trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string,
                        s_shares, encrypted_key, enc_len,
                        encr_bls_key, &enc_bls_key_len);

  free(s_shares);
  free(err_string);
  free(encrypted_key);
  free(pub_x);
  free(pub_y);
  free(encr_bls_key);
}

HARNESS_REGISTER(harness_create_bls_key_v2_no_null, 5)
