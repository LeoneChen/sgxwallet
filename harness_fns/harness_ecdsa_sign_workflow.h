#pragma once

static void harness_ecdsa_sign_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  int is_exportable = 1;
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  char *pub_y = (char *)calloc(1024, sizeof(char));
  if (!encrypted_key || !pub_x || !pub_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, encrypted_key, &enc_len,
                          pub_x, pub_y);
  if (errStatus != 0 || enc_len == 0) return;

  size_t hash_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 64);
  char *hash = (char *)calloc(hash_len + 1, sizeof(char));
  if (!hash) return;
  fill_hex_string(hash, hash_len);

  char *sig_r = (char *)calloc(1024, sizeof(char));
  char *sig_s = (char *)calloc(1024, sizeof(char));
  uint8_t *sig_v = (uint8_t *)calloc(1, sizeof(uint8_t));
  if (!sig_r || !sig_s || !sig_v) return;

  int base = g_fdp->ConsumeIntegralInRange<int>(10, 16);
  trustedEcdsaSign(__g_harness_eid, &errStatus, err_string,
                   encrypted_key, enc_len, hash, sig_r, sig_s, sig_v, base);
}

// Dedicated: GenerateBLSKey standalone (0/70 edges, completely uncovered)

HARNESS_REGISTER(harness_ecdsa_sign_workflow, 50)
