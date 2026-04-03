#pragma once

static void harness_ecdsa_get_pubkey(void) {
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

  char *out_x = (char *)calloc(1024, sizeof(char));
  char *out_y = (char *)calloc(1024, sizeof(char));
  if (!out_x || !out_y) return;

  trustedGetPublicEcdsaKey(__g_harness_eid, &errStatus, err_string,
                           encrypted_key, enc_len, out_x, out_y);
}

// Dedicated: EcdsaSign (0/93 edges, completely uncovered)

HARNESS_REGISTER(harness_ecdsa_get_pubkey, 60)
