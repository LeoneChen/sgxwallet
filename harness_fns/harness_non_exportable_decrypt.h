#pragma once

static void harness_non_exportable_decrypt(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Generate key with is_exportable=0 -> key gets NON_EXPORTABLE flag
  int is_exportable = 0;
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  char *pub_y = (char *)calloc(1024, sizeof(char));
  if (!encrypted_key || !pub_x || !pub_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, encrypted_key, &enc_len, pub_x, pub_y);
  if (errStatus != 0 || enc_len == 0) return;

  // trustedDecryptKey detects NON_EXPORTABLE flag at line 634, erases key, returns -11
  char *decrypted_key = (char *)calloc(1024, sizeof(char));
  if (!decrypted_key) return;
  trustedDecryptKey(__g_harness_eid, &errStatus, err_string,
                    encrypted_key, enc_len, decrypted_key);
}

// trustedEcdsaSign mpz_set_str hash failure (line 550-554 in secure_enclave.c).
// Use non-hex characters (e.g., 'g'-'z') in hash so mpz_set_str(msgMpz, hash, 16)
// returns -1, hitting the previously uncovered error branch.

HARNESS_REGISTER(harness_non_exportable_decrypt, 25)
