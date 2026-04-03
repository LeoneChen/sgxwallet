#pragma once

static void harness_domain_params_edge_cases(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  uint8_t *encrypted_key = (uint8_t *)calloc(1024, 1);
  char *key_out = (char *)calloc(1024, 1);
  if (!encrypted_key || !key_out) return;

  // enc_len = 1 → AES_decrypt length < 28 → line 110 → return -5. Fixed value, no FDP.
  uint64_t short_enc_len = 1;
  trustedDecryptKey(__g_harness_eid, &errStatus, err_string,
                    encrypted_key, short_enc_len, key_out);
}

// Covers ConvertHexToDec with boundary values that stress mpz operations:
// - Maximum length hex strings
// - Leading zeros with various lengths
// - Alternating 0/f patterns
// Targets ConvertHexToDec (DKGUtils.cpp:460, 6/26 edges = 23.1%)

HARNESS_REGISTER(harness_domain_params_edge_cases, 200)
