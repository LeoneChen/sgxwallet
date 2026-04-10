#pragma once

static void harness_bls_generate_standalone(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  int is_exportable = g_fdp->ConsumeIntegralInRange<int>(0, 1);
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  if (!encrypted_key) return;

  trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string,
                        &is_exportable, encrypted_key, &enc_len);
}

// Dedicated: BlsSignMessage (0/80 edges, completely uncovered)

HARNESS_REGISTER(harness_bls_generate_standalone, 30)
