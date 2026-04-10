#pragma once

static void harness_bls_pubkey_workflow(void) {
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
  if (errStatus != 0 || enc_len == 0) return;

  char *bls_pub_key = (char *)calloc(320, sizeof(char));
  if (!bls_pub_key) return;

  trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string,
                      encrypted_key, enc_len, bls_pub_key);
}

// Dedicated: GetPublicShares (0/58 edges, completely uncovered)

HARNESS_REGISTER(harness_bls_pubkey_workflow, 20)
