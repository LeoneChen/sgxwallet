#pragma once

static void harness_bls_sign_workflow(void) {
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

  // hashX/hashY must be decimal strings of a valid BN128 G1 curve point;
  // (1, 2) is the generator satisfying y^2 = x^3 + 3 mod p
  char *hashX = (char *)calloc(65, sizeof(char));
  char *hashY = (char *)calloc(65, sizeof(char));
  char *signature = (char *)calloc(1024, sizeof(char));
  if (!hashX || !hashY || !signature) return;
  strncpy(hashX, "1", 64);
  strncpy(hashY, "2", 64);

  trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                        encrypted_key, enc_len, hashX, hashY, signature);
}

// Dedicated: GetBlsPubKey (0/58 edges, completely uncovered)

HARNESS_REGISTER(harness_bls_sign_workflow, 60)
