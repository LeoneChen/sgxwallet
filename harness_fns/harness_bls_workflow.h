#pragma once

static void harness_bls_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Generate BLS key
  int is_exportable = g_fdp->ConsumeIntegralInRange<int>(0, 1);
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  if (!encrypted_key) return;

  trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string,
                        &is_exportable, encrypted_key, &enc_len);
  if (errStatus != 0 || enc_len == 0) return;

  int op = g_fdp->ConsumeIntegralInRange<int>(0, 1);
  switch (op) {
    case 0: {
      // BlsSignMessage with valid key + valid BN128 G1 generator point coords
      // hashX/hashY must be decimal strings of a valid curve point:
      // (1, 2) is the BN128 G1 generator satisfying y^2 = x^3 + 3 mod p
      char *hashX = (char *)calloc(65, sizeof(char));
      char *hashY = (char *)calloc(65, sizeof(char));
      char *signature = (char *)calloc(1024, sizeof(char));
      if (!hashX || !hashY || !signature) break;
      strncpy(hashX, "1", 64);
      strncpy(hashY, "2", 64);
      trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                            encrypted_key, enc_len, hashX, hashY, signature);
      break;
    }
    case 1: {
      // GetBlsPubKey with valid key
      char *bls_pub_key = (char *)calloc(320, sizeof(char));
      if (bls_pub_key) {
        trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string,
                            encrypted_key, enc_len, bls_pub_key);
      }
      break;
    }
  }
}

// Workflow 5: Generate ECDSA key, then DkgVerify with fuzzed shares
// Targets: trustedDkgVerify (22%), trustedDkgVerifyV2 (20%)

HARNESS_REGISTER(harness_bls_workflow, 8)
