#pragma once

static void harness_decrypt_dkg_secret_standalone(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  uint8_t *encrypted_dkg_secret = (uint8_t *)calloc(3072, sizeof(uint8_t));
  uint64_t enc_len = 0;
  if (!encrypted_dkg_secret) return;

  size_t t = g_fdp->ConsumeIntegralInRange<size_t>(1, 4);
  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_dkg_secret, &enc_len, t);
  if (errStatus != 0 || enc_len == 0) return;

  uint8_t *decrypted = (uint8_t *)calloc(3072, sizeof(uint8_t));
  if (!decrypted) return;

  trustedDecryptDkgSecret(__g_harness_eid, &errStatus, err_string,
                          encrypted_dkg_secret, enc_len, decrypted);
}

// ============================================================================
// Customized Initialization
// ============================================================================

// Dedicated: SetSEK workflow (trustedSetSEK has 0/46 edges - never covered)
// trustedSetSEK requires valid sgx_sealed_data_t; random bytes always fail
// sgx_unseal_data(). Uses g_sealed_sek_buf saved by preamble from trustedGenerateSEK
// or trustedSetSEKBackup. trustedSetSEK has its OWN CALL_ONCE counter (separate from
// trustedGenerateSEK's), so the first call to trustedSetSEK each iteration proceeds.
// SGX sealing uses SGX_KEYPOLICY_MRENCLAVE: same binary can unseal across instances.

HARNESS_REGISTER(harness_decrypt_dkg_secret_standalone, 80)
