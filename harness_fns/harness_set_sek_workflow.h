#pragma once

static void harness_set_sek_workflow(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // trustedSetSEK uses CALL_ONCE: only one call allowed per enclave instance.
  // Pick ONE path per iteration using fuzz data.
  int path = g_fdp->ConsumeIntegralInRange<int>(0, 2);
  switch (path) {
    case 0:
      // Path 1: Valid sealed SEK from preamble (success path)
      if (g_sealed_sek_len > 0) {
        trustedSetSEK(__g_harness_eid, &errStatus, err_string, g_sealed_sek_buf);
      }
      break;
    case 1:
      // Path 2: NULL -> CHECK_STATE(encrypted_sek) fail
      trustedSetSEK(__g_harness_eid, &errStatus, err_string, NULL);
      break;
    case 2: {
      // Path 3: Random bytes -> sgx_unseal_data fail -> 0x3001 error path
      uint8_t *rand_sek = (uint8_t *)calloc(1024, 1);
      if (rand_sek) {
        size_t fill = g_fdp->ConsumeIntegralInRange<size_t>(16, 1024);
        g_fdp->ConsumeData(rand_sek, fill);
        trustedSetSEK(__g_harness_eid, &errStatus, err_string, rand_sek);
      }
      break;
    }
  }
}

// Fix gen_session_key coverage: trustedGetEncryptedSecretShare needs a valid
// secp256k1 EC point as pub_keyB. Previous harness used random hex which always
// fails point_set_hex validation. Use real pub_x+pub_y from trustedGenerateEcdsaKey.

HARNESS_REGISTER(harness_set_sek_workflow, 25)
