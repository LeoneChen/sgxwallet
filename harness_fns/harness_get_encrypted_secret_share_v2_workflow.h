#pragma once

static void harness_get_encrypted_secret_share_v2_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Generate DKG secret first (provides encrypted_poly)
  uint8_t *encrypted_dkg_secret = (uint8_t *)calloc(3072, sizeof(uint8_t));
  uint64_t enc_len = 0;
  size_t t = g_fdp->ConsumeIntegralInRange<size_t>(1, 4);
  if (!encrypted_dkg_secret) return;

  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_dkg_secret, &enc_len, t);
  if (errStatus != 0 || enc_len == 0) return;

  // Prepare output buffers
  uint8_t *encrypted_skey = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t dec_len = 0;
  char *result_str = (char *)calloc(193, sizeof(char));
  char *s_shareG2 = (char *)calloc(320, sizeof(char));
  if (!encrypted_skey || !result_str || !s_shareG2) return;

  // pub_keyB: always 128 hex chars - gen_session_key requires strnlen >= 128
  size_t pk_len = 128;
  char *pub_keyB = (char *)calloc(129, sizeof(char));
  if (!pub_keyB) return;
  fill_hex_string(pub_keyB, pk_len);

  uint8_t n = g_fdp->ConsumeIntegralInRange<uint8_t>((uint8_t)t, 16);
  if (n < (uint8_t)t) n = (uint8_t)t;
  uint8_t ind = g_fdp->ConsumeIntegralInRange<uint8_t>(1, n > 0 ? n : 1);

  // ALWAYS call V2
  trustedGetEncryptedSecretShareV2(
      __g_harness_eid, &errStatus, err_string,
      encrypted_dkg_secret, enc_len, encrypted_skey, &dec_len,
      result_str, s_shareG2, pub_keyB, (uint8_t)t, n, ind);
}

// Workflow 10 (removed): ECDSA multi-sign was removed because:
// - The enclave is RECREATED each fuzzing iteration, resetting sigCounter to 0 every time.
//   The sigCounter % 1000 path can therefore never be reached.
// - The 1001-iteration loop caused 20+ second per-iteration slowdowns, making LibFuzzer
//   effectively non-functional (LibFuzzer reported "no interesting inputs" after 2 iterations).

// Workflow 11: GetDecryptionShare with valid BLS key (currently 1 hit, 2/6 edges)
// Targets: trustedGetDecryptionShare, getDecryptionShare in DKGUtils

HARNESS_REGISTER(harness_get_encrypted_secret_share_v2_workflow, 60)
