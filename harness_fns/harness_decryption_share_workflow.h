#pragma once

static void harness_decryption_share_workflow(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Generate BLS key (provides valid encrypted BLS private key)
  int is_exportable = g_fdp->ConsumeIntegralInRange<int>(0, 1);
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  if (!encrypted_key) return;

  trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string,
                        &is_exportable, encrypted_key, &enc_len);
  if (errStatus != 0 || enc_len == 0) return;

  // public_decryption_value: fuzzed 320-byte hex string (G2 point repr)
  char *pub_dec_val = (char *)calloc(320, sizeof(char));
  char *dec_share = (char *)calloc(320, sizeof(char));
  if (!pub_dec_val || !dec_share) return;

  // Fill with hex - represents a serialized G2 point
  size_t fill_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 319);
  if (g_fdp->ConsumeProbability<double>() < 0.7) {
    fill_hex_string(pub_dec_val, fill_len);
  } else {
    fill_mixed_hex_string(pub_dec_val, fill_len);
  }

  trustedGetDecryptionShare(__g_harness_eid, &errStatus, err_string,
                            encrypted_key, pub_dec_val, enc_len,
                            dec_share);
}

// Workflow 12: Full V2 DKG round-trip - GenSecret -> GetEncryptedSecretShareV2 -> DkgVerifyV2
// Targets: Complete V2 code path end-to-end (all V2 functions in sequence)

HARNESS_REGISTER(harness_decryption_share_workflow, 30)
