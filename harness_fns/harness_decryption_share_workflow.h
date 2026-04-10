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

  // public_decryption_value: "d1:d2:d3:d4" format, each di is a decimal string.
  // libff::bigint<4> can represent at most ~77 decimal digits (bn128 Fq modulus).
  // Generating values longer than 77 digits triggers assert in bigint.tcc:40 (false positive).
  // Use fuzz bytes to pick length of each segment (1..77 digits) and digit values.
  char *pub_dec_val = (char *)calloc(320, sizeof(char));
  char *dec_share = (char *)calloc(320, sizeof(char));
  if (!pub_dec_val || !dec_share) return;

  // Build "d1:d2:d3:d4" — each segment: 1..77 decimal digits
  size_t offset = 0;
  for (int seg = 0; seg < 4; seg++) {
    size_t seg_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 77);
    for (size_t j = 0; j < seg_len && offset < 318; j++)
      pub_dec_val[offset++] = '0' + g_fdp->ConsumeIntegralInRange<int>(0, 9);
    if (seg < 3 && offset < 318)
      pub_dec_val[offset++] = ':';
  }
  pub_dec_val[offset] = '\0';

  trustedGetDecryptionShare(__g_harness_eid, &errStatus, err_string,
                            encrypted_key, pub_dec_val, enc_len,
                            dec_share);
}

// Workflow 12: Full V2 DKG round-trip - GenSecret -> GetEncryptedSecretShareV2 -> DkgVerifyV2
// Targets: Complete V2 code path end-to-end (all V2 functions in sequence)

HARNESS_REGISTER(harness_decryption_share_workflow, 30)
