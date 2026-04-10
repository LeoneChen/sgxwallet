#pragma once

static void harness_decrypt_dkg_garbage_input(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Fuzz-controlled length in [28, 3072]; AES_decrypt needs ≥28 bytes to attempt decryption
  uint64_t poly_len =
      (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(28, 3072);
  uint8_t *enc_poly = (uint8_t *)calloc(poly_len, sizeof(uint8_t));
  uint8_t *dec_poly = (uint8_t *)calloc(3073, sizeof(uint8_t));
  if (!enc_poly || !dec_poly) return;
  g_fdp->ConsumeData(enc_poly, (size_t)poly_len);

  // AES_decrypt will fail on random bytes → *errStatus = non-zero → error branch ✓
  trustedDecryptDkgSecret(__g_harness_eid, &errStatus, err_string,
                          enc_poly, poly_len, dec_poly);
}

// trustedBlsSignMessage NULL-check paths (lines 708-711) + AES short-enc path.
// harness_null_paths_batch2 covers these (cases 14-17) but is weight=30 in Tier 1
// and rarely triggered (~1 hit in 91 iters). Dedicated Tier-0 harness ensures
// reliable coverage of all 5 error branches per run.

HARNESS_REGISTER(harness_decrypt_dkg_garbage_input, 60)
