#pragma once

// Target: signature_verify at secure_enclave.c:567 (sigCounter % 1000 == 0)
// Root cause analysis: enclave is destroyed and recreated each LLVMFuzzerTestOneInput
// iteration (runtime-v/host/test.cpp:82-94), so sigCounter resets every iteration.
// Solution: call trustedEcdsaSign 1000+ times in a SINGLE iteration to cross the threshold.
// Trade-off: slow per-iteration but guaranteed to hit signature_verify every time.
// Use a fixed valid ECDSA key (no fuzz data after key generation) for speed.

static void harness_ecdsa_sign_highfreq(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Generate ECDSA key once
  int is_exportable = 1;
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  char *pub_y = (char *)calloc(1024, sizeof(char));
  if (!encrypted_key || !pub_x || !pub_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, encrypted_key, &enc_len,
                          pub_x, pub_y);
  if (errStatus != 0 || enc_len == 0) return;

  // Fixed hash: valid 64-char hex, no fuzz data consumed → fast loop
  const char *fixed_hash = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
                           "e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";

  // Sign 1001 times to guarantee sigCounter % 1000 == 0 is hit at least once
  for (int i = 0; i < 1001; i++) {
    char *sig_r = (char *)calloc(1024, sizeof(char));
    char *sig_s = (char *)calloc(1024, sizeof(char));
    uint8_t sig_v = 0;
    if (!sig_r || !sig_s) { free(sig_r); free(sig_s); break; }

    errStatus = 0;
    trustedEcdsaSign(__g_harness_eid, &errStatus, err_string,
                     encrypted_key, enc_len, fixed_hash, sig_r, sig_s,
                     &sig_v, 16);
    free(sig_r);
    free(sig_s);
  }
}

HARNESS_REGISTER(harness_ecdsa_sign_highfreq, 10)
