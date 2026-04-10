#pragma once

static void harness_bls_key_for_ecdsa_sign(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Generate a BLS key (encrypted with type=BLS)
  int is_exportable = 1;
  uint8_t *encrypted_bls_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  if (!encrypted_bls_key) return;

  trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string,
                        &is_exportable, encrypted_bls_key, &enc_len);
  if (errStatus != 0 || enc_len == 0) return;

  // Pass BLS-type key to EcdsaSign → type != ECDSA → error branch at line 523
  char *sig_r = (char *)calloc(1024, sizeof(char));
  char *sig_s = (char *)calloc(1024, sizeof(char));
  uint8_t sig_v = 0;
  if (!sig_r || !sig_s) return;
  errStatus = 0;
  trustedEcdsaSign(__g_harness_eid, &errStatus, err_string,
                   encrypted_bls_key, enc_len,
                   "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9",
                   sig_r, sig_s, &sig_v, 16);
}

// Calls trustedDecryptDkgSecret with garbage input (random bytes of valid length).
// AES_decrypt fails immediately → covers error branch in trustedDecryptDkgSecret
// that cannot be reached via the normal GenDkgSecret → Decrypt path.
// trustedDecryptDkgSecret: 2 hits, 20/58 edges — AES failure path currently uncovered.

HARNESS_REGISTER(harness_bls_key_for_ecdsa_sign, 50)
