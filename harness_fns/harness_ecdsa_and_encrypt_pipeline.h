#pragma once

static void harness_ecdsa_and_encrypt_pipeline(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Step 1: Generate ECDSA key (exportable)
  int is_exportable = 1;
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  char *pub_x = (char *)calloc(65, sizeof(char));
  char *pub_y = (char *)calloc(65, sizeof(char));
  if (!encrypted_key || !pub_x || !pub_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, encrypted_key, &enc_len, pub_x, pub_y);
  if (errStatus != 0 || enc_len == 0) return;

  // Step 2: GetPublicEcdsaKey (trustedGetPublicEcdsaKey: 2 hits, 24/70)
  char *out_x = (char *)calloc(65, sizeof(char));
  char *out_y = (char *)calloc(65, sizeof(char));
  if (!out_x || !out_y) return;
  errStatus = 0;
  trustedGetPublicEcdsaKey(__g_harness_eid, &errStatus, err_string,
                           encrypted_key, enc_len, out_x, out_y);

  // Step 3: EcdsaSign with fixed valid hex hash (trustedEcdsaSign: 5 hits, 31/93)
  const char *fixed_hash =
      "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9";
  char *sig_r = (char *)calloc(1024, sizeof(char));
  char *sig_s = (char *)calloc(1024, sizeof(char));
  uint8_t sig_v = 0;
  if (!sig_r || !sig_s) return;
  errStatus = 0;
  trustedEcdsaSign(__g_harness_eid, &errStatus, err_string,
                   encrypted_key, enc_len, fixed_hash, sig_r, sig_s, &sig_v, 16);

  // Step 4: EncryptKey using pub_x as key material (trustedEncryptKey: 4 hits, 24/70)
  uint8_t *enc_key2 = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len2 = 0;
  if (!enc_key2) return;
  errStatus = 0;
  trustedEncryptKey(__g_harness_eid, &errStatus, err_string, pub_x, enc_key2, &enc_len2);
  if (errStatus != 0 || enc_len2 == 0) return;

  // Step 5: DecryptKey (trustedDecryptKey: 5 hits, 20/58)
  char *decrypted = (char *)calloc(1024, sizeof(char));
  if (!decrypted) return;
  errStatus = 0;
  trustedDecryptKey(__g_harness_eid, &errStatus, err_string,
                    enc_key2, enc_len2, decrypted);
}

// Encrypt a 64-char non-hex string, then sign with it in both ECDSA and BLS.
// trustedEcdsaSign line 544: mpz_set_str(privateKeyMpz, skey, 16) fails (G not hex) → error branch
// trustedBlsSignMessage line 723: keyFromString fails → !enclave_sign → error branch

HARNESS_REGISTER(harness_ecdsa_and_encrypt_pipeline, 50)
