#pragma once

static void harness_aes_encrypt_long_key(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  char *key = (char *)calloc(1024, sizeof(char));
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, 1);
  uint64_t enc_len = 0;
  if (!key || !encrypted_key) return;

  // strlen(key) = 994: 2 + 995 + 28 = 1025 > 1024 = BUF_LEN → AES_encrypt line 60 → return -4
  memset(key, 'A', 994);

  trustedEncryptKey(__g_harness_eid, &errStatus, err_string,
                    key, encrypted_key, &enc_len);
}

// Covers calc_secret_share line 346 (poly.size() != _t):
// When trustedGetEncryptedSecretShare is called with a _t that differs from the
// number of coefficients in the stored DKG poly, SplitStringToFr returns a vector
// whose size != _t, triggering the early return at line 346.
// Strategy: generate poly with t=1 (1 coefficient), then call
// GetEncryptedSecretShare with _t=3 → poly.size()=1 != 3 → line 346 ✓.
// Need a valid secp256k1 pubKeyB for gen_session_key to proceed past its own
// strnlen check; use trustedGenerateEcdsaKey output (pub_x + pub_y = 128 chars).

HARNESS_REGISTER(harness_aes_encrypt_long_key, 25)
