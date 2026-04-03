#pragma once

static void harness_sign_invalid_key(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // 64-char key with 'G' chars: valid C string but invalid hex (G > F).
  char *invalid_key = (char *)calloc(65, sizeof(char));
  if (!invalid_key) return;
  memset(invalid_key, 'G', 64);
  // invalid_key[64] = '\0' from calloc

  uint8_t *enc_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  if (!enc_key) return;

  trustedEncryptKey(__g_harness_eid, &errStatus, err_string,
                    invalid_key, enc_key, &enc_len);
  // errStatus will be non-zero (strnlen("GGG...") < 128 → strncmp mismatch actually...
  // But enc_len IS set by AES_encrypt before the error check.
  if (enc_len == 0) return;

  // trustedEcdsaSign: skey = "GGG...G" → mpz_set_str(priv, skey, 16) fails → line 544 ✓
  char *sig_r = (char *)calloc(1024, sizeof(char));
  char *sig_s = (char *)calloc(1024, sizeof(char));
  uint8_t sig_v = 0;
  if (!sig_r || !sig_s) return;
  errStatus = 0;
  trustedEcdsaSign(__g_harness_eid, &errStatus, err_string,
                   enc_key, enc_len,
                   "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9",
                   sig_r, sig_s, &sig_v, 16);

  // trustedBlsSignMessage: AES_decrypt → key = "GGG...G"
  // keyFromString: mpz_set_str("GGG...G", 16) == -1 → returns nullptr
  // enclave_sign returns false → line 723 ✓
  char *signature = (char *)calloc(1024, sizeof(char));
  char *hashX = (char *)calloc(65, sizeof(char));
  char *hashY = (char *)calloc(65, sizeof(char));
  if (!signature || !hashX || !hashY) return;
  strncpy(hashX, "1", 64);
  strncpy(hashY, "2", 64);
  errStatus = 0;
  trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                        enc_key, enc_len, hashX, hashY, signature);
}

// Encrypt a 128-char (= MAX_KEY_LENGTH) key to trigger null-not-terminated error branches.
// trustedEncryptKey line 679: strnlen(decryptedKey, 128) == 128 → "not null terminated" error
// trustedDecryptKey line 628: strnlen(key, 128) == 128 → same condition on decrypt output

HARNESS_REGISTER(harness_sign_invalid_key, 60)
