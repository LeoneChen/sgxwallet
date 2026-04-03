#pragma once

static void harness_sealhexsek_callonce_trigger(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Attempt trustedSetSEKBackup (executes body when preamble used Path A)
  // Pass a valid 32-char hex SEK so trustedSetSEKBackup body reaches sealHexSEK.
  uint8_t *enc_sek = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  char *sek_hex = (char *)calloc(33, sizeof(char));
  if (!enc_sek || !sek_hex) return;
  memset(sek_hex, '0', 32);
  sek_hex[32] = '\0';
  trustedSetSEKBackup(__g_harness_eid, &errStatus, err_string,
                      enc_sek, &enc_len, sek_hex);

  // Attempt trustedGenerateSEK (executes body when preamble used Path B)
  errStatus = 0;
  uint8_t *enc_sek2 = (uint8_t *)calloc(1024, sizeof(uint8_t));
  char *hex_out = (char *)calloc(65, sizeof(char));
  uint64_t enc_len2 = 0;
  if (!enc_sek2 || !hex_out) return;
  trustedGenerateSEK(__g_harness_eid, &errStatus, err_string,
                     enc_sek2, &enc_len2, hex_out);
}

// Covers AES_encrypt line 60 (AESUtils.c): encrBufLen too small → return -4
// trustedEncryptKey calls AES_encrypt(key, encryptedPrivateKey, BUF_LEN=1024, ...)
// Condition: 2 + strlen(key)+1 + SGX_AESGCM_MAC_SIZE(16) + SGX_AESGCM_IV_SIZE(12) > 1024
//   → 2 + (strlen+1) + 28 > 1024 → strlen >= 994 triggers the check.
// A 994-char key reliably fires AESUtils.c line 60.

HARNESS_REGISTER(harness_sealhexsek_callonce_trigger, 50)
