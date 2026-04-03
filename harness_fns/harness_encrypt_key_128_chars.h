#pragma once

static void harness_encrypt_key_128_chars(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // 128 lowercase-hex chars — valid content but strnlen(..., 128) == 128 == MAX_KEY_LENGTH
  char *key128 = (char *)calloc(129, sizeof(char));
  if (!key128) return;
  memset(key128, 'a', 128);
  // key128[128] = '\0' from calloc

  uint8_t *enc_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  if (!enc_key) return;

  // trustedEncryptKey: AES_encrypt succeeds → AES_decrypt → strnlen == 128 → line 679 ✓
  trustedEncryptKey(__g_harness_eid, &errStatus, err_string,
                    key128, enc_key, &enc_len);
  // errStatus will be non-zero (line 679 goto clean), but enc_len is valid
  if (enc_len == 0) return;

  // trustedDecryptKey: AES_decrypt → output has 128 'a's → strnlen == 128 → line 628 ✓
  char *dec_key = (char *)calloc(1024, sizeof(char));
  if (!dec_key) return;
  errStatus = 0;
  trustedDecryptKey(__g_harness_eid, &errStatus, err_string,
                    enc_key, enc_len, dec_key);
}

// trustedGenerateEcdsaKey: NON_EXPORTABLE else-branch (line 420-422) never covered.
// All previous harnesses pass is_exportable=1 → only the EXPORTABLE branch runs.
// trustedDecryptKey: exportable != EXPORTABLE → "access denied" error (new branch).
// trustedEcdsaSign: NON_EXPORTABLE key still signs correctly (type==ECDSA check passes).

HARNESS_REGISTER(harness_encrypt_key_128_chars, 150)
