#pragma once

static void harness_encrypt_key_variations(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Encrypt with various key formats and lengths
  char *key = (char *)calloc(1024, sizeof(char));
  if (!key) return;

  int key_type = g_fdp->ConsumeIntegralInRange<int>(0, 3);
  size_t key_len;
  switch (key_type) {
    case 0: // Short key
      key_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 16);
      fill_hex_string(key, key_len);
      break;
    case 1: // Standard ECDSA key length (64 hex chars)
      key_len = 64;
      fill_hex_string(key, key_len);
      break;
    case 2: // Long key (near buffer limit)
      key_len = g_fdp->ConsumeIntegralInRange<size_t>(500, 900);
      fill_hex_string(key, key_len);
      break;
    case 3: // Key with non-hex chars to test error paths
      key_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 128);
      fill_mixed_hex_string(key, key_len);
      break;
  }

  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  if (!encrypted_key) return;

  trustedEncryptKey(__g_harness_eid, &errStatus, err_string,
                    key, encrypted_key, &enc_len);
  if (errStatus != 0 || enc_len == 0) return;

  // Now decrypt it - tests trustedDecryptKey deeper paths
  char *decrypted_key = (char *)calloc(1024, sizeof(char));
  if (decrypted_key) {
    errStatus = 0;
    trustedDecryptKey(__g_harness_eid, &errStatus, err_string,
                      encrypted_key, enc_len, decrypted_key);
  }
}

// ============================================================================
// Dedicated Bottleneck Harnesses (for completely uncovered functions)
// ============================================================================

// Dedicated: GetPublicEcdsaKey (0/70 edges, completely uncovered)

HARNESS_REGISTER(harness_encrypt_key_variations, 8)
