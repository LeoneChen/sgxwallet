#pragma once

static void harness_aes_roundtrip_coverage(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Use uppercase hex key (2-64 chars) to cover char2int uppercase path
  size_t key_len = g_fdp->ConsumeIntegralInRange<size_t>(2, 64);
  char *key = (char *)calloc(1024, sizeof(char));
  if (!key) return;
  // 50% uppercase, 50% lowercase to cover both char2int paths
  if (g_fdp->ConsumeProbability<double>() < 0.5) {
    fill_uppercase_hex_string(key, key_len);
  } else {
    fill_hex_string(key, key_len);
  }

  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  if (!encrypted_key) return;

  trustedEncryptKey(__g_harness_eid, &errStatus, err_string,
                    key, encrypted_key, &enc_len);
  if (errStatus != 0 || enc_len == 0) return;

  // Decrypt: AES_decrypt line 136 executes when strlen(decrypted)>=2 after GCM decrypt
  char *decrypted_key = (char *)calloc(1024, sizeof(char));
  if (decrypted_key) {
    trustedDecryptKey(__g_harness_eid, &errStatus, err_string,
                      encrypted_key, enc_len, decrypted_key);
  }
}

// Workflow 7: DKG V2 workflow - HIGHEST PRIORITY (trustedDkgVerifyV2 is 0/10 edges)
// Targets: trustedDkgVerifyV2 (UNCOVERED), xor_decrypt_v2, hash_key paths

HARNESS_REGISTER(harness_aes_roundtrip_coverage, 10)
