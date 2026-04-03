#pragma once

static void harness_encrypt_decrypt_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Encrypt a fuzzed key string
  size_t key_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 64);
  char *key = (char *)calloc(1024, sizeof(char));
  if (!key) return;
  fill_hex_string(key, key_len);

  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  if (!encrypted_key) return;

  trustedEncryptKey(__g_harness_eid, &errStatus, err_string,
                    key, encrypted_key, &enc_len);
  if (errStatus != 0 || enc_len == 0) return;

  // Decrypt the encrypted key
  char *decrypted_key = (char *)calloc(1024, sizeof(char));
  if (decrypted_key) {
    trustedDecryptKey(__g_harness_eid, &errStatus, err_string,
                      encrypted_key, enc_len, decrypted_key);
  }
}

// AES roundtrip coverage: encrypt then decrypt with uppercase hex key.
// Targets: AES_decrypt line 136 (post-decrypt loop requires strlen(message)>=2),
//          char2int line 278 (uppercase A-F path), hex2carray loop body (line 315).
// Uses uppercase key so trustedDecryptKey processes uppercase chars through char2int.
// Placed in Tier 0 of registry to be reachable with 1-byte seeds.

HARNESS_REGISTER(harness_encrypt_decrypt_workflow, 40)
