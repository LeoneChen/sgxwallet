#pragma once

// Target: trustedEncryptKey with [in, count=SMALL_BUF_SIZE] const char* key
// Strategy: fill all 1024 bytes, replace \0 with 'A' → no null terminator anywhere in buffer
// Hypothesis: if enclave calls strlen(key), it reads past SMALL_BUF_SIZE into enclave heap

static void harness_encrypt_key_no_null(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Fill full SMALL_BUF_SIZE (1024) bytes, no \0
  char *key = (char *)malloc(1024);
  if (!key) return;
  auto bytes = g_fdp->ConsumeBytes<uint8_t>(1024);
  memcpy(key, bytes.data(), bytes.size());
  // Pad if fdp ran out of data
  for (size_t i = bytes.size(); i < 1024; i++)
    key[i] = 'A';
  // Replace all \0 with non-zero
  for (int i = 0; i < 1024; i++)
    if (key[i] == '\0') key[i] = 'A';

  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  if (!encrypted_key) return;

  trustedEncryptKey(__g_harness_eid, &errStatus, err_string,
                    key, encrypted_key, &enc_len);

  free(key);
  free(err_string);
  free(encrypted_key);
}

HARNESS_REGISTER(harness_encrypt_key_no_null, 5)
