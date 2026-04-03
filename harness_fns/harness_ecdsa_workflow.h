#pragma once

static void harness_ecdsa_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Generate ECDSA key (uses curve from init, AES_key from SEK)
  int is_exportable = g_fdp->ConsumeIntegralInRange<int>(0, 1);
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  char *pub_key_x = (char *)calloc(1024, sizeof(char));
  char *pub_key_y = (char *)calloc(1024, sizeof(char));
  if (!encrypted_key || !pub_key_x || !pub_key_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, encrypted_key, &enc_len,
                          pub_key_x, pub_key_y);
  if (errStatus != 0 || enc_len == 0) return;

  // Use the generated key for a random operation
  int op = g_fdp->ConsumeIntegralInRange<int>(0, 2);
  switch (op) {
    case 0: {
      // GetPublicEcdsaKey with valid encrypted key
      char *out_x = (char *)calloc(1024, sizeof(char));
      char *out_y = (char *)calloc(1024, sizeof(char));
      if (out_x && out_y) {
        trustedGetPublicEcdsaKey(__g_harness_eid, &errStatus, err_string,
                                 encrypted_key, enc_len, out_x, out_y);
      }
      break;
    }
    case 1: {
      // EcdsaSign with valid encrypted key + fuzzed hex hash
      size_t hash_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 64);
      char *hash = (char *)calloc(hash_len + 1, sizeof(char));
      if (!hash) break;
      fill_hex_string(hash, hash_len);

      char *sig_r = (char *)calloc(1024, sizeof(char));
      char *sig_s = (char *)calloc(1024, sizeof(char));
      uint8_t *sig_v = (uint8_t *)calloc(1, sizeof(uint8_t));
      int base = g_fdp->ConsumeIntegralInRange<int>(10, 16);
      if (sig_r && sig_s && sig_v) {
        trustedEcdsaSign(__g_harness_eid, &errStatus, err_string,
                         encrypted_key, enc_len, hash, sig_r, sig_s,
                         sig_v, base);
      }
      break;
    }
    case 2: {
      // DecryptKey with valid encrypted key
      char *key = (char *)calloc(1024, sizeof(char));
      if (key) {
        trustedDecryptKey(__g_harness_eid, &errStatus, err_string,
                          encrypted_key, enc_len, key);
      }
      break;
    }
  }
}

// Workflow 3: Generate BLS key, then Sign/GetPubKey
// Targets: trustedGenerateBLSKey (29%), trustedBlsSignMessage (22%),
//          trustedGetBlsPubKey (33%)

HARNESS_REGISTER(harness_ecdsa_workflow, 8)
