#pragma once

// Target: trustedGetDecryptionShare with [in, count=320] const char* public_decryption_value
// Strategy: fill all 320 bytes with no \0
// Hypothesis: if enclave calls strlen(public_decryption_value), it reads past 320 bytes

static void harness_decryption_share_no_null(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Need a valid encrypted BLS key first
  uint8_t *ecdsa_key = (uint8_t *)calloc(1024, 1);
  uint64_t ecdsa_enc_len = 0;
  char *pub_x = (char *)calloc(1024, 1);
  char *pub_y = (char *)calloc(1024, 1);
  if (!ecdsa_key || !pub_x || !pub_y) return;

  int is_exportable = 1;
  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, ecdsa_key, &ecdsa_enc_len,
                          pub_x, pub_y);
  if (errStatus != 0 || ecdsa_enc_len == 0) return;

  // Fill all 320 bytes, no \0
  char *pdv = (char *)malloc(320);
  if (!pdv) return;
  auto bytes = g_fdp->ConsumeBytes<uint8_t>(320);
  memcpy(pdv, bytes.data(), bytes.size());
  for (size_t i = bytes.size(); i < 320; i++)
    pdv[i] = 'a';
  for (int i = 0; i < 320; i++)
    if (pdv[i] == '\0') pdv[i] = 'a';

  char *decryption_share = (char *)calloc(320, 1);
  if (!decryption_share) return;

  errStatus = 0;
  trustedGetDecryptionShare(__g_harness_eid, &errStatus, err_string,
                            ecdsa_key, pdv, ecdsa_enc_len,
                            decryption_share);

  free(pdv);
  free(err_string);
  free(ecdsa_key);
  free(pub_x);
  free(pub_y);
  free(decryption_share);
}

HARNESS_REGISTER(harness_decryption_share_no_null, 5)
