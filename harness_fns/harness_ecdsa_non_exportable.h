#pragma once

static void harness_ecdsa_non_exportable(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  int is_exportable = 0;  // NON-EXPORTABLE: covers else-branch at GenerateEcdsaKey:420
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  char *pub_y = (char *)calloc(1024, sizeof(char));
  if (!encrypted_key || !pub_x || !pub_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, encrypted_key, &enc_len, pub_x, pub_y);
  if (errStatus != 0 || enc_len == 0) return;

  // GetPublicEcdsaKey: does not check exportable flag → succeeds
  char *out_x = (char *)calloc(1024, sizeof(char));
  char *out_y = (char *)calloc(1024, sizeof(char));
  if (!out_x || !out_y) return;
  errStatus = 0;
  trustedGetPublicEcdsaKey(__g_harness_eid, &errStatus, err_string,
                           encrypted_key, enc_len, out_x, out_y);

  // EcdsaSign with NON_EXPORTABLE key: type==ECDSA check passes → signs normally
  char *sig_r = (char *)calloc(1024, sizeof(char));
  char *sig_s = (char *)calloc(1024, sizeof(char));
  uint8_t sig_v = 0;
  if (!sig_r || !sig_s) return;
  errStatus = 0;
  trustedEcdsaSign(__g_harness_eid, &errStatus, err_string,
                   encrypted_key, enc_len,
                   "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef",
                   sig_r, sig_s, &sig_v, 16);

  // DecryptKey with NON_EXPORTABLE key → exportable != EXPORTABLE → "access denied" error
  char *dec_key = (char *)calloc(1024, sizeof(char));
  if (!dec_key) return;
  errStatus = 0;
  trustedDecryptKey(__g_harness_eid, &errStatus, err_string,
                    encrypted_key, enc_len, dec_key);
}

// Generate BLS key (type=BLS), then pass its encrypted blob to trustedEcdsaSign.
// trustedEcdsaSign line 523: if (type != ECDSA) → error branch — never covered before
// because all prior EcdsaSign harnesses use ECDSA-type keys.

HARNESS_REGISTER(harness_ecdsa_non_exportable, 50)
