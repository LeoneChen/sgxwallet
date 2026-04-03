#pragma once

static void harness_create_bls_key_xor_fail(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  uint8_t *encrypted_key = (uint8_t *)calloc(1024, 1);
  uint64_t enc_len = 0;
  char *pub_x = (char *)calloc(1024, 1);
  char *pub_y = (char *)calloc(1024, 1);
  if (!encrypted_key || !pub_x || !pub_y) return;

  int is_exportable = 0;
  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, encrypted_key, &enc_len,
                          pub_x, pub_y);
  if (errStatus != 0 || enc_len == 0) return;

  // One 192-char block: positions 0-63 = encr_sshare (non-hex → hex2carray fails),
  // positions 64-191 = pb_keyB_x/y filler (point_set_hex silently ignores invalid).
  char *s_shares = (char *)calloc(6145, 1);
  uint8_t *encr_bls_key = (uint8_t *)calloc(1024, 1);
  uint64_t enc_bls_key_len = 0;
  if (!s_shares || !encr_bls_key) return;

  for (int i = 0; i < 64; i++)
    s_shares[i] = 'g' + (i % 20);   // non-hex, non-null
  for (int i = 64; i < 192; i++)
    s_shares[i] = '0' + (i % 10);   // non-null filler

  errStatus = 0;
  trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string,
                      s_shares, encrypted_key, enc_len,
                      encr_bls_key, &enc_bls_key_len);
}

// Covers xor_decrypt_v2 error path (DHDkg.c:330, secure_enclave.c:1302):
// Same strategy for the V2 path: session_key_recover → hash_key succeed
// (commonKey is all-zero hex from point_set_hex failure, valid for hex2carray),
// then xor_decrypt_v2 fails at hex2carray(cypher) with non-hex encr_sshare.

HARNESS_REGISTER(harness_create_bls_key_xor_fail, 20)
