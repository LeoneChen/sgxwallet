#pragma once

static void harness_create_bls_key_v2_xor_fail(void) {
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

  char *secret_shares = (char *)calloc(6145, 1);
  uint8_t *encr_bls_key = (uint8_t *)calloc(1024, 1);
  uint64_t enc_bls_key_len = 0;
  if (!secret_shares || !encr_bls_key) return;

  for (int i = 0; i < 64; i++)
    secret_shares[i] = 'g' + (i % 20);  // non-hex, non-null
  for (int i = 64; i < 192; i++)
    secret_shares[i] = '0' + (i % 10);  // non-null filler

  errStatus = 0;
  trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string,
                        secret_shares, encrypted_key, enc_len,
                        encr_bls_key, &enc_bls_key_len);
}

// Covers signature_sign line 112 (Signature.c):
// if (mpz_sizeinbase(message, 2) > mpz_sizeinbase(curve->n, 2)) → fires when
// hash > secp256k1 n (256 bits). A 65-char hex string has MSB set → 260 bits.
// secp256k1 n ≈ 2^256, so mpz_sizeinbase(message,2) = 260 > 256 → line 112.

HARNESS_REGISTER(harness_create_bls_key_v2_xor_fail, 15)
