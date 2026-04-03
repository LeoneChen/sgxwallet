#pragma once

static void harness_create_bls_key_with_real_sshare(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Generate ECDSA key A (pub_x/pub_y go into s_share[64:192] as valid secp256k1 point)
  int is_exportable_a = 1;
  uint8_t *ecdsa_key_a = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t ecdsa_enc_len_a = 0;
  char *pub_x_a = (char *)calloc(1024, sizeof(char));
  char *pub_y_a = (char *)calloc(1024, sizeof(char));
  if (!ecdsa_key_a || !pub_x_a || !pub_y_a) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable_a, ecdsa_key_a, &ecdsa_enc_len_a,
                          pub_x_a, pub_y_a);
  if (errStatus != 0 || ecdsa_enc_len_a == 0) return;

  // Generate ECDSA key B (its private key decrypted inside enclave for session_key_recover)
  int is_exportable_b = 1;
  uint8_t *ecdsa_key_b = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t ecdsa_enc_len_b = 0;
  char *pub_x_b = (char *)calloc(1024, sizeof(char));
  char *pub_y_b = (char *)calloc(1024, sizeof(char));
  if (!ecdsa_key_b || !pub_x_b || !pub_y_b) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable_b, ecdsa_key_b, &ecdsa_enc_len_b,
                          pub_x_b, pub_y_b);
  if (errStatus != 0 || ecdsa_enc_len_b == 0) return;

  // Build s_shares with real pub_x_a/pub_y_a at positions 64-191
  // EDL specifies [in, count=6145] so bridge reads exactly 6145 bytes from host buffer
  char *s_shares = (char *)calloc(6145, sizeof(char));
  if (!s_shares) return;

  // pos 0-63: encr_sshare placeholder (deterministic hex, no g_fdp consumption)
  static const char hex_pat[] = "0123456789abcdef";
  for (int i = 0; i < 64; i++) s_shares[i] = hex_pat[i % 16];
  // pos 64-127: real pub_x_a (valid secp256k1 x coord, 64 hex chars)
  strncpy(s_shares + 64, pub_x_a, 64);
  // pos 128-191: real pub_y_a (valid secp256k1 y coord, 64 hex chars)
  strncpy(s_shares + 128, pub_y_a, 64);
  // pos 192+: zero (from calloc) → s_shares[192]='\0' → loop iterates exactly once

  uint8_t *encr_bls_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_bls_key_len = 0;
  if (!encr_bls_key) return;

  // key_b's encrypted private key is used inside enclave for session_key_recover
  // key_a's public coords are embedded in s_share for point_multiplication
  if (g_fdp->remaining_bytes() == 0 || g_fdp->ConsumeProbability<double>() < 0.5) {
    trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string,
                        s_shares, ecdsa_key_b, ecdsa_enc_len_b,
                        encr_bls_key, &enc_bls_key_len);
  } else {
    trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string,
                          s_shares, ecdsa_key_b, ecdsa_enc_len_b,
                          encr_bls_key, &enc_bls_key_len);
  }
}

// Fix for trustedBlsSignMessage deeper coverage (2/9 edges, lines 723/738 UNCOVERED)
// Root cause: fill_hex_string with tiny seeds → all-zero hashX/hashY
//   (mpz_set_str may accept zeros but point_multiplication on (0,0) fails)
// Fix: use fixed known-good 64-char hex strings, no g_fdp consumption

HARNESS_REGISTER(harness_create_bls_key_with_real_sshare, 30)
