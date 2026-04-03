#pragma once

static void harness_createbls_v2_loop(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Step 1: Generate ECDSA key (provides valid AES-encrypted key for CreateBlsKeyV2)
  int is_exportable = 1;
  uint8_t *ecdsa_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t ecdsa_enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  char *pub_y = (char *)calloc(1024, sizeof(char));
  if (!ecdsa_key || !pub_x || !pub_y) return;
  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, ecdsa_key, &ecdsa_enc_len, pub_x, pub_y);
  if (errStatus != 0 || ecdsa_enc_len == 0) return;

  // Step 2: s_shares with exactly 2×192=384 hex chars → numShares=2 → 2 loop iters.
  // Each 192-char block: [0..63]=hex_cipher for xor_decrypt_v2,
  //   [64..127]=actual pub_x, [128..191]=actual pub_y for session_key_recover ECDH.
  // Real secp256k1 coordinates ensure secp256k1_ec_pubkey_parse succeeds in both iters,
  // so session_key_recover → hash_key → xor_decrypt_v2 → mpz_set_str all complete,
  // covering the loop back-edge at line 1276.
  size_t pub_x_len = strnlen(pub_x, 128);
  size_t pub_y_len = strnlen(pub_y, 128);
  if (pub_x_len < 64 || pub_y_len < 64) return;
  char *s_shares = (char *)calloc(6145, sizeof(char));
  if (!s_shares) return;
  // Block 0 (chars 0..191): random cipher + valid pub coords
  fill_hex_string(s_shares, 64);
  memcpy(s_shares + 64, pub_x, 64);
  memcpy(s_shares + 128, pub_y, 64);
  // Block 1 (chars 192..383): random cipher + same valid pub coords
  fill_hex_string(s_shares + 192, 64);
  memcpy(s_shares + 256, pub_x, 64);
  memcpy(s_shares + 320, pub_y, 64);
  // s_shares[384] = '\0' (calloc-zeroed)

  // Step 3: CreateBlsKeyV2 → loop runs 2 iterations → back-edge at line 1276 covered.
  uint8_t *encr_bls_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_bls_key_len = 0;
  if (!encr_bls_key) return;

  errStatus = 0;
  trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string,
                        s_shares, ecdsa_key, ecdsa_enc_len,
                        encr_bls_key, &enc_bls_key_len);
}

// gen_session_key line 76: strnlen(pb_keyB, 128) < 128 → error path.
// harness_getss_error_paths op=1 targets this (weight 50, ~1 fire/96 iters, 50/50 op),
// but with only ~1 opportunity per run line 76 stays uncovered.
// Dedicated harness (weight 60, ~2.5 fires/96 iters, ALWAYS short pub_keyB):
//   GenDkgSecret → GetEncryptedSecretShare[V1|V2] with pub_keyB = "ab" (2 chars < 128)
//   → trustedSetEncryptedDkgPoly succeeds (valid poly) → GenerateEcdsaKey succeeds
//   → AES_decrypt succeeds → gen_session_key(skey, "ab", ...) → line 76 triggered.
// Covers: gen_session_key DHDkg.c:76, trustedGetEncryptedSecretShare line 889,
//         trustedGetEncryptedSecretShareV2 line 965 (50/50 V1/V2 split).

HARNESS_REGISTER(harness_createbls_v2_loop, 200)
