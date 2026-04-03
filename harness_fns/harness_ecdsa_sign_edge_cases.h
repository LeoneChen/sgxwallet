#pragma once

static void harness_ecdsa_sign_edge_cases(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Generate a valid exportable ECDSA key first
  int is_exportable = 1;
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  char *pub_y = (char *)calloc(1024, sizeof(char));
  if (!encrypted_key || !pub_x || !pub_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, encrypted_key, &enc_len, pub_x, pub_y);
  if (errStatus != 0 || enc_len == 0) return;

  char *sig_r = (char *)calloc(1024, sizeof(char));
  char *sig_s = (char *)calloc(1024, sizeof(char));
  if (!sig_r || !sig_s) return;
  uint8_t sig_v = 0;

  // Build a hash string containing non-hex chars to trigger mpz_set_str failure
  // at line 550: mpz_set_str(msgMpz, hash, 16) == -1
  char hash[65] = {0};
  size_t hash_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 64);
  // Fill with non-hex characters ('g'-'z') so base-16 parse fails
  for (size_t i = 0; i < hash_len && i < 64; i++) {
    hash[i] = (char)('g' + (g_fdp->ConsumeIntegralInRange<int>(0, 19)));
  }

  trustedEcdsaSign(__g_harness_eid, &errStatus, err_string,
                   encrypted_key, enc_len, hash, sig_r, sig_s, &sig_v, 16);
}

// ============================================================================
// New Bottleneck Harnesses (iter_20260320_053421 analysis)
// ============================================================================

// Fix for trustedCreateBlsKey/V2 loop body coverage (lines 1174/1276 UNCOVERED)
// Root cause: fill_hex_string with tiny seeds produces all-zeros at s_share[64:128]/[128:192]
//   → point_set_hex((0,0)) fails → session_key_recover returns early before loop body
// Fix: embed real pub_x/pub_y from trustedGenerateEcdsaKey at s_share positions 64-191
//   + allocate full 6145 bytes matching EDL [in, count=6145]

HARNESS_REGISTER(harness_ecdsa_sign_edge_cases, 50)
