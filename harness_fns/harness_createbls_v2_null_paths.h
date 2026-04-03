#pragma once

static void harness_createbls_v2_null_paths(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  uint8_t *dummy_key     = (uint8_t *)calloc(1024, 1);
  uint8_t *dummy_encrkey = (uint8_t *)calloc(1024, 1);
  uint64_t dummy_keylen  = 0;
  uint64_t dummy_enclen  = 0;
  if (!dummy_key || !dummy_encrkey) return;

  // Both cases in one invocation — no FDP randomness needed.
  // NULL s_shares ([in, string]): NULL propagates through SDK → CHECK_STATE line 1248.
  trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string,
                        NULL, dummy_key, dummy_keylen,
                        dummy_encrkey, &dummy_enclen);
  errStatus = 0;
  // NULL encrypted_key ([in, count=enc_len]): SDK may reject; keep for minimal diversity.
  trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string,
                        (const char *)dummy_key, NULL, dummy_keylen,
                        dummy_encrkey, &dummy_enclen);
}

// trustedCreateBlsKeyV2 loop back-edge (line 1276): numShares=2 → loop runs twice.
// Root cause of uncovered back-edge: all existing harnesses pass ≤1 share block
// (harness_v2_dkg_create_bls_roundtrip: result_str=192 → numShares=1;
//  harness_create_bls_key_v2_workflow: ConsumeIntegralInRange(1,16) → often 1 with short seeds).
// Fix: always pass 2×192=384 hex chars → numShares=2 → 2 loop iterations.
// AES_decrypt guaranteed OK: ecdsa_key from same-iteration trustedGenerateEcdsaKey.
// session_key_recover OK: pub_x/pub_y from same GenerateEcdsaKey → valid secp256k1 point,
//   secp256k1_ec_pubkey_parse succeeds; random hex at [0..63] is valid cipher input.
// xor_decrypt_v2 OK: hex cipher at [0..63] valid; hash_key output is 64-byte key.
// mpz_set_str OK: carray2Hex(xor output) always produces valid hex.

HARNESS_REGISTER(harness_createbls_v2_null_paths, 80)
