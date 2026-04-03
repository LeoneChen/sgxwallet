#pragma once

static void harness_getss_short_pubkey(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Valid encrypted poly (same enclave instance → AES key matches)
  uint8_t *enc_poly = (uint8_t *)calloc(3050, 1);
  uint64_t poly_len = 0;
  if (!enc_poly) return;
  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string, enc_poly, &poly_len, 1);
  if (errStatus != 0 || poly_len == 0) return;

  // Output buffers
  uint8_t *encrypted_skey = (uint8_t *)calloc(1024, 1);
  uint64_t dec_len = 0;
  char *result_str = (char *)calloc(193, 1);
  char *s_shareG2  = (char *)calloc(320, 1);
  if (!encrypted_skey || !result_str || !s_shareG2) return;

  // pub_keyB = "ab" (2 chars < 128) → gen_session_key strnlen check fails at line 76
  char *short_pub = (char *)calloc(8, 1);
  if (!short_pub) return;
  short_pub[0] = 'a'; short_pub[1] = 'b';

  // Both V1 and V2 called sequentially: each invocation covers gen_session_key:76
  // for both GetEncryptedSecretShare and V2. Prior 50/50 split had ~50% chance of
  // missing one per run; sequential guarantees both fire every call.
  // V1: covers gen_session_key:76 + trustedGetEncryptedSecretShare line 889
  trustedGetEncryptedSecretShare(
      __g_harness_eid, &errStatus, err_string,
      enc_poly, poly_len,
      encrypted_skey, &dec_len, result_str, s_shareG2,
      short_pub, 1, 1, 1);
  errStatus = 0;
  // V2: covers gen_session_key:76 + trustedGetEncryptedSecretShareV2 line 965
  trustedGetEncryptedSecretShareV2(
      __g_harness_eid, &errStatus, err_string,
      enc_poly, poly_len,
      encrypted_skey, &dec_len, result_str, s_shareG2,
      short_pub, 1, 1, 1);
}

// session_key_recover line 123: strnlen(sshare, 193) < 192 → error path.
// All existing DkgVerify harnesses fix s_share = 192 chars to exercise the ECDH
// happy path, so line 123 has NEVER been triggered (37 hits, all ≥192 chars).
// Fix: pass s_share = 64 chars (< 192) with a valid encrypted ECDSA key so that:
//   AES_decrypt(valid_key) succeeds → skey is valid hex → session_key_recover(skey,
//   s_share_64, ...) → strnlen=64 < 192 → goto clean → return -1 → CHECK_STATUS fires.
// Covers: session_key_recover DHDkg.c:123 (score=18.5), trustedDkgVerify session_key fail.

HARNESS_REGISTER(harness_getss_short_pubkey, 150)
