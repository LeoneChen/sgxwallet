#pragma once

static void harness_dkgverify_short_sshare(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Valid ECDSA key: AES_decrypt succeeds → skey is a valid hex private key
  int is_exportable = 1;
  uint8_t *ecdsa_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t ecdsa_enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  char *pub_y = (char *)calloc(1024, sizeof(char));
  if (!ecdsa_key || !pub_x || !pub_y) return;
  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, ecdsa_key, &ecdsa_enc_len, pub_x, pub_y);
  if (errStatus != 0 || ecdsa_enc_len == 0) return;

  // public_shares: short string, doesn't matter (session_key_recover fails before Verification)
  size_t ps_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 64);
  char *public_shares = (char *)calloc(ps_len + 1, sizeof(char));
  if (!public_shares) return;
  fill_hex_string(public_shares, ps_len);

  // s_share: exactly 64 chars (< 192) → session_key_recover line 123 triggered
  char *s_share = (char *)calloc(65, sizeof(char));
  if (!s_share) return;
  fill_hex_string(s_share, 64);

  unsigned _t = g_fdp->ConsumeIntegralInRange<unsigned>(1, 8);
  int _ind = g_fdp->ConsumeIntegralInRange<int>(1, 8);
  int *result = (int *)calloc(1, sizeof(int));
  if (!result) return;

  // Always call BOTH V1 and V2: each harness invocation deterministically covers
  // session_key_recover:123 (strnlen<192 path) for both trustedDkgVerify and trustedDkgVerifyV2.
  // Prior 50/50 split had ~3.4% chance of 0 fires per run → line 123 stochastically missed.
  trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                   public_shares, s_share, ecdsa_key, ecdsa_enc_len,
                   _t, _ind, result);
  errStatus = 0;
  trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string,
                     public_shares, s_share, ecdsa_key, ecdsa_enc_len,
                     _t, _ind, result);
}

// trustedCreateBlsKeyV2 loop back-edge (line 1276): uses actual GetEncryptedSecretShareV2 output
// as BOTH share blocks (correct ECDH roundtrip) → guaranteed numShares=2 → loop runs 2 iterations.
// Strategy: gen poly(t=1) + gen ECDSA key as verifier → call GetEncryptedSecretShareV2 to get
// a real 192-char result_str (cipher[0..63] + ephemeral_pubX[64..127] + ephemeral_pubY[128..191]).
// Duplicate result_str → s_shares = result_str + result_str (384 chars → numShares=2).
// Call CreateBlsKeyV2(s_shares, verifier_key): session_key_recover(verifier_skey, result_str)
// does ECDH = verifier_skey * ephemeral_pub → same shared secret as gen_session_key in GetSS,
// so hash_key → xor_decrypt_v2 → mpz_set_str all succeed in BOTH iterations → line 1276 covered.

HARNESS_REGISTER(harness_dkgverify_short_sshare, 40)
