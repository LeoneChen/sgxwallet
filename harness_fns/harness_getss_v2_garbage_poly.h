#pragma once

static void harness_getss_v2_garbage_poly(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  uint8_t *garbage_poly = (uint8_t *)calloc(3050, 1);
  if (!garbage_poly) return;
  if (g_fdp->remaining_bytes() >= 3050)
    g_fdp->ConsumeData(garbage_poly, 3050);

  uint8_t *enc_skey = (uint8_t *)calloc(1024, 1);
  uint64_t skey_enc_len = 0;
  char *result_str = (char *)calloc(193, 1);
  char *s_shareG2 = (char *)calloc(320, 1);
  if (!enc_skey || !result_str || !s_shareG2) return;

  // 128 hex chars — any content works; gen_session_key doesn't validate the EC point.
  char pub_keyB[129];
  memset(pub_keyB, 'a', 128);
  pub_keyB[128] = '\0';

  trustedGetEncryptedSecretShareV2(
      __g_harness_eid, &errStatus, err_string,
      garbage_poly, 3050, enc_skey, &skey_enc_len,
      result_str, s_shareG2, pub_keyB, 1, 1, 1);
}

// trustedCreateBlsKeyV2 line 1276 (for-loop body) — NEVER covered.
// Root cause: all V2 roundtrip harnesses depend on trustedGetEncryptedSecretShareV2
// succeeding, which always fails at trustedSetEncryptedDkgPoly (mystery, see analysis).
// Bypass: generate a valid AES-encrypted ECDSA key via trustedGenerateEcdsaKey, use it as
// encryptedPrivateKey directly. AES_decrypt at line 1268 now SUCCEEDS.
// secretShares = 192 hex 'a' chars → numShares=1 → loop body at line 1276 executes.
// session_key_recover will fail (synthetic share, not a real V2 ECDH output) but the
// loop body IS covered, plus session_key_recover error branches are covered too.

HARNESS_REGISTER(harness_getss_v2_garbage_poly, 60)
