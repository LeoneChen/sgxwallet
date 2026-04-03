#pragma once

static void harness_dkg_verify_v2_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Generate ECDSA key (provides valid encrypted private key)
  int is_exportable = 1;
  uint8_t *ecdsa_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t ecdsa_enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  char *pub_y = (char *)calloc(1024, sizeof(char));
  if (!ecdsa_key || !pub_x || !pub_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, ecdsa_key, &ecdsa_enc_len,
                          pub_x, pub_y);
  if (errStatus != 0 || ecdsa_enc_len == 0) return;

  // Fuzzed public_shares and s_share - use mixed hex to trigger error paths
  size_t ps_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 512);
  char *public_shares = (char *)calloc(ps_len + 1, sizeof(char));
  if (!public_shares) return;
  if (g_fdp->ConsumeProbability<double>() < 0.7) {
    fill_hex_string(public_shares, ps_len);
  } else {
    fill_mixed_hex_string(public_shares, ps_len);
  }

  // s_share: must be exactly 192 chars (64 encr_sshare + 64 pubkey_x + 64 pubkey_y)
  // session_key_recover() requires strnlen(sshare, 193) >= 192; shorter strings skip
  // the ECDH path entirely, so fix at 192 to always exercise it.
  size_t ss_len = 192;
  char *s_share = (char *)calloc(ss_len + 1, sizeof(char));
  if (!s_share) return;
  fill_hex_string(s_share, ss_len);

  unsigned _t = g_fdp->ConsumeIntegralInRange<unsigned>(1, 16);
  int _ind = g_fdp->ConsumeIntegralInRange<int>(1, 16);
  int *result = (int *)calloc(1, sizeof(int));
  if (!result) return;

  // ALWAYS call V2 - this is the uncovered function
  trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string,
                     public_shares, s_share, ecdsa_key, ecdsa_enc_len,
                     _t, _ind, result);
}

// Workflow 8: CreateBlsKeyV2 dedicated - V2 path barely covered (2/19 edges)
// Targets: trustedCreateBlsKeyV2, hash_key, xor_decrypt_v2

HARNESS_REGISTER(harness_dkg_verify_v2_workflow, 80)
