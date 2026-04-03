#pragma once

static void harness_dkg_verify_v1_only(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

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

  size_t ps_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 512);
  char *public_shares = (char *)calloc(ps_len + 1, sizeof(char));
  if (!public_shares) return;
  fill_hex_string(public_shares, ps_len);

  size_t ss_len = 192;
  char *s_share = (char *)calloc(ss_len + 1, sizeof(char));
  if (!s_share) return;
  fill_hex_string(s_share, ss_len);

  unsigned _t = g_fdp->ConsumeIntegralInRange<unsigned>(1, 16);
  int _ind = g_fdp->ConsumeIntegralInRange<int>(1, 16);
  int *result = (int *)calloc(1, sizeof(int));
  if (!result) return;

  trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                   public_shares, s_share, ecdsa_key, ecdsa_enc_len,
                   _t, _ind, result);
}

// ============================================================================
// Additional Bottleneck Harnesses (DKG entry points)
// ============================================================================

// Standalone: Call trustedGenDkgSecret only (fast, no libff G2 ops)
// This is the minimal DKG entry-point to start covering DKG code paths.

HARNESS_REGISTER(harness_dkg_verify_v1_only, 25)
