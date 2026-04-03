#pragma once

static void harness_dkg_verify_workflow(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Generate ECDSA key
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

  // Fuzzed public_shares and s_share (hex strings)
  size_t ps_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 512);
  char *public_shares = (char *)calloc(ps_len + 1, sizeof(char));
  if (!public_shares) return;
  fill_hex_string(public_shares, ps_len);

  size_t ss_len = g_fdp->ConsumeIntegralInRange<size_t>(64, 192);
  char *s_share = (char *)calloc(ss_len + 1, sizeof(char));
  if (!s_share) return;
  fill_hex_string(s_share, ss_len);

  unsigned _t = g_fdp->ConsumeIntegralInRange<unsigned>(1, 16);
  int _ind = g_fdp->ConsumeIntegralInRange<int>(1, 16);
  int *result = (int *)calloc(1, sizeof(int));
  if (!result) return;

  if (g_fdp->ConsumeProbability<double>() < 0.5) {
    trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                     public_shares, s_share, ecdsa_key, ecdsa_enc_len,
                     _t, _ind, result);
  } else {
    trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string,
                       public_shares, s_share, ecdsa_key, ecdsa_enc_len,
                       _t, _ind, result);
  }
}

// Workflow 6: Encrypt key then decrypt it
// Targets: trustedEncryptKey (25%), trustedDecryptKey (22%)

HARNESS_REGISTER(harness_dkg_verify_workflow, 15)
