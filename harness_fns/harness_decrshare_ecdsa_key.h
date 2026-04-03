#pragma once

static void harness_decrshare_ecdsa_key(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  int is_exportable = 1;
  uint8_t *ecdsa_key = (uint8_t *)calloc(1024, 1);
  uint64_t ecdsa_enc_len = 0;
  char *pub_x = (char *)calloc(1024, 1);
  char *pub_y = (char *)calloc(1024, 1);
  if (!ecdsa_key || !pub_x || !pub_y) return;
  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, ecdsa_key, &ecdsa_enc_len, pub_x, pub_y);
  if (errStatus != 0 || ecdsa_enc_len == 0) return;

  char *g2_gen = (char *)calloc(320, sizeof(char));
  char *dec_share = (char *)calloc(320, sizeof(char));
  if (!g2_gen || !dec_share) return;
  static const char G2_GEN_DEC[] =
      "10857046999023057135944570762232829481370756359578518086990519993285655852781"
      ":11559732032986387107991004021392285783925812861821192530917403151452391805634"
      ":8495653923123431417604973247489272438418190587263600148770280649306958101930"
      ":4082367875863433681332203403145435568316851327593401208105741076214120093531";
  strncpy(g2_gen, G2_GEN_DEC, 319);

  errStatus = 0;
  trustedGetDecryptionShare(__g_harness_eid, &errStatus, err_string,
                            ecdsa_key, g2_gen, ecdsa_enc_len,
                            dec_share);
}

// trustedDkgVerifyV2 lines 1086-1088: CHECK_STATE fails for NULL publicShares, secretShare,
// encrypted_key. harness_dkgverify_null_paths (weight=25, 8 cases) gives ~0.09 expected hits
// per V2-null path per 90-iter run → essentially never fires. Fix: dedicated harness that
// tests all 3 V2 NULL paths in ONE invocation (no op randomness). Each call covers all 3.
// Also covers trustedDkgVerify lines 1034-1036 (V1 NULL paths) in the same invocation.

HARNESS_REGISTER(harness_decrshare_ecdsa_key, 400)
