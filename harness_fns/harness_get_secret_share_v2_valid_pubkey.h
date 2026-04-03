#pragma once

static void harness_get_secret_share_v2_valid_pubkey(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  uint8_t *encrypted_dkg_secret = (uint8_t *)calloc(3072, sizeof(uint8_t));
  uint64_t enc_len = 0;
  size_t t = g_fdp->ConsumeIntegralInRange<size_t>(1, 4);
  if (!encrypted_dkg_secret) return;
  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_dkg_secret, &enc_len, t);
  if (errStatus != 0 || enc_len == 0) return;

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

  char *pub_keyB = (char *)calloc(129, sizeof(char));
  if (!pub_keyB) return;
  strncpy(pub_keyB, pub_x, 64);
  strncpy(pub_keyB + 64, pub_y, 64);
  pub_keyB[128] = '\0';

  uint8_t *encrypted_skey = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t dec_len = 0;
  char *result_str = (char *)calloc(193, sizeof(char));
  char *s_shareG2 = (char *)calloc(320, sizeof(char));
  if (!encrypted_skey || !result_str || !s_shareG2) return;

  uint8_t n = g_fdp->ConsumeIntegralInRange<uint8_t>((uint8_t)t, 8);
  if (n < (uint8_t)t) n = (uint8_t)t;
  uint8_t ind = g_fdp->ConsumeIntegralInRange<uint8_t>(1, n > 0 ? n : 1);

  trustedGetEncryptedSecretShareV2(
      __g_harness_eid, &errStatus, err_string,
      encrypted_dkg_secret, enc_len, encrypted_skey, &dec_len,
      result_str, s_shareG2, pub_keyB, (uint8_t)t, n, ind);
}

// Fix Verification() coverage: trustedDkgVerify needs valid BN128 G2 points in
// public_shares. Pass REAL output of trustedGetPublicShares instead of random hex.
// Verification() has 154 uncovered edges (50/204) - biggest bottleneck.

HARNESS_REGISTER(harness_get_secret_share_v2_valid_pubkey, 60)
