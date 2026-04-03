#pragma once

static void harness_dkg_verify_with_real_shares(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Generate DKG polynomial (t=1..3 for speed)
  uint8_t *encrypted_dkg_secret = (uint8_t *)calloc(3072, sizeof(uint8_t));
  uint64_t enc_len = 0;
  size_t t = g_fdp->ConsumeIntegralInRange<size_t>(1, 3);
  if (!encrypted_dkg_secret) return;
  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_dkg_secret, &enc_len, t);
  if (errStatus != 0 || enc_len == 0) return;

  // Get REAL public shares (valid BN128 G2 points in the correct format)
  char *public_shares = (char *)calloc(10000, sizeof(char));
  if (!public_shares) return;
  trustedGetPublicShares(__g_harness_eid, &errStatus, err_string,
                         encrypted_dkg_secret, enc_len, public_shares,
                         (unsigned)t);
  if (errStatus != 0 || public_shares[0] == '\0') return;

  // Generate ECDSA key for the verifier's private key (used to decrypt s_share)
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

  // Fuzzed s_share (192 hex chars = 3 x 64-char fields)
  char *s_share = (char *)calloc(193, sizeof(char));
  if (!s_share) return;
  fill_hex_string(s_share, 192);

  int _ind = g_fdp->ConsumeIntegralInRange<int>(1, 16);
  int *result = (int *)calloc(1, sizeof(int));
  if (!result) return;

  if (g_fdp->ConsumeProbability<double>() < 0.5) {
    trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                     public_shares, s_share, ecdsa_key, ecdsa_enc_len,
                     (unsigned)t, _ind, result);
  } else {
    trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string,
                       public_shares, s_share, ecdsa_key, ecdsa_enc_len,
                       (unsigned)t, _ind, result);
  }
}

// trustedDecryptKey non-exportable path (lines 634-641 in secure_enclave.c).
// Generate ECDSA key with is_exportable=0, then trustedDecryptKey erases content
// and returns error -11. Previously missed because all test keys used is_exportable=1.

HARNESS_REGISTER(harness_dkg_verify_with_real_shares, 20)
