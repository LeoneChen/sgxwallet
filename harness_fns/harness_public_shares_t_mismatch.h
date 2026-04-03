#pragma once

static void harness_public_shares_t_mismatch(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  uint8_t *encrypted_dkg_secret = (uint8_t *)calloc(3072, sizeof(uint8_t));
  uint64_t enc_len = 0;
  if (!encrypted_dkg_secret) return;

  // Generate DKG secret with t=1 (polynomial has 1 coefficient)
  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_dkg_secret, &enc_len, 1);
  if (errStatus != 0 || enc_len == 0) return;

  char *public_shares = (char *)calloc(10000, sizeof(char));
  if (!public_shares) return;

  // Request _t=3 → poly.size()=1 != 3 → CHECK_STATE at DKGUtils.cpp:436
  errStatus = 0;
  trustedGetPublicShares(__g_harness_eid, &errStatus, err_string,
                         encrypted_dkg_secret, enc_len, public_shares, 3);
}

HARNESS_REGISTER(harness_public_shares_t_mismatch, 30)
