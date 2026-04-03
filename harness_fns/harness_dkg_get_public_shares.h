#pragma once

static void harness_dkg_get_public_shares(void) {
  init_enclave_and_sek();
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

  char *public_shares = (char *)calloc(10000, sizeof(char));
  if (!public_shares) return;

  trustedGetPublicShares(__g_harness_eid, &errStatus, err_string,
                         encrypted_dkg_secret, enc_len, public_shares,
                         (unsigned)t);
}

// calc_public_shares line 436: poly.size() != _t check.
// GenDkgSecret(t=1) → GetPublicShares(_t=3):
//   AES_decrypt → poly has 1 coeff (from t=1) → SplitStringToFr → 1 element ≠ _t=3 →
//   line 436 (CHECK_STATE) covered.

HARNESS_REGISTER(harness_dkg_get_public_shares, 200)
