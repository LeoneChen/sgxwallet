#pragma once

static void harness_dkg_poly_multi_t(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  uint8_t *encrypted_dkg_secret = (uint8_t *)calloc(3072, sizeof(uint8_t));
  uint64_t enc_len = 0;
  // Force t >= 2 to ensure gen_dkg_poly for loop runs multiple iterations
  size_t t = g_fdp->ConsumeIntegralInRange<size_t>(2, 4);
  if (!encrypted_dkg_secret) return;

  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_dkg_secret, &enc_len, t);
  if (errStatus != 0 || enc_len == 0) return;

  // Also call GetPublicShares to exercise SplitStringToFr with multi-coeff poly
  char *public_shares = (char *)calloc(10000, sizeof(char));
  if (public_shares) {
    trustedGetPublicShares(__g_harness_eid, &errStatus, err_string,
                           encrypted_dkg_secret, enc_len, public_shares,
                           (unsigned)t);
  }
}

// Standalone: Call trustedGenDkgSecret then trustedDecryptDkgSecret
// Covers the decrypt path which is 0/5 edges.

HARNESS_REGISTER(harness_dkg_poly_multi_t, 80)
