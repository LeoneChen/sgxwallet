#pragma once

static void harness_gen_dkg_secret_standalone(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  uint8_t *encrypted_dkg_secret = (uint8_t *)calloc(3072, sizeof(uint8_t));
  uint64_t enc_len = 0;
  if (!encrypted_dkg_secret) return;

  size_t t = g_fdp->ConsumeIntegralInRange<size_t>(1, 4);
  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_dkg_secret, &enc_len, t);
}

// DKG poly multi-t: forces _t>=2 to cover gen_dkg_poly loop multi-iteration edges.
// Targets: gen_dkg_poly loop body (DKGUtils.cpp:240) for _t>1,
//          SplitStringToFr (DKGUtils.cpp:194) with multi-coefficient polynomial.
// With _t=1 (FDP min), gen_dkg_poly loop runs once; _t>=2 covers subsequent iterations.

HARNESS_REGISTER(harness_gen_dkg_secret_standalone, 15)
