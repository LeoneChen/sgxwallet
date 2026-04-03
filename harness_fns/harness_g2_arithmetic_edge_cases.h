#pragma once

static void harness_g2_arithmetic_edge_cases(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Use trustedGetPublicShares which exercises G2 arithmetic
  uint8_t *encrypted_dkg = (uint8_t *)calloc(3050, 1);
  uint64_t enc_len = 0;
  char *public_shares = (char *)calloc(10000, 1);
  if (!encrypted_dkg || !public_shares) return;

  // Generate DKG secret with varying _t to exercise different poly sizes
  unsigned _t = g_fdp->ConsumeIntegralInRange<unsigned>(2, 16);
  
  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_dkg, &enc_len, _t);
  if (errStatus != 0 || enc_len == 0) return;

  errStatus = 0;
  trustedGetPublicShares(__g_harness_eid, &errStatus, err_string,
                         encrypted_dkg, enc_len, public_shares, _t);
}

// Covers xor_decrypt error path (DHDkg.c:291, secure_enclave.c:1193):
// Provides valid encryptedPrivateKey + s_shares where positions 0-63 contain
// non-hex chars. session_key_recover succeeds (point_set_hex silently ignores
// invalid coords, so common_key = "00..0"), then xor_decrypt fails at
// hex2carray(cypher) because encr_sshare is non-hex.

HARNESS_REGISTER(harness_g2_arithmetic_edge_cases, 50)
