#pragma once

static void harness_verification_edge_cases(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Need encrypted_key for trustedDkgVerify
  uint8_t *verifier_key = (uint8_t *)calloc(1024, 1);
  if (!verifier_key) return;
  
  // Generate valid encrypted key first
  uint64_t verifier_enc_len = 0;
  trustedEncryptKey(__g_harness_eid, &errStatus, err_string,
                    "0123456789abcdef", verifier_key, &verifier_enc_len);
  if (errStatus != 0) return;

  char *dummy_s_share = (char *)calloc(256, 1);
  int *verify_result = (int *)calloc(1, sizeof(int));
  if (!dummy_s_share || !verify_result) return;
  memset(dummy_s_share, 'a', 64);  // dummy secret share

  int op = g_fdp->ConsumeIntegralInRange<int>(0, 2);
  unsigned _t = g_fdp->ConsumeIntegralInRange<unsigned>(1, 4);
  
  if (op == 0) {
    // Invalid hex chars in public_shares -> ConvertHexToDec returns ""
    size_t ps_size = 256 * _t + 1;
    char *public_shares = (char *)calloc(ps_size, 1);
    if (!public_shares) return;
    
    // Fill with non-hex characters (g, h, z, etc.)
    for (size_t i = 0; i < ps_size - 1; i++) {
      public_shares[i] = g_fdp->ConsumeIntegralInRange<char>('g', 'z');
    }
    
    errStatus = 0;
    trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                     public_shares, dummy_s_share, verifier_key, verifier_enc_len,
                     _t, 1, verify_result);
  } else if (op == 1) {
    // Valid hex but invalid G2 coordinates -> isG2 fails
    size_t ps_size = 256 * _t + 1;
    char *public_shares = (char *)calloc(ps_size, 1);
    if (!public_shares) return;
    
    // Fill with all zeros (valid hex but invalid G2 point)
    memset(public_shares, '0', ps_size - 1);
    
    errStatus = 0;
    trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                     public_shares, dummy_s_share, verifier_key, verifier_enc_len,
                     _t, 1, verify_result);
  } else {
    // Truncated public_shares (shorter than expected)
    size_t short_size = 128;  // Less than 256 * _t
    char *public_shares = (char *)calloc(short_size + 1, 1);
    if (!public_shares) return;
    
    memset(public_shares, 'a', short_size);
    
    errStatus = 0;
    trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                     public_shares, dummy_s_share, verifier_key, verifier_enc_len,
                     _t, 1, verify_result);
  }
}

// Covers calc_bls_public_key error paths:
//   line 583: mpz_set_str fails (invalid hex in skey_hex)
// trustedEncryptKey("G"×64) → enc_key → trustedGetBlsPubKey → AES_decrypt →
// skey_hex = "GGG...G" (64 non-hex chars) → mpz_set_str(..., 16) == -1 →
// calc_bls_public_key line 584 covered.
// trustedEncryptKey succeeds: AES encrypts any string; strnlen("G"×64,128)=64≠128
// so the length-check error path at secure_enclave.c:678 is NOT triggered.

HARNESS_REGISTER(harness_verification_edge_cases, 30)
