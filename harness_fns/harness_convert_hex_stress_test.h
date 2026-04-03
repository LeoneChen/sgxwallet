#pragma once

static void harness_convert_hex_stress_test(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  uint8_t *encrypted_key = (uint8_t *)calloc(1024, 1);
  uint64_t enc_len = 0;
  if (!encrypted_key) return;

  trustedEncryptKey(__g_harness_eid, &errStatus, err_string,
                    "fedcba9876543210", encrypted_key, &enc_len);
  if (errStatus != 0) return;

  char *s_share = (char *)calloc(128, 1);
  int *result = (int *)calloc(1, sizeof(int));
  if (!s_share || !result) return;
  memset(s_share, 'f', 64);

  unsigned _t = g_fdp->ConsumeIntegralInRange<unsigned>(2, 5);
  size_t ps_size = 256 * _t + 1;
  char *public_shares = (char *)calloc(ps_size, 1);
  if (!public_shares) return;

  int op = g_fdp->ConsumeIntegralInRange<int>(0, 3);
  
  if (op == 0) {
    // Maximum value (all 'f's)
    memset(public_shares, 'f', ps_size - 1);
  } else if (op == 1) {
    // Leading zeros with varying counts
    size_t zero_count = g_fdp->ConsumeIntegralInRange<size_t>(0, ps_size/2);
    memset(public_shares, '0', zero_count);
    for (size_t i = zero_count; i < ps_size - 1; i++) {
      public_shares[i] = g_fdp->ConsumeIntegralInRange<char>('1', 'f');
    }
  } else if (op == 2) {
    // Alternating pattern to stress conversion
    for (size_t i = 0; i < ps_size - 1; i++) {
      public_shares[i] = (i % 2) ? 'f' : '0';
    }
  } else {
    // Gradient pattern
    for (size_t i = 0; i < ps_size - 1; i++) {
      uint8_t val = (i * 15) / (ps_size - 1);
      public_shares[i] = (val < 10) ? ('0' + val) : ('a' + val - 10);
    }
  }

  errStatus = 0;
  trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                   public_shares, s_share, encrypted_key, enc_len,
                   _t, 1, result);
}

// Covers libff G2 operations with edge case coordinates:
// Targets various libff::alt_bn128_G2 functions with low coverage
// - G2::dbl (2/16 = 12.5%)
// - G2::to_affine_coordinates (5/25 = 20%)
// - G2::operator== (12/52 = 23.1%)

HARNESS_REGISTER(harness_convert_hex_stress_test, 20)
