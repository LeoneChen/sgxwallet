#pragma once

static void harness_hex_conversion_edge_cases(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Use trustedDkgVerify with crafted public_shares to exercise ConvertHexToDec
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

  unsigned _t = g_fdp->ConsumeIntegralInRange<unsigned>(1, 3);
  size_t ps_size = 256 * _t + 1;
  char *public_shares = (char *)calloc(ps_size, 1);
  if (!public_shares) return;

  int op = g_fdp->ConsumeIntegralInRange<int>(0, 2);
  
  if (op == 0) {
    // All leading zeros (64 zeros per coordinate, 4 coords per share)
    for (size_t i = 0; i < ps_size - 1; i++)
      public_shares[i] = '0';
  } else if (op == 1) {
    // Mix of very large and very small hex values
    for (size_t i = 0; i < ps_size - 1; i++) {
      if ((i / 64) % 2 == 0)
        public_shares[i] = 'f';  // Max value
      else
        public_shares[i] = '0';  // Min value
    }
  } else {
    // Random valid hex with varying patterns
    for (size_t i = 0; i < ps_size - 1; i++) {
      if (g_fdp->remaining_bytes() > 0) {
        uint8_t nib = g_fdp->ConsumeIntegral<uint8_t>() & 0xF;
        public_shares[i] = (nib < 10) ? ('0' + nib) : ('a' + nib - 10);
      }
    }
  }

  errStatus = 0;
  trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                   public_shares, s_share, encrypted_key, enc_len,
                   _t, 1, result);
}

// Covers SplitStringToFr edge cases with extreme separator patterns:
// - Consecutive separators (empty tokens between)
// - String starting/ending with separator
// - Very long token sequences
// - Mixed valid/invalid hex in tokens
// Targets SplitStringToFr (DKGUtils.cpp:189, 24/75 edges coverage)

HARNESS_REGISTER(harness_hex_conversion_edge_cases, 15)
