#pragma once

static void harness_split_string_to_fr_edge_cases(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Need encrypted_key for trustedCreateBlsKey
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, 1);
  uint64_t enc_len = 0;
  if (!encrypted_key) return;

  trustedEncryptKey(__g_harness_eid, &errStatus, err_string,
                    "0123456789abcdef", encrypted_key, &enc_len);
  if (errStatus != 0) return;

  // Prepare s_shares buffer with malformed separator patterns
  char *s_shares = (char *)calloc(6145, 1);
  uint8_t *encr_bls_key = (uint8_t *)calloc(1024, 1);
  uint64_t enc_bls_key_len = 0;
  if (!s_shares || !encr_bls_key) return;

  int op = g_fdp->ConsumeIntegralInRange<int>(0, 5);
  
  if (op == 0) {
    // Start with separator
    strcpy(s_shares, ":abc123:def456");
  } else if (op == 1) {
    // End with separator
    strcpy(s_shares, "abc123:def456:");
  } else if (op == 2) {
    // Multiple consecutive separators
    strcpy(s_shares, "abc:::def:::ghi");
  } else if (op == 3) {
    // Empty tokens between separators
    strcpy(s_shares, ":::");
  } else if (op == 4) {
    // Very long single token (no separators)
    memset(s_shares, 'f', 100);
  } else {
    // Mixed: some valid hex, some invalid, random separators
    size_t len = g_fdp->ConsumeIntegralInRange<size_t>(50, 200);
    for (size_t i = 0; i < len && i < 6140; i++) {
      if (i % 30 == 0) {
        s_shares[i] = ':';
      } else if (g_fdp->ConsumeProbability<double>() < 0.7) {
        // Valid hex
        uint8_t nib = g_fdp->ConsumeIntegral<uint8_t>() & 0xF;
        s_shares[i] = (nib < 10) ? ('0' + nib) : ('a' + nib - 10);
      } else {
        // Invalid hex (g-z)
        s_shares[i] = g_fdp->ConsumeIntegralInRange<char>('g', 'z');
      }
    }
  }

  errStatus = 0;
  trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string,
                      s_shares, encrypted_key, enc_len,
                      encr_bls_key, &enc_bls_key_len);
}

// Covers AES_decrypt short-length error path (AESUtils.c:110):
// if (length < SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE) → return -5
// SGX_AESGCM_MAC_SIZE=16, SGX_AESGCM_IV_SIZE=12 → minimum = 28 bytes.
// trustedDecryptKey passes enc_len directly to AES_decrypt without validation,
// so passing enc_len in [1,27] reliably hits line 110.

HARNESS_REGISTER(harness_split_string_to_fr_edge_cases, 25)
