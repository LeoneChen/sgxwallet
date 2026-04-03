#pragma once

static void harness_bls_sign_null_paths(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  uint8_t *valid_buf = (uint8_t *)calloc(1024, 1);
  char    *dummy_str = (char *)calloc(64, 1);
  char    *sig_buf   = (char *)calloc(1024, 1);
  if (!valid_buf || !dummy_str || !sig_buf) return;

  dummy_str[0] = 'x';  // non-empty string
  uint64_t dummy_len = 0;

  int op = g_fdp->ConsumeIntegralInRange<int>(0, 4);
  switch (op) {
    case 0:
      // NULL encryptedPrivateKey → CHECK_STATE line 708
      trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                            NULL, dummy_len, dummy_str, dummy_str, sig_buf);
      break;
    case 1:
      // NULL _hashX → CHECK_STATE line 709
      trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                            valid_buf, dummy_len, NULL, dummy_str, sig_buf);
      break;
    case 2:
      // NULL _hashY → CHECK_STATE line 710
      trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                            valid_buf, dummy_len, dummy_str, NULL, sig_buf);
      break;
    case 3:
      // NULL signature → CHECK_STATE line 711
      trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                            valid_buf, dummy_len, dummy_str, dummy_str, NULL);
      break;
    case 4: {
      // Short enc_len (1-27) → AES_decrypt length check fails → CHECK_STATUS line 720
      uint64_t short_len = (uint64_t)g_fdp->ConsumeIntegralInRange<uint32_t>(1, 27);
      trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                            valid_buf, short_len, dummy_str, dummy_str, sig_buf);
      break;
    }
  }
}

// trustedCreateBlsKeyV2 NULL-check paths (lines 1248-1249).
// s_shares is [in, count=6145]: NULL host ptr → SDK passes NULL into enclave
//   → CHECK_STATE(secretShares) line 1248 triggered.
// encrypted_key is [in, count=SMALL_BUF_SIZE]: same NULL propagation
//   → CHECK_STATE(encryptedPrivateKey) line 1249 triggered.
// encr_bls_key is [out, count=SMALL_BUF_SIZE]: SDK allocates unconditionally
//   → line 1250 is unreachable via NULL host ptr.
// harness_null_paths_batch2 covers CreateBlsKey V1 (lines 1145-1147) but
// NOT V2 — this dedicated harness fills that gap.

HARNESS_REGISTER(harness_bls_sign_null_paths, 15)
