#pragma once

static void harness_dkgverify_v2_null_all(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  uint8_t *buf = (uint8_t *)calloc(1024, 1);
  char *str = (char *)calloc(64, 1);
  if (!buf || !str) return;
  str[0] = 'x';
  int result = 0;
  uint64_t dummy_len = 0;

  // --- trustedDkgVerifyV2 NULL paths ---
  // NULL publicShares → CHECK_STATE line 1086
  trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string,
                     NULL, str, buf, dummy_len, 1, 1, &result);
  errStatus = 0;
  // NULL secretShare → CHECK_STATE line 1087
  trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string,
                     str, NULL, buf, dummy_len, 1, 1, &result);
  errStatus = 0;
  // NULL encrypted_key → CHECK_STATE line 1088
  trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string,
                     str, str, NULL, dummy_len, 1, 1, &result);
  errStatus = 0;

  // --- trustedDkgVerify NULL paths (bonus: covers lines 1034-1036) ---
  // NULL public_shares → CHECK_STATE line 1034
  trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                   NULL, str, buf, dummy_len, 1, 1, &result);
  errStatus = 0;
  // NULL s_share → CHECK_STATE line 1035
  trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                   str, NULL, buf, dummy_len, 1, 1, &result);
  errStatus = 0;
  // NULL encrypted_key → CHECK_STATE line 1036
  trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                   str, str, NULL, dummy_len, 1, 1, &result);
}

// harness_error_path_coverage converted to sequential: all 20 error cases per invocation.
// Previously FDP-switched (op in [0,19]): expected hits/case = 40/3357*90/20 < 0.1 per
// run → essentially never fired. Sequential: each call deterministically covers all 20.

HARNESS_REGISTER(harness_dkgverify_v2_null_all, 100)
