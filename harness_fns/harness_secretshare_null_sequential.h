#pragma once

static void harness_secretshare_null_sequential(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  uint8_t *dummy_poly = (uint8_t *)calloc(100, 1);
  uint8_t *dummy_skey = (uint8_t *)calloc(1024, 1);
  uint64_t dummy_dec_len = 0;
  char *dummy_result = (char *)calloc(193, 1);
  char *dummy_s_shareG2 = (char *)calloc(320, 1);
  char *dummy_pub_keyB = (char *)calloc(129, 1);
  if (!dummy_poly || !dummy_skey || !dummy_result || !dummy_s_shareG2 ||
      !dummy_pub_keyB)
    return;
  memset(dummy_pub_keyB, 'a', 128);

  // Case 0: V1: NULL encrypted_skey → CHECK_STATE line 853 ([out] param; SDK allocs)
  trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string,
                                 dummy_poly, 50, NULL, &dummy_dec_len,
                                 dummy_result, dummy_s_shareG2,
                                 dummy_pub_keyB, 1, 1, 1);
  errStatus = 0;
  // Case 1: V1: NULL result_str → CHECK_STATE line 854
  trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string,
                                 dummy_poly, 50, dummy_skey, &dummy_dec_len,
                                 NULL, dummy_s_shareG2, dummy_pub_keyB, 1, 1, 1);
  errStatus = 0;
  // Case 2: V1: NULL s_shareG2 → CHECK_STATE line 855
  trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string,
                                 dummy_poly, 50, dummy_skey, &dummy_dec_len,
                                 dummy_result, NULL, dummy_pub_keyB, 1, 1, 1);
  errStatus = 0;
  // Case 3: V1: NULL pub_keyB → CHECK_STATE line 856
  trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string,
                                 dummy_poly, 50, dummy_skey, &dummy_dec_len,
                                 dummy_result, dummy_s_shareG2, NULL, 1, 1, 1);
  errStatus = 0;
  // Case 4: V1: zero poly bytes → SetEncryptedDkgPoly fail → line 862
  trustedGetEncryptedSecretShare(__g_harness_eid, &errStatus, err_string,
                                 dummy_poly, 50, dummy_skey,
                                 &dummy_dec_len, dummy_result,
                                 dummy_s_shareG2, dummy_pub_keyB, 1, 1, 1);
  errStatus = 0;
  // Case 5: V2: NULL encryptedSkey → CHECK_STATE line 928
  trustedGetEncryptedSecretShareV2(
      __g_harness_eid, &errStatus, err_string, dummy_poly, 50, NULL,
      &dummy_dec_len, dummy_result, dummy_s_shareG2, dummy_pub_keyB, 1, 1, 1);
  errStatus = 0;
  // Case 6: V2: NULL resultStr → CHECK_STATE line 929
  trustedGetEncryptedSecretShareV2(
      __g_harness_eid, &errStatus, err_string, dummy_poly, 50, dummy_skey,
      &dummy_dec_len, NULL, dummy_s_shareG2, dummy_pub_keyB, 1, 1, 1);
  errStatus = 0;
  // Case 7: V2: NULL secretShareG2 → CHECK_STATE line 930
  trustedGetEncryptedSecretShareV2(
      __g_harness_eid, &errStatus, err_string, dummy_poly, 50, dummy_skey,
      &dummy_dec_len, dummy_result, NULL, dummy_pub_keyB, 1, 1, 1);
  errStatus = 0;
  // Case 8: V2: NULL pubKeyB → CHECK_STATE line 931
  trustedGetEncryptedSecretShareV2(
      __g_harness_eid, &errStatus, err_string, dummy_poly, 50, dummy_skey,
      &dummy_dec_len, dummy_result, dummy_s_shareG2, NULL, 1, 1, 1);
  errStatus = 0;
  // Case 9: V2: zero poly bytes → SetEncryptedDkgPoly fail → line 937
  trustedGetEncryptedSecretShareV2(
      __g_harness_eid, &errStatus, err_string, dummy_poly, 50, dummy_skey,
      &dummy_dec_len, dummy_result, dummy_s_shareG2, dummy_pub_keyB, 1, 1, 1);
}

HARNESS_REGISTER(harness_secretshare_null_sequential, 300)
