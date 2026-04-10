#pragma once

static void harness_null_paths_batch2(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Shared dummy non-NULL buffers sized for their largest use
  uint8_t *buf_1024 = (uint8_t *)calloc(1024, 1); // SMALL/TINY_BUF_SIZE [in] params
  uint8_t *buf_3050 = (uint8_t *)calloc(3050, 1); // encrypted_dkg_secret [in,count=3050]
  char    *buf_6145 = (char *)calloc(6145, 1);    // s_shares [in,count=6145]
  char    *dummy_str = (char *)calloc(64, 1);     // [in,string] params
  if (!buf_1024 || !buf_3050 || !buf_6145 || !dummy_str) return;
  dummy_str[0] = 'x'; // non-empty so [in,string] wrapper doesn't get strlen(NULL)

  uint64_t dummy_len = 0;
  uint64_t dummy_out_len = 0;
  int dummy_result = 0;

  int op = g_fdp->ConsumeIntegralInRange<int>(0, 17);
  switch (op) {
    case 0:
      // trustedGenDkgSecret: NULL encrypted_dkg_secret -> CHECK_STATE line 752
      trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                          NULL, &dummy_out_len, 1);
      break;
    case 1:
      // trustedDecryptDkgSecret: NULL encrypted_dkg_secret -> line 797
      trustedDecryptDkgSecret(__g_harness_eid, &errStatus, err_string,
                              NULL, dummy_len, buf_1024);
      break;
    case 2:
      // trustedDecryptDkgSecret: NULL decrypted_dkg_secret -> line 798
      trustedDecryptDkgSecret(__g_harness_eid, &errStatus, err_string,
                              buf_3050, dummy_len, NULL);
      break;
    case 3:
      // trustedGetPublicShares: NULL public_shares -> line 1005
      trustedGetPublicShares(__g_harness_eid, &errStatus, err_string,
                             buf_3050, dummy_len, NULL, 1);
      break;
    case 4: {
      // trustedGetPublicShares: _t==0 -> CHECK_STATE(_t > 0) line 1006
      char *pub_buf = (char *)calloc(10000, 1);
      if (!pub_buf) break;
      trustedGetPublicShares(__g_harness_eid, &errStatus, err_string,
                             buf_3050, dummy_len, pub_buf, 0);
      break;
    }
    case 5:
      // trustedDkgVerify: NULL public_shares -> line 1034
      trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                       NULL, dummy_str, buf_1024, dummy_len, 1, 0,
                       &dummy_result);
      break;
    case 6:
      // trustedDkgVerify: NULL s_share -> line 1035
      trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                       dummy_str, NULL, buf_1024, dummy_len, 1, 0,
                       &dummy_result);
      break;
    case 7:
      // trustedDkgVerify: NULL encryptedPrivateKey -> line 1036
      trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                       dummy_str, dummy_str, NULL, dummy_len, 1, 0,
                       &dummy_result);
      break;
    case 8:
      // trustedDkgVerifyV2: NULL publicShares -> line 1086
      trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string,
                         NULL, dummy_str, buf_1024, dummy_len, 1, 0,
                         &dummy_result);
      break;
    case 9:
      // trustedDkgVerifyV2: NULL secretShare -> line 1087
      trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string,
                         dummy_str, NULL, buf_1024, dummy_len, 1, 0,
                         &dummy_result);
      break;
    case 10:
      // trustedDkgVerifyV2: NULL encryptedPrivateKey -> line 1088
      trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string,
                         dummy_str, dummy_str, NULL, dummy_len, 1, 0,
                         &dummy_result);
      break;
    case 11:
      // trustedCreateBlsKey: NULL s_shares -> line 1145
      trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string,
                          NULL, buf_1024, dummy_len, buf_1024, &dummy_out_len);
      break;
    case 12:
      // trustedCreateBlsKey: NULL encryptedPrivateKey -> line 1146
      trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string,
                          buf_6145, NULL, dummy_len, buf_1024, &dummy_out_len);
      break;
    case 13:
      // trustedCreateBlsKey: NULL encr_bls_key -> line 1147
      trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string,
                          buf_6145, buf_1024, dummy_len, NULL, &dummy_out_len);
      break;
    case 14:
      // trustedBlsSignMessage: NULL encryptedPrivateKey -> line 708
      trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                            NULL, dummy_len, dummy_str, dummy_str,
                            (char *)buf_1024);
      break;
    case 15:
      // trustedBlsSignMessage: NULL _hashX -> line 709
      trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                            buf_1024, dummy_len, NULL, dummy_str,
                            (char *)buf_1024);
      break;
    case 16:
      // trustedBlsSignMessage: NULL _hashY -> line 710
      trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                            buf_1024, dummy_len, dummy_str, NULL,
                            (char *)buf_1024);
      break;
    case 17:
      // trustedBlsSignMessage: NULL signature -> line 711
      trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                            buf_1024, dummy_len, dummy_str, dummy_str,
                            NULL);
      break;
  }
}

// Covers NULL check fail branches in:
//   trustedDkgVerify:          line 1034 (NULL public_shares, [in,string])
//                              line 1035 (NULL s_share, [in,string])
//                              line 1036 (NULL encrypted_key, [in,count=SMALL_BUF_SIZE])
//   trustedDkgVerifyV2:        line 1086 (NULL publicShares)
//                              line 1087 (NULL secretShare)

// Covers trustedGetEncryptedSecretShare error branches:
//   line 862: trustedSetEncryptedDkgPoly fails (garbage encrypted_poly, AES_decrypt fails)
//   line 889: gen_session_key fails (pub_keyB shorter than required 128 hex chars)
// Case 0: pass random garbage as encrypted_poly -> SetEncryptedDkgPoly returns error.
// Case 1: first obtain a valid encrypted_poly via trustedGenDkgSecret, then call
//         GetEncryptedSecretShare with a short pub_keyB (len=2) to trigger line 889.

HARNESS_REGISTER(harness_null_paths_batch2, 50)
