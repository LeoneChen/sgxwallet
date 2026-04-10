#pragma once

static void harness_v2_full_roundtrip(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Step 1: Generate DKG poly
  uint8_t *encrypted_poly = (uint8_t *)calloc(3072, sizeof(uint8_t));
  uint64_t poly_enc_len = 0;
  size_t t = g_fdp->ConsumeIntegralInRange<size_t>(1, 4);
  if (!encrypted_poly) return;

  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_poly, &poly_enc_len, t);
  if (errStatus != 0 || poly_enc_len == 0) return;

  // Step 2: GetEncryptedSecretShareV2 (generates ECDSA key internally)
  uint8_t *encrypted_skey = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t skey_enc_len = 0;
  char *result_str = (char *)calloc(193, sizeof(char));
  char *s_shareG2 = (char *)calloc(320, sizeof(char));
  if (!encrypted_skey || !result_str || !s_shareG2) return;

  // Generate a fake public key for the peer
  size_t pk_len = 128;
  char *pub_keyB = (char *)calloc(pk_len + 1, sizeof(char));
  if (!pub_keyB) return;
  fill_hex_string(pub_keyB, pk_len);

  uint8_t n = g_fdp->ConsumeIntegralInRange<uint8_t>((uint8_t)t, 16);
  if (n < (uint8_t)t) n = (uint8_t)t;
  uint8_t ind = g_fdp->ConsumeIntegralInRange<uint8_t>(1, n > 0 ? n : 1);

  trustedGetEncryptedSecretShareV2(
      __g_harness_eid, &errStatus, err_string,
      encrypted_poly, poly_enc_len, encrypted_skey, &skey_enc_len,
      result_str, s_shareG2, pub_keyB, (uint8_t)t, n, ind);
  if (errStatus != 0 || skey_enc_len == 0) return;

  // Step 3: Use the output for DkgVerifyV2
  // Build a fake s_share from the result_str (first 192 chars)
  size_t rs_len = strnlen(result_str, 192);
  char *s_share = (char *)calloc(193, sizeof(char));
  if (!s_share) return;
  memcpy(s_share, result_str, rs_len < 192 ? rs_len : 192);
  s_share[rs_len < 192 ? rs_len : 192] = '\0';

  // Fuzzed public_shares for Verification
  size_t ps_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 256);
  char *public_shares = (char *)calloc(ps_len + 1, sizeof(char));
  if (!public_shares) return;
  fill_hex_string(public_shares, ps_len);

  int *result = (int *)calloc(1, sizeof(int));
  if (!result) return;

  trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string,
                     public_shares, s_share, encrypted_skey, skey_enc_len,
                     (unsigned)t, (int)ind, result);
}

// Workflow 13: Dedicated trustedEncryptKey with various key formats
// Targets: trustedEncryptKey (2/8 edges), trustedDecryptKey exportable check

HARNESS_REGISTER(harness_v2_full_roundtrip, 20)
