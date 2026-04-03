#pragma once

static void harness_dkg_get_secret_share_v1(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  uint8_t *encrypted_dkg_secret = (uint8_t *)calloc(3072, sizeof(uint8_t));
  uint64_t enc_len = 0;
  size_t t = g_fdp->ConsumeIntegralInRange<size_t>(1, 4);
  if (!encrypted_dkg_secret) return;

  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_dkg_secret, &enc_len, t);
  if (errStatus != 0 || enc_len == 0) return;

  uint8_t *encrypted_skey = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t dec_len = 0;
  char *result_str = (char *)calloc(193, sizeof(char));
  char *s_shareG2 = (char *)calloc(320, sizeof(char));
  // Always 128 chars: gen_session_key requires strnlen(pub_keyB, 128) >= 128.
  // With variable 1-128 and small seeds, FDP exhaustion returns min (1),
  // causing gen_session_key to fail with "pb_keyB is too short" every time.
  char *pub_keyB = (char *)calloc(129, sizeof(char));
  if (!encrypted_skey || !result_str || !s_shareG2 || !pub_keyB) return;
  fill_hex_string(pub_keyB, 128);

  uint8_t n = g_fdp->ConsumeIntegralInRange<uint8_t>((uint8_t)t, 16);
  if (n < (uint8_t)t) n = (uint8_t)t;
  uint8_t ind = g_fdp->ConsumeIntegralInRange<uint8_t>(1, n > 0 ? n : 1);

  trustedGetEncryptedSecretShare(
      __g_harness_eid, &errStatus, err_string,
      encrypted_dkg_secret, enc_len, encrypted_skey, &dec_len,
      result_str, s_shareG2, pub_keyB, (uint8_t)t, n, ind);
}

// Dedicated: CreateBlsKey V1 (0/80 edges, completely uncovered)

HARNESS_REGISTER(harness_dkg_get_secret_share_v1, 10)
