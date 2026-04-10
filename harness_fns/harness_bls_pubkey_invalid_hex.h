#pragma once

static void harness_bls_pubkey_invalid_hex(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  char *key = (char *)calloc(65, 1);
  uint8_t *enc_key = (uint8_t *)calloc(1024, 1);
  uint64_t enc_len = 0;
  char *pub_key = (char *)calloc(320, 1);
  if (!err_string || !key || !enc_key || !pub_key) return;

  memset(key, 'G', 64);  // 64 non-hex chars; strnlen=64 < MAX_KEY_LENGTH=128 → no error
  trustedEncryptKey(__g_harness_eid, &errStatus, err_string, key, enc_key, &enc_len);
  if (errStatus != 0 || enc_len == 0) return;

  errStatus = 0;
  trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string,
                      enc_key, enc_len, pub_key);
}

// Sequential harness targeting three uncovered paths in getDecryptionShare (TEUtils.cpp):
//
// Case 1: line 168 — mpz_set_str(skey, skey_hex, 16) == -1
//   trustedEncryptKey("G"×64) → enc_key → trustedGetDecryptionShare(enc_key, G2_GEN_DEC)
//   AES_decrypt recovers skey_hex="GGG...G" → mpz_set_str("GGG...G", 16) = -1 → covered.
//
// Case 2: line 193 — !decryption_value.is_well_formed()
//   trustedGenerateEcdsaKey → ecdsa_key → trustedGetDecryptionShare(ecdsa_key, "1:2:3:4")
//   skey_hex = ECDSA private key hex (valid hex) → mpz_set_str succeeds → Fr decimal ok →
//   SplitStringToFq("1:2:3:4") → 4 Fq elements → G2 point (1,2,3,4) NOT on BN128 curve →
//   is_well_formed() == false → line 193 covered.
//   "1","2","3","4" are all pure decimal: bigint assert passes.
//
// Case 3 (retained): line 179-181 — decryptionValue components != 4
//   enc_key from case 1 + pdv="123:456:789" (3 components) → size()!=4 → line 179 covered.

HARNESS_REGISTER(harness_bls_pubkey_invalid_hex, 15)
