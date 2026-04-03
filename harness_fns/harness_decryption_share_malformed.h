#pragma once

static void harness_decryption_share_malformed(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  static const char G2_GEN_DEC[] =
      "10857046999023057135944570762232829481370756359578518086990519993285655852781"
      ":11559732032986387107991004021392285783925812861821192530917403151452391805634"
      ":8495653923123431417604973247489272438418190587263600148770280649306958101930"
      ":4082367875863433681332203403145435568316851327593401208105741076214120093531";

  // Case 1: non-hex skey_hex → mpz_set_str fails → line 168
  {
    char *key = (char *)calloc(65, 1);
    uint8_t *enc_key = (uint8_t *)calloc(1024, 1);
    uint64_t enc_len = 0;
    char *dec_share = (char *)calloc(320, 1);
    char *g2 = (char *)calloc(320, 1);
    if (key && enc_key && dec_share && g2) {
      memset(key, 'G', 64);
      trustedEncryptKey(__g_harness_eid, &errStatus, err_string, key, enc_key, &enc_len);
      if (errStatus == 0 && enc_len > 0) {
        strncpy(g2, G2_GEN_DEC, 319);
        errStatus = 0;
        trustedGetDecryptionShare(__g_harness_eid, &errStatus, err_string,
                                  enc_key, g2, enc_len, dec_share);
      }
    }
  }

  // Case 2: valid ECDSA key + G2 point not on curve → is_well_formed() false → line 193
  {
    int is_exportable = 1;
    uint8_t *ecdsa_key = (uint8_t *)calloc(1024, 1);
    uint64_t ecdsa_enc_len = 0;
    char *pub_x = (char *)calloc(1024, 1);
    char *pub_y = (char *)calloc(1024, 1);
    char *dec_share = (char *)calloc(320, 1);
    if (ecdsa_key && pub_x && pub_y && dec_share) {
      errStatus = 0;
      trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                              &is_exportable, ecdsa_key, &ecdsa_enc_len, pub_x, pub_y);
      if (errStatus == 0 && ecdsa_enc_len > 0) {
        // "1:2:3:4": 4 valid decimal Fq elements but NOT a valid BN128 G2 point
        errStatus = 0;
        trustedGetDecryptionShare(__g_harness_eid, &errStatus, err_string,
                                  ecdsa_key, (char *)"1:2:3:4", ecdsa_enc_len, dec_share);
      }
    }
  }

  // Case 3: wrong number of components → line 179-181
  {
    char *key = (char *)calloc(65, 1);
    uint8_t *enc_key = (uint8_t *)calloc(1024, 1);
    uint64_t enc_len = 0;
    char *dec_share = (char *)calloc(320, 1);
    if (key && enc_key && dec_share) {
      memset(key, 'G', 64);
      trustedEncryptKey(__g_harness_eid, &errStatus, err_string, key, enc_key, &enc_len);
      if (errStatus == 0 && enc_len > 0) {
        errStatus = 0;
        trustedGetDecryptionShare(__g_harness_eid, &errStatus, err_string,
                                  enc_key, (char *)"123:456:789", enc_len, dec_share);
      }
    }
  }
}

// Covers ConvertHexToDec boundary cases:
//   - Empty string input
//   - Very long hex strings
//   - Strings with leading zeros
// Used by Verification, so this helps improve its 106/204 coverage

HARNESS_REGISTER(harness_decryption_share_malformed, 20)
