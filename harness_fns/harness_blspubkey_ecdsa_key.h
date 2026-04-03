#pragma once

static void harness_blspubkey_ecdsa_key(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  int is_exportable = 1;
  uint8_t *ecdsa_key = (uint8_t *)calloc(1024, 1);
  uint64_t ecdsa_enc_len = 0;
  char *pub_x = (char *)calloc(1024, 1);
  char *pub_y = (char *)calloc(1024, 1);
  if (!ecdsa_key || !pub_x || !pub_y) return;
  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, ecdsa_key, &ecdsa_enc_len, pub_x, pub_y);
  if (errStatus != 0 || ecdsa_enc_len == 0) return;

  char *bls_pub_key = (char *)calloc(320, sizeof(char));
  if (!bls_pub_key) return;
  errStatus = 0;
  trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string,
                      ecdsa_key, ecdsa_enc_len, bls_pub_key);
}

// trustedGetDecryptionShare → getDecryptionShare via ECDSA-key bypass.
// Same root cause as harness_blspubkey_ecdsa_key: BLS AES roundtrip unreliable.
// Fix: use ECDSA-encrypted key for AES_decrypt → skey_hex = ECDSA private key hex →
// getDecryptionShare(skey_hex, G2_GEN_DEC, decryption_share) covers the full function:
//   SplitStringToFq(':') → 4 elements (size==4 check passes) →
//   decryption_value constructed as G2 point → is_well_formed() true →
//   scalar mult: skey * decryption_value → to_affine_coordinates → ConvertG2ElementToString.
// G2_GEN_DEC: alt_bn128 G2 generator in decimal ':'-separated format (same as harness_get_decryption_share_valid_g2).

HARNESS_REGISTER(harness_blspubkey_ecdsa_key, 400)
