#pragma once

static void harness_get_decryption_share_valid_g2(void) {
  init_enclave_and_sek();
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // Generate BLS key: this is the skey used in getDecryptionShare
  int is_exportable = 1;
  uint8_t *encr_bls_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  uint64_t enc_len = 0;
  if (!encr_bls_key) return;
  trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string,
                        &is_exportable, encr_bls_key, &enc_len);
  if (errStatus != 0 || enc_len == 0) return;

  // Use hardcoded alt_bn128 G2 generator as public_decryption_value.
  // Format: X.c0:X.c1:Y.c0:Y.c1 (decimal Fq values, ':'-separated, 320-byte buf).
  // SplitStringToFq(':') → 4 elements → size()==4 check passes ✓
  // decryption_value.Z is set to Fq2::one() inside getDecryptionShare (not via G2::one())
  //   → bypasses whatever causes trustedGetBlsPubKey/calc_bls_public_key to fail ✓
  // is_well_formed() → true for the generator ✓
  // Covers: getDecryptionShare lines 184-206 (G2 point construction, scalar mult,
  //   to_affine_coordinates, ConvertG2ElementToString) + alt_bn128_G2::dbl() branches.
  char *g2_gen = (char *)calloc(320, sizeof(char));
  if (!g2_gen) return;
  // G2 generator coords from alt_bn128_init.cpp (libff alt_bn128 parameters)
  static const char G2_GEN[] =
      "10857046999023057135944570762232829481370756359578518086990519993285655852781"
      ":11559732032986387107991004021392285783925812861821192530917403151452391805634"
      ":8495653923123431417604973247489272438418190587263600148770280649306958101930"
      ":4082367875863433681332203403145435568316851327593401208105741076214120093531";
  strncpy(g2_gen, G2_GEN, 319);

  char *dec_share = (char *)calloc(320, sizeof(char));
  if (!dec_share) return;
  errStatus = 0;
  trustedGetDecryptionShare(__g_harness_eid, &errStatus, err_string,
                            encr_bls_key, g2_gen, enc_len,
                            dec_share);
}

// Targeted Verification() deep coverage via hardcoded BN128 G2 generator as public_shares:
// Verification() reads public_shares as 256 hex chars per share (4×64-char hex coords).
// Previously:
//   harness_dkg_create_bls_roundtrip passes zeros → isG2({0,0,0}) fails → early return at ret=3
//   harness_complete_dkg_roundtrip passes decimal format from trustedGetPublicShares
//     → ConvertHexToDec on decimal digits produces wrong coords → isG2 fails → ret=3
// Fix: hardcode BN128 G2 generator hex (256 chars) so isG2 returns true → covers lines 533-557:
//   the loop, power(), scalar mult, to_affine_coordinates(), strncpy, and the == comparison.
// Use ECDH roundtrip for valid s_share/verifier_key so session_key_recover + xor_decrypt work.

HARNESS_REGISTER(harness_get_decryption_share_valid_g2, 10)
