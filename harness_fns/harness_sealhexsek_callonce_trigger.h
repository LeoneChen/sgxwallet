#pragma once

static void harness_sealhexsek_callonce_trigger(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  if (!err_string) return;

  // sealHexSEK is CALL_ONCE per enclave lifetime.
  // The preamble already calls it once (via trustedGenerateSEK or trustedSetSEKBackup).
  // Goal: hit the "if (called) return" branch at sealHexSEK line 232.
  //
  // Strategy: only call trustedSetSEKBackup when preamble used Path A (trustedGenerateSEK),
  // i.e. when sek_counter % 3 != 0. We detect this by checking g_sealed_sek_len:
  // after Path A, g_sealed_sek_len > 0 (GenerateSEK saved a sealed key).
  // after Path B, g_sealed_sek_len is also > 0 — can't distinguish directly.
  //
  // Simpler fix: always call trustedGenerateSEK here (not SetSEKBackup).
  // trustedGenerateSEK internally calls sealHexSEK → hits CALL_ONCE guard.
  uint8_t *enc_sek = (uint8_t *)calloc(1024, sizeof(uint8_t));
  char *hex_out = (char *)calloc(65, sizeof(char));
  uint64_t enc_len = 0;
  if (!enc_sek || !hex_out) return;
  trustedGenerateSEK(__g_harness_eid, &errStatus, err_string,
                     enc_sek, &enc_len, hex_out);
  // This second call to trustedGenerateSEK will invoke sealHexSEK again,
  // hitting the CALL_ONCE "if (called) return" branch (line 232).
}

HARNESS_REGISTER(harness_sealhexsek_callonce_trigger, 50)
