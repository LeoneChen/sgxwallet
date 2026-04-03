#pragma once

#include <string.h>

// Shared initialization helper for all harness functions.
// Call at the beginning of each harness to set up enclave and SEK.
// g_sealed_sek_buf / g_sealed_sek_len are updated as a side effect.
static inline void init_enclave_and_sek(void) {
    // Step 1: Initialize the enclave (required for all operations)
    // Sets up curve, GMP memory functions, globalRandom
    // CRITICAL: Use fixed logLevel=0 to avoid consuming fuzz data.
    trustedEnclaveInit(__g_harness_eid, 0);

    // Step 2: Set up SEK (required for AES operations)
    // Alternate between trustedGenerateSEK and trustedSetSEKBackup using a
    // static counter instead of consuming fuzz data for the decision.
    static unsigned long sek_counter = 0;
    sek_counter++;

    int errStatus = 0;
    char *err_string = (char *)calloc(1024, sizeof(char));
    uint8_t *encrypted_SEK = (uint8_t *)calloc(1024, sizeof(uint8_t));
    uint64_t enc_len = 0;

    if (err_string && encrypted_SEK) {
        if (sek_counter % 3 != 0) {
            // Path A: Generate random SEK (67% of iterations)
            char *hex_SEK = (char *)calloc(65, sizeof(char));
            if (hex_SEK) {
                trustedGenerateSEK(__g_harness_eid, &errStatus, err_string,
                                   encrypted_SEK, &enc_len, hex_SEK);
                // Save sealed SEK for harness_set_sek_workflow
                if (enc_len > 0 && enc_len <= 1024) {
                    memcpy(g_sealed_sek_buf, encrypted_SEK, enc_len);
                    g_sealed_sek_len = enc_len;
                }
            }
        } else {
            // Path B: Set SEK from hex backup (33% of iterations)
            // Uses a deterministic hex string so no fuzz data is consumed
            char *sek_hex = (char *)calloc(33, sizeof(char));
            if (sek_hex) {
                // Alternate uppercase/lowercase hex to cover both char2int paths:
                // - lowercase: EnclaveCommon.cpp:280 (char2int 'a'-'f' branch)
                // - uppercase: EnclaveCommon.cpp:278 (char2int 'A'-'F' branch)
                // Also ensures hex2carray loop body (line 315) is hit with non-empty string.
                if ((sek_counter / 3) % 2 == 0) {
                    memcpy(sek_hex, "aabbccdd11223344aabbccdd11223344", 32);  // lowercase
                } else {
                    memcpy(sek_hex, "AABBCCDD11223344AABBCCDD11223344", 32);  // uppercase
                }
                sek_hex[32] = '\0';
                trustedSetSEKBackup(__g_harness_eid, &errStatus, err_string,
                                    encrypted_SEK, &enc_len, sek_hex);
                // Save sealed SEK for harness_set_sek_workflow
                if (enc_len > 0 && enc_len <= 1024) {
                    memcpy(g_sealed_sek_buf, encrypted_SEK, enc_len);
                    g_sealed_sek_len = enc_len;
                }
            }
        }
    }
}
