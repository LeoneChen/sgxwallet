/*
 * EnclaveFuzz - SGX Enclave Fuzzing Test Harness
 *
 * Generated from EDL: secure_enclave.edl
 * For EDL attribute reference, fuzzing strategies, and harness patterns,
 * see: EnclavePatch-Data/skills/enclavefuzz/references/harness_cookbook.md
 *
 * ============================================================================
 * Fuzzing Framework Architecture
 * ============================================================================
 *
 * Initialization (once):
 *     LibFuzzer → LLVMFuzzerInitialize()
 *                  ↓
 *                 customized_init()  ← Sanity check only (registration is
 *                                      done automatically via HARNESS_REGISTER
 *                                      static initializers in harness_fns/*.h)
 *
 * Fuzzing loop (per input):
 *     LibFuzzer → LLVMFuzzerTestOneInput(data, size)
 *                  ↓ Reinitialize g_fdp with new input
 *                  ↓ Recreate enclave (__g_harness_eid)
 *                  ↓
 *                 customized_harness()  ← Weighted selection
 *                  ↓
 *                 harness_xxx()  ← Per-function headers in harness_fns/
 *                  ↓
 *                 ECall → Enclave Code
 *
 * ============================================================================
 * Memory Management
 * ============================================================================
 * All harness allocations go through arena_calloc() (via the calloc macro),
 * which is a bump-pointer allocator backed by a single anonymous mmap in
 * test.cpp.  The arena is reset with madvise(MADV_DONTNEED) at the end of
 * each iteration — no individual free() calls are needed or performed.
 *
 * ============================================================================
 * Adding / Downweighting a Harness
 * ============================================================================
 * Add:
 *   1. Create harness_fns/harness_new_fn.h with function + HARNESS_REGISTER
 *   2. Add #include "harness_fns/harness_new_fn.h" below
 * Downweight (when sufficiently tested):
 *   1. Edit HARNESS_REGISTER weight in harness_fns/harness_xxx.h to 🟢 (3-15)
 *   2. Record in program_insight.md「已充分测试函数」section
 *   (Do NOT delete the file — keeps coverage history visible in fuzz reports)
 *
 * ============================================================================
 */

#include "FuzzedDataProvider.h"
#include "secure_enclave_u.h"
#include <sgx_urts.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Arena allocator defined in test.cpp. All enclave ECall parameter buffers
// go through this to keep them off the glibc heap and prevent malloc-lock
// deadlocks when the enclave OOBs into host memory.
extern uint8_t *g_arena_alloc(size_t size);
static inline void *arena_calloc(size_t nmemb, size_t size) {
  return g_arena_alloc(nmemb * size);
}
// Redirect calloc/malloc/free to the arena so any agent-generated code
// automatically stays off the glibc heap.
#define calloc(n, s) arena_calloc((n), (s))
#define malloc(s)    arena_calloc(1, (s))
#define free(p)      ((void)(p))

template <typename T> constexpr size_t safe_sizeof() {
  return sizeof(
      typename std::conditional<std::is_void<T>::value, char, T>::type);
}

// ============================================================================
// Global Variables
// ============================================================================

extern FuzzedDataProvider *g_fdp;
extern sgx_enclave_id_t __g_harness_eid;

// Fuzzing configuration parameters
static size_t g_max_strlen = 128; // Max string length for [string] attributes
static size_t g_max_cnt = 32;     // Max count for unbounded arrays
static size_t g_max_size = 512;   // Max size for unbounded buffers

// Sealed SEK saved from preamble's trustedGenerateSEK / trustedSetSEKBackup call.
// Used by harness_set_sek_workflow to call trustedSetSEK with VALID sgx_sealed_data_t.
// trustedSetSEK requires valid sealed data (sgx_unseal_data) - random bytes always fail.
static uint8_t g_sealed_sek_buf[1024];
static uint64_t g_sealed_sek_len = 0;

// ============================================================================
// Test Harness Registration System
// ============================================================================

typedef void (*TestHarness)(void);

struct TestHarnessEntry {
  TestHarness function;
  int weight; // Selection weight (default: 10)
};

static TestHarnessEntry test_harness_registry[10240];
static unsigned int test_harness_count = 0;
static int total_weight = 0;

// Auto-registration macro: place HARNESS_REGISTER(fn, weight) at the end of
// each harness_fns/harness_xxx.h file. The static initializer runs before
// main(), appending the entry to test_harness_registry automatically.
#define HARNESS_REGISTER(fn, w)                                          \
  static bool _harness_reg_##fn =                                        \
      (test_harness_registry[test_harness_count++] = {fn, w},            \
       total_weight += w, true);

// ============================================================================
// Shared initialization helper (must come after global externs/defines)
// ============================================================================
#include "harness_fns/harness_init_helpers.h"

// ============================================================================
// OCall Wrappers (see harness_fns/ocall_wrappers.h)
// ============================================================================
#include "harness_fns/ocall_wrappers.h"

// ============================================================================
// ECall Test Harnesses
// ============================================================================
// Auto-generated harness functions for each ECall
// Each function prepares fuzz inputs and invokes the corresponding ECall
// ============================================================================

// ============================================================================
// Workflow Harnesses (Bottleneck-Targeted)
// ============================================================================
// These harnesses chain initialization with operations to ensure valid state.
// Key insight: Most enclave functions need trustedEnclaveInit (sets up curve,
// GMP) + trustedGenerateSEK (sets AES_key[512]) before they can work.
// Functions that use AES_decrypt need properly encrypted keys from prior
// AES_encrypt calls - random bytes will fail GCM MAC verification.
// ============================================================================

// Helper: generate a fuzzed hex string of given length
static void fill_hex_string(char *buf, size_t len) {
  static const char hex_chars[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    buf[i] = hex_chars[g_fdp->ConsumeIntegralInRange<int>(0, 15)];
  }
  buf[len] = '\0';
}

// Helper: generate a string with mixed valid hex and occasional non-hex chars
static void fill_mixed_hex_string(char *buf, size_t len) {
  static const char all_chars[] = "0123456789abcdefghijklmnopqrstuvwxyz!@#$%^&*()";
  static const char hex_chars[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    if (g_fdp->ConsumeProbability<double>() < 0.85) {
      buf[i] = hex_chars[g_fdp->ConsumeIntegralInRange<int>(0, 15)];
    } else {
      buf[i] = all_chars[g_fdp->ConsumeIntegralInRange<int>(0, (int)sizeof(all_chars) - 2)];
    }
  }
  buf[len] = '\0';
}

// Helper: generate uppercase hex string (0-9, A-F) to cover char2int uppercase path
// Targets: char2int line 278 (EnclaveCommon.cpp) and hex2carray loop body (line 315)
static void fill_uppercase_hex_string(char *buf, size_t len) {
  static const char hex_upper[] = "0123456789ABCDEF";
  for (size_t i = 0; i < len; i++) {
    buf[i] = hex_upper[g_fdp->ConsumeIntegralInRange<int>(0, 15)];
  }
  buf[len] = '\0';
}

// Workflow 1: Generate ECDSA key, then use it for GetPubKey/Sign/Decrypt
// Targets: trustedGenerateEcdsaKey (11%), trustedGetPublicEcdsaKey (15%),
//          trustedEcdsaSign (23%), trustedDecryptKey (22%)

// ====== Per-function harness files (harness_fns/) ======
#include "harness_fns/harness_ecdsa_workflow.h"
#include "harness_fns/harness_ecdsa_get_pubkey.h"
#include "harness_fns/harness_ecdsa_sign_workflow.h"
#include "harness_fns/harness_non_exportable_decrypt.h"
#include "harness_fns/harness_ecdsa_sign_edge_cases.h"
#include "harness_fns/harness_signature_sign_large_hash.h"
#include "harness_fns/harness_ecdsa_and_encrypt_pipeline.h"
#include "harness_fns/harness_ecdsa_non_exportable.h"
#include "harness_fns/harness_bls_key_for_ecdsa_sign.h"
#include "harness_fns/harness_createbls_v2_ecdsa_key.h"
#include "harness_fns/harness_dkgverifyv2_ecdsa_key.h"
#include "harness_fns/harness_blspubkey_ecdsa_key.h"
#include "harness_fns/harness_decrshare_ecdsa_key.h"
#include "harness_fns/harness_dkg_verify_workflow.h"
#include "harness_fns/harness_dkg_verify_v2_workflow.h"
#include "harness_fns/harness_create_bls_key_v2_workflow.h"
#include "harness_fns/harness_decryption_share_workflow.h"
#include "harness_fns/harness_v2_full_roundtrip.h"
#include "harness_fns/harness_dkg_get_public_shares.h"
#include "harness_fns/harness_public_shares_t_mismatch.h"
#include "harness_fns/harness_dkg_get_secret_share_v1.h"
#include "harness_fns/harness_create_bls_key_v1_only.h"
#include "harness_fns/harness_dkg_verify_v1_only.h"
#include "harness_fns/harness_gen_dkg_secret_standalone.h"
#include "harness_fns/harness_dkg_poly_multi_t.h"
#include "harness_fns/harness_decrypt_dkg_secret_standalone.h"
#include "harness_fns/harness_get_secret_share_valid_pubkey.h"
#include "harness_fns/harness_get_secret_share_v2_valid_pubkey.h"
#include "harness_fns/harness_dkg_verify_with_real_shares.h"
#include "harness_fns/harness_create_bls_key_with_real_sshare.h"
#include "harness_fns/harness_complete_dkg_roundtrip.h"
#include "harness_fns/harness_dkg_create_bls_roundtrip.h"
#include "harness_fns/harness_get_decryption_share_valid_g2.h"
#include "harness_fns/harness_verification_deep.h"
#include "harness_fns/harness_v2_dkg_create_bls_roundtrip.h"
#include "harness_fns/harness_verification_multi_t.h"
#include "harness_fns/harness_null_paths_batch2.h"
#include "harness_fns/harness_getss_error_paths.h"
#include "harness_fns/harness_verification_edge_cases.h"
#include "harness_fns/harness_decryption_share_malformed.h"
#include "harness_fns/harness_hex_conversion_edge_cases.h"
#include "harness_fns/harness_split_string_to_fr_edge_cases.h"
#include "harness_fns/harness_convert_hex_stress_test.h"
#include "harness_fns/harness_g2_arithmetic_edge_cases.h"
#include "harness_fns/harness_create_bls_key_xor_fail.h"
#include "harness_fns/harness_create_bls_key_v2_xor_fail.h"
#include "harness_fns/harness_calc_secret_share_t_mismatch.h"
#include "harness_fns/harness_decrypt_dkg_garbage_input.h"
#include "harness_fns/harness_getss_short_pubkey.h"
#include "harness_fns/harness_dkgverify_short_sshare.h"
#include "harness_fns/harness_getss_v2_mismatched_t.h"
#include "harness_fns/harness_getss_v2_garbage_poly.h"
#include "harness_fns/harness_dkgverify_v2_null_all.h"
#include "harness_fns/harness_error_path_sequential.h"
#include "harness_fns/harness_bls_workflow.h"
#include "harness_fns/harness_bls_generate_standalone.h"
#include "harness_fns/harness_bls_sign_workflow.h"
#include "harness_fns/harness_bls_pubkey_workflow.h"
#include "harness_fns/harness_bls_sign_fixed.h"
#include "harness_fns/harness_bls_pubkey_invalid_hex.h"
#include "harness_fns/harness_bls_sign_null_paths.h"
#include "harness_fns/harness_encrypt_decrypt_workflow.h"
#include "harness_fns/harness_aes_roundtrip_coverage.h"
#include "harness_fns/harness_encrypt_key_variations.h"
#include "harness_fns/harness_set_sek_workflow.h"
#include "harness_fns/harness_domain_params_edge_cases.h"
#include "harness_fns/harness_sealhexsek_callonce_trigger.h"
#include "harness_fns/harness_aes_encrypt_long_key.h"
#include "harness_fns/harness_encrypt_key_128_chars.h"
#include "harness_fns/harness_get_encrypted_secret_share_v2_workflow.h"
#include "harness_fns/harness_bls_create_and_use.h"
#include "harness_fns/harness_sign_invalid_key.h"
#include "harness_fns/harness_createbls_v2_null_paths.h"
#include "harness_fns/harness_createbls_v2_loop.h"
#include "harness_fns/harness_createbls_v2_2shares.h"
#include "harness_fns/harness_secretshare_null_sequential.h"


extern "C" void customized_init() {
  // Harnesses are auto-registered via HARNESS_REGISTER macro in harness_fns/*.h
  // total_weight is accumulated during static initialization (before main).
  if (test_harness_count == 0) {
    fprintf(stderr, "[!] Error: No test harnesses registered\n");
    abort();
  }
  if (total_weight == 0) {
    fprintf(stderr, "[!] Error: All harness weights are 0\n");
    abort();
  }
}

// ============================================================================
// Main Test Entry Point
// ============================================================================
// Called by LLVMFuzzerTestOneInput for each fuzzing iteration.
// CRITICAL CHANGE: Always initializes the enclave and SEK before dispatching
// to harnesses. This ensures curve, GMP, and AES_key[512] are set up.
// ============================================================================

extern "C" void customized_harness(void) {
  if (g_fdp->remaining_bytes() < 1) return;
  int rand_val = g_fdp->ConsumeIntegralInRange<int>(0, total_weight - 1);
  int cumulative = 0;
  for (unsigned int i = 0; i < test_harness_count; i++) {
    cumulative += test_harness_registry[i].weight;
    if (rand_val < cumulative) {
      test_harness_registry[i].function();
      break;
    }
  }
}
