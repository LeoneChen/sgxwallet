/*
 * EnclaveFuzz - SGX Enclave Fuzzing Test Harness (Auto-Generated)
 *
 * Generated from EDL: secure_enclave.edl
 *
 * ============================================================================
 * Fuzzing Framework Architecture
 * ============================================================================
 *
 * Initialization (once):
 *     LibFuzzer → LLVMFuzzerInitialize()
 *                  ↓
 *                 customized_init()  ← Register harnesses, calculate weights
 *
 * Fuzzing loop (per input):
 *     LibFuzzer → LLVMFuzzerTestOneInput(data, size)
 *                  ↓ Reinitialize g_fdp with new input
 *                  ↓ Recreate enclave (__g_harness_eid)
 *                  ↓
 *                 customized_harness()  ← Weighted selection
 *                  ↓
 *                 _harness_xxx()   ← Auto-generated test functions
 *                  ↓
 *                 ECall → Enclave Code
 *
 * ============================================================================
 * EDL Attribute Reference
 * ============================================================================
 *
 * | Attribute    | Meaning             | Fuzzing Strategy (ECall)         |
 * |--------------|---------------------|----------------------------------|
 * | [in]         | Input to callee     | Generate fuzzy data (Host→Encl)  |
 * | [out]        | Output from callee  | Allocate buffer (Encl→Host)      |
 * | [in,out]     | Bidirectional       | Generate input + allocate        |
 * | [size=N]     | Buffer size (bytes) | Use N for allocation             |
 * | [count=N]    | Array element count | Use N * sizeof(element)          |
 * | [string]     | Null-terminated str | Ensure null terminator           |
 * | [user_check] | No auto checking    | High fuzz value                  |
 *
 * CRITICAL: Direction Semantics ([in]/[out] relative to callee)
 * - For ECalls (Enclave is callee):
 *   [in] = Host→Enclave → FUZZ THIS in harness
 *   [out] = Enclave→Host → Allocate buffer only
 * - For OCalls (Host is callee):
 *   [in] = Enclave→Host → No fuzzing needed
 *   [out] = Host→Enclave → FUZZ THIS in OCall wrapper
 *
 * ============================================================================
 * Memory Management (Two Approaches)
 * ============================================================================
 * Approach 1 (Auto-Managed by g_alloc_mgr) - CURRENT DEFAULT:
 * - Use calloc() + g_alloc_mgr.push_back() to track allocations
 * - Framework in LLVMFuzzerTestOneInput (at test.cpp) automatically frees all
 * tracked memory after each iteration
 * - No explicit free() needed in harness functions
 * - Pros: Simple, no memory leaks, centralized cleanup
 * - Cons: Memory accumulates until end of iteration
 *
 * Approach 2 (Explicit free()):
 * - Use calloc() without g_alloc_mgr tracking
 * - Manually write free() calls at appropriate locations in harness code
 * - Pros: Immediate memory release, lower memory footprint
 * - Cons: Must ensure all allocations are freed, risk of memory leaks
 *
 * Usage: Choose approach based on your needs:
 * - Default: g_alloc_mgr for safety and simplicity
 * - Manual: Direct free() for memory-sensitive scenarios
 *
 * ============================================================================
 * Weighted Selection System
 * ============================================================================
 * Each harness has a weight (default: 10). Adjust weights in customized_init():
 * - High weight (e.g., 50-100) for critical/bottleneck paths
 * - Low weight (e.g., 1-5) for well-covered paths
 * - Modify test_harness_registry[i].weight before calculating total_weight
 *
 * ============================================================================
 */

#include "FuzzedDataProvider.h"
#include "secure_enclave_u.h"
#include <errno.h>
#include <sgx_urts.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

template <typename T> constexpr size_t safe_sizeof() {
  return sizeof(
      typename std::conditional<std::is_void<T>::value, char, T>::type);
}

// ============================================================================
// Global Variables
// ============================================================================

extern FuzzedDataProvider *g_fdp;
extern std::vector<uint8_t *> g_alloc_mgr;
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

// ============================================================================
// OCall Wrappers
// ============================================================================
// These wrappers intercept OCalls and fuzz [out] parameters
// to test Enclave's resilience to untrusted data
// ============================================================================

extern "C" uint64_t _harness_oc_realloc(void *optr, size_t osz, size_t nsz) {
  uint64_t _fuzz_ret = oc_realloc(optr, osz, nsz);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_optr =
        g_fdp->ConsumeIntegralInRange<size_t>(1 < 8 ? (20 / 1) : 1, g_max_cnt);
    g_fdp->ConsumeData((void *)optr, count_0_optr * 1);
  }
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    g_fdp->ConsumeData(&_fuzz_ret, sizeof(uint64_t));
  }
  return _fuzz_ret;
}

extern "C" void _harness_oc_printf(const char *str) { oc_printf(str); }

extern "C" void _harness_oc_free(void *optr, size_t sz) {
  oc_free(optr, sz);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_optr =
        g_fdp->ConsumeIntegralInRange<size_t>(1 < 8 ? (20 / 1) : 1, g_max_cnt);
    g_fdp->ConsumeData((void *)optr, count_0_optr * 1);
  }
}

extern "C" void _harness_sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf) {
  sgx_oc_cpuidex(cpuinfo, leaf, subleaf);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    for (size_t i_0_0 = 0; i_0_0 < 4; i_0_0++) {
      g_fdp->ConsumeData(&cpuinfo[i_0_0], sizeof(int));
    }
  }
}

extern "C" int
_harness_sgx_thread_wait_untrusted_event_ocall(const void *self) {
  int _fuzz_ret = sgx_thread_wait_untrusted_event_ocall(self);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_self =
        g_fdp->ConsumeIntegralInRange<size_t>(1 < 8 ? (20 / 1) : 1, g_max_cnt);
    g_fdp->ConsumeData((void *)self, count_0_self * 1);
  }
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
  }
  return _fuzz_ret;
}

extern "C" int
_harness_sgx_thread_set_untrusted_event_ocall(const void *waiter) {
  int _fuzz_ret = sgx_thread_set_untrusted_event_ocall(waiter);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_waiter =
        g_fdp->ConsumeIntegralInRange<size_t>(1 < 8 ? (20 / 1) : 1, g_max_cnt);
    g_fdp->ConsumeData((void *)waiter, count_0_waiter * 1);
  }
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
  }
  return _fuzz_ret;
}

extern "C" int
_harness_sgx_thread_setwait_untrusted_events_ocall(const void *waiter,
                                                   const void *self) {
  int _fuzz_ret = sgx_thread_setwait_untrusted_events_ocall(waiter, self);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_waiter =
        g_fdp->ConsumeIntegralInRange<size_t>(1 < 8 ? (20 / 1) : 1, g_max_cnt);
    g_fdp->ConsumeData((void *)waiter, count_0_waiter * 1);
  }
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_self =
        g_fdp->ConsumeIntegralInRange<size_t>(1 < 8 ? (20 / 1) : 1, g_max_cnt);
    g_fdp->ConsumeData((void *)self, count_0_self * 1);
  }
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
  }
  return _fuzz_ret;
}

extern "C" int
_harness_sgx_thread_set_multiple_untrusted_events_ocall(const void **waiters,
                                                        size_t total) {
  int _fuzz_ret =
      sgx_thread_set_multiple_untrusted_events_ocall(waiters, total);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
  }
  return _fuzz_ret;
}

// ============================================================================
// ECall Test Harnesses
// ============================================================================
// Auto-generated harness functions for each ECall
// Each function prepares fuzz inputs and invokes the corresponding ECall
// ============================================================================

static void _harness_trustedEnclaveInit(void) {
  uint64_t _logLevel;
  g_fdp->ConsumeData(&_logLevel, sizeof(uint64_t));
  trustedEnclaveInit(__g_harness_eid, _logLevel);
}
static void _harness_trustedGenerateSEK(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  uint8_t *encrypted_SEK = NULL;
  encrypted_SEK = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_SEK =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_SEK = (uint8_t *)calloc(count_0_encrypted_SEK, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_SEK);
  }
  uint64_t *enc_len = NULL;
  enc_len = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_enc_len =
        ((1) * (sizeof(uint64_t)) + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    enc_len = (uint64_t *)calloc(count_0_enc_len, sizeof(uint64_t));
    g_alloc_mgr.push_back((uint8_t *)enc_len);
  }
  char *hex_SEK = NULL;
  hex_SEK = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_hex_SEK =
        ((65) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    hex_SEK = (char *)calloc(count_0_hex_SEK, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)hex_SEK);
  }
  trustedGenerateSEK(__g_harness_eid, errStatus, err_string, encrypted_SEK,
                     enc_len, hex_SEK);
}
static void _harness_trustedSetSEK(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  uint8_t *encrypted_SEK = NULL;
  encrypted_SEK = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_SEK =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_SEK = (uint8_t *)calloc(count_0_encrypted_SEK, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_SEK);
    g_fdp->ConsumeData((void *)encrypted_SEK,
                       count_0_encrypted_SEK * sizeof(uint8_t));
  }
  trustedSetSEK(__g_harness_eid, errStatus, err_string, encrypted_SEK);
}
static void _harness_trustedSetSEKBackup(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  uint8_t *encrypted_SEK = NULL;
  encrypted_SEK = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_SEK =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_SEK = (uint8_t *)calloc(count_0_encrypted_SEK, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_SEK);
  }
  uint64_t *enc_len = NULL;
  enc_len = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_enc_len =
        ((1) * (sizeof(uint64_t)) + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    enc_len = (uint64_t *)calloc(count_0_enc_len, sizeof(uint64_t));
    g_alloc_mgr.push_back((uint8_t *)enc_len);
  }
  char *SEK_hex = NULL;
  size_t SEK_hex_strlen =
      g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  SEK_hex = (char *)calloc(SEK_hex_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)SEK_hex);
  g_fdp->ConsumeData(SEK_hex, SEK_hex_strlen * sizeof(char));
  trustedSetSEKBackup(__g_harness_eid, errStatus, err_string, encrypted_SEK,
                      enc_len, SEK_hex);
}
static void _harness_trustedGenerateEcdsaKey(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  int *is_exportable = NULL;
  is_exportable = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_is_exportable =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    is_exportable = (int *)calloc(count_0_is_exportable, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)is_exportable);
    g_fdp->ConsumeData((void *)is_exportable,
                       count_0_is_exportable * sizeof(int));
  }
  uint8_t *encrypted_key = NULL;
  encrypted_key = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_key =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_key = (uint8_t *)calloc(count_0_encrypted_key, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_key);
  }
  uint64_t *enc_len = NULL;
  enc_len = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_enc_len =
        ((1) * (sizeof(uint64_t)) + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    enc_len = (uint64_t *)calloc(count_0_enc_len, sizeof(uint64_t));
    g_alloc_mgr.push_back((uint8_t *)enc_len);
  }
  char *pub_key_x = NULL;
  pub_key_x = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_pub_key_x =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    pub_key_x = (char *)calloc(count_0_pub_key_x, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)pub_key_x);
  }
  char *pub_key_y = NULL;
  pub_key_y = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_pub_key_y =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    pub_key_y = (char *)calloc(count_0_pub_key_y, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)pub_key_y);
  }
  trustedGenerateEcdsaKey(__g_harness_eid, errStatus, err_string, is_exportable,
                          encrypted_key, enc_len, pub_key_x, pub_key_y);
}
static void _harness_trustedGetPublicEcdsaKey(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  uint8_t *encrypted_key = NULL;
  encrypted_key = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_key =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_key = (uint8_t *)calloc(count_0_encrypted_key, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_key);
    g_fdp->ConsumeData((void *)encrypted_key,
                       count_0_encrypted_key * sizeof(uint8_t));
  }
  uint64_t dec_len;
  g_fdp->ConsumeData(&dec_len, sizeof(uint64_t));
  char *pub_key_x = NULL;
  pub_key_x = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_pub_key_x =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    pub_key_x = (char *)calloc(count_0_pub_key_x, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)pub_key_x);
  }
  char *pub_key_y = NULL;
  pub_key_y = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_pub_key_y =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    pub_key_y = (char *)calloc(count_0_pub_key_y, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)pub_key_y);
  }
  trustedGetPublicEcdsaKey(__g_harness_eid, errStatus, err_string,
                           encrypted_key, dec_len, pub_key_x, pub_key_y);
}
static void _harness_trustedEcdsaSign(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  uint8_t *encrypted_key = NULL;
  encrypted_key = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_key =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_key = (uint8_t *)calloc(count_0_encrypted_key, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_key);
    g_fdp->ConsumeData((void *)encrypted_key,
                       count_0_encrypted_key * sizeof(uint8_t));
  }
  uint64_t enc_len;
  g_fdp->ConsumeData(&enc_len, sizeof(uint64_t));
  char *hash = NULL;
  size_t hash_strlen = g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  hash = (char *)calloc(hash_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)hash);
  g_fdp->ConsumeData(hash, hash_strlen * sizeof(char));
  char *sig_r = NULL;
  sig_r = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_sig_r =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    sig_r = (char *)calloc(count_0_sig_r, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)sig_r);
  }
  char *sig_s = NULL;
  sig_s = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_sig_s =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    sig_s = (char *)calloc(count_0_sig_s, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)sig_s);
  }
  uint8_t *sig_v = NULL;
  sig_v = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_sig_v =
        ((1) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    sig_v = (uint8_t *)calloc(count_0_sig_v, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)sig_v);
  }
  int base;
  g_fdp->ConsumeData(&base, sizeof(int));
  trustedEcdsaSign(__g_harness_eid, errStatus, err_string, encrypted_key,
                   enc_len, hash, sig_r, sig_s, sig_v, base);
}
static void _harness_trustedEncryptKey(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  char *key = NULL;
  key = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_key =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    key = (char *)calloc(count_0_key, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)key);
    g_fdp->ConsumeData((void *)key, count_0_key * sizeof(char));
  }
  uint8_t *encrypted_key = NULL;
  encrypted_key = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_key =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_key = (uint8_t *)calloc(count_0_encrypted_key, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_key);
  }
  uint64_t *enc_len = NULL;
  enc_len = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_enc_len =
        ((1) * (sizeof(uint64_t)) + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    enc_len = (uint64_t *)calloc(count_0_enc_len, sizeof(uint64_t));
    g_alloc_mgr.push_back((uint8_t *)enc_len);
  }
  trustedEncryptKey(__g_harness_eid, errStatus, err_string, key, encrypted_key,
                    enc_len);
}
static void _harness_trustedDecryptKey(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  uint8_t *encrypted_key = NULL;
  encrypted_key = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_key =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_key = (uint8_t *)calloc(count_0_encrypted_key, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_key);
    g_fdp->ConsumeData((void *)encrypted_key,
                       count_0_encrypted_key * sizeof(uint8_t));
  }
  uint64_t enc_len;
  g_fdp->ConsumeData(&enc_len, sizeof(uint64_t));
  char *key = NULL;
  key = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_key =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    key = (char *)calloc(count_0_key, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)key);
  }
  trustedDecryptKey(__g_harness_eid, errStatus, err_string, encrypted_key,
                    enc_len, key);
}
static void _harness_trustedGenDkgSecret(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  uint8_t *encrypted_dkg_secret = NULL;
  encrypted_dkg_secret = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_dkg_secret =
        ((3072) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_dkg_secret =
        (uint8_t *)calloc(count_0_encrypted_dkg_secret, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_dkg_secret);
  }
  uint64_t *enc_len = NULL;
  enc_len = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_enc_len =
        ((1) * (sizeof(uint64_t)) + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    enc_len = (uint64_t *)calloc(count_0_enc_len, sizeof(uint64_t));
    g_alloc_mgr.push_back((uint8_t *)enc_len);
  }
  size_t _t;
  g_fdp->ConsumeData(&_t, sizeof(size_t));
  trustedGenDkgSecret(__g_harness_eid, errStatus, err_string,
                      encrypted_dkg_secret, enc_len, _t);
}
static void _harness_trustedDecryptDkgSecret(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  uint8_t *encrypted_dkg_secret = NULL;
  encrypted_dkg_secret = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_dkg_secret =
        ((3050) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_dkg_secret =
        (uint8_t *)calloc(count_0_encrypted_dkg_secret, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_dkg_secret);
    g_fdp->ConsumeData((void *)encrypted_dkg_secret,
                       count_0_encrypted_dkg_secret * sizeof(uint8_t));
  }
  uint64_t enc_len;
  g_fdp->ConsumeData(&enc_len, sizeof(uint64_t));
  uint8_t *decrypted_dkg_secret = NULL;
  decrypted_dkg_secret = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_decrypted_dkg_secret =
        ((3072) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    decrypted_dkg_secret =
        (uint8_t *)calloc(count_0_decrypted_dkg_secret, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)decrypted_dkg_secret);
  }
  trustedDecryptDkgSecret(__g_harness_eid, errStatus, err_string,
                          encrypted_dkg_secret, enc_len, decrypted_dkg_secret);
}
static void _harness_trustedGetEncryptedSecretShare(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  uint8_t *encrypted_poly = NULL;
  encrypted_poly = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_poly =
        ((3050) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_poly = (uint8_t *)calloc(count_0_encrypted_poly, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_poly);
    g_fdp->ConsumeData((void *)encrypted_poly,
                       count_0_encrypted_poly * sizeof(uint8_t));
  }
  uint64_t enc_len;
  g_fdp->ConsumeData(&enc_len, sizeof(uint64_t));
  uint8_t *encrypted_skey = NULL;
  encrypted_skey = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_skey =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_skey = (uint8_t *)calloc(count_0_encrypted_skey, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_skey);
  }
  uint64_t *dec_len = NULL;
  dec_len = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_dec_len =
        ((1) * (sizeof(uint64_t)) + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    dec_len = (uint64_t *)calloc(count_0_dec_len, sizeof(uint64_t));
    g_alloc_mgr.push_back((uint8_t *)dec_len);
  }
  char *result_str = NULL;
  result_str = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_result_str =
        ((193) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    result_str = (char *)calloc(count_0_result_str, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)result_str);
  }
  char *s_shareG2 = NULL;
  s_shareG2 = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_s_shareG2 =
        ((320) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    s_shareG2 = (char *)calloc(count_0_s_shareG2, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)s_shareG2);
  }
  char *pub_keyB = NULL;
  size_t pub_keyB_strlen =
      g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  pub_keyB = (char *)calloc(pub_keyB_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_keyB);
  g_fdp->ConsumeData(pub_keyB, pub_keyB_strlen * sizeof(char));
  uint8_t _t;
  g_fdp->ConsumeData(&_t, sizeof(uint8_t));
  uint8_t _n;
  g_fdp->ConsumeData(&_n, sizeof(uint8_t));
  uint8_t ind;
  g_fdp->ConsumeData(&ind, sizeof(uint8_t));
  trustedGetEncryptedSecretShare(
      __g_harness_eid, errStatus, err_string, encrypted_poly, enc_len,
      encrypted_skey, dec_len, result_str, s_shareG2, pub_keyB, _t, _n, ind);
}
static void _harness_trustedGetEncryptedSecretShareV2(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  uint8_t *encrypted_poly = NULL;
  encrypted_poly = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_poly =
        ((3050) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_poly = (uint8_t *)calloc(count_0_encrypted_poly, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_poly);
    g_fdp->ConsumeData((void *)encrypted_poly,
                       count_0_encrypted_poly * sizeof(uint8_t));
  }
  uint64_t enc_len;
  g_fdp->ConsumeData(&enc_len, sizeof(uint64_t));
  uint8_t *encrypted_skey = NULL;
  encrypted_skey = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_skey =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_skey = (uint8_t *)calloc(count_0_encrypted_skey, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_skey);
  }
  uint64_t *dec_len = NULL;
  dec_len = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_dec_len =
        ((1) * (sizeof(uint64_t)) + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    dec_len = (uint64_t *)calloc(count_0_dec_len, sizeof(uint64_t));
    g_alloc_mgr.push_back((uint8_t *)dec_len);
  }
  char *result_str = NULL;
  result_str = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_result_str =
        ((193) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    result_str = (char *)calloc(count_0_result_str, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)result_str);
  }
  char *s_shareG2 = NULL;
  s_shareG2 = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_s_shareG2 =
        ((320) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    s_shareG2 = (char *)calloc(count_0_s_shareG2, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)s_shareG2);
  }
  char *pub_keyB = NULL;
  size_t pub_keyB_strlen =
      g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  pub_keyB = (char *)calloc(pub_keyB_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_keyB);
  g_fdp->ConsumeData(pub_keyB, pub_keyB_strlen * sizeof(char));
  uint8_t _t;
  g_fdp->ConsumeData(&_t, sizeof(uint8_t));
  uint8_t _n;
  g_fdp->ConsumeData(&_n, sizeof(uint8_t));
  uint8_t ind;
  g_fdp->ConsumeData(&ind, sizeof(uint8_t));
  trustedGetEncryptedSecretShareV2(
      __g_harness_eid, errStatus, err_string, encrypted_poly, enc_len,
      encrypted_skey, dec_len, result_str, s_shareG2, pub_keyB, _t, _n, ind);
}
static void _harness_trustedGetPublicShares(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  uint8_t *encrypted_dkg_secret = NULL;
  encrypted_dkg_secret = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_dkg_secret =
        ((3050) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_dkg_secret =
        (uint8_t *)calloc(count_0_encrypted_dkg_secret, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_dkg_secret);
    g_fdp->ConsumeData((void *)encrypted_dkg_secret,
                       count_0_encrypted_dkg_secret * sizeof(uint8_t));
  }
  uint64_t enc_len;
  g_fdp->ConsumeData(&enc_len, sizeof(uint64_t));
  char *public_shares = NULL;
  public_shares = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_public_shares =
        ((10000) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    public_shares = (char *)calloc(count_0_public_shares, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)public_shares);
  }
  unsigned int _t;
  g_fdp->ConsumeData(&_t, sizeof(unsigned int));
  trustedGetPublicShares(__g_harness_eid, errStatus, err_string,
                         encrypted_dkg_secret, enc_len, public_shares, _t);
}
static void _harness_trustedDkgVerify(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  char *public_shares = NULL;
  size_t public_shares_strlen =
      g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  public_shares = (char *)calloc(public_shares_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)public_shares);
  g_fdp->ConsumeData(public_shares, public_shares_strlen * sizeof(char));
  char *s_share = NULL;
  size_t s_share_strlen =
      g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  s_share = (char *)calloc(s_share_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)s_share);
  g_fdp->ConsumeData(s_share, s_share_strlen * sizeof(char));
  uint8_t *encrypted_key = NULL;
  encrypted_key = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_key =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_key = (uint8_t *)calloc(count_0_encrypted_key, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_key);
    g_fdp->ConsumeData((void *)encrypted_key,
                       count_0_encrypted_key * sizeof(uint8_t));
  }
  uint64_t key_len;
  g_fdp->ConsumeData(&key_len, sizeof(uint64_t));
  unsigned int _t;
  g_fdp->ConsumeData(&_t, sizeof(unsigned int));
  int _ind;
  g_fdp->ConsumeData(&_ind, sizeof(int));
  int *result = NULL;
  result = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_result =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    result = (int *)calloc(count_0_result, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)result);
  }
  trustedDkgVerify(__g_harness_eid, errStatus, err_string, public_shares,
                   s_share, encrypted_key, key_len, _t, _ind, result);
}
static void _harness_trustedDkgVerifyV2(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  char *public_shares = NULL;
  size_t public_shares_strlen =
      g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  public_shares = (char *)calloc(public_shares_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)public_shares);
  g_fdp->ConsumeData(public_shares, public_shares_strlen * sizeof(char));
  char *s_share = NULL;
  size_t s_share_strlen =
      g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  s_share = (char *)calloc(s_share_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)s_share);
  g_fdp->ConsumeData(s_share, s_share_strlen * sizeof(char));
  uint8_t *encrypted_key = NULL;
  encrypted_key = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_key =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_key = (uint8_t *)calloc(count_0_encrypted_key, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_key);
    g_fdp->ConsumeData((void *)encrypted_key,
                       count_0_encrypted_key * sizeof(uint8_t));
  }
  uint64_t key_len;
  g_fdp->ConsumeData(&key_len, sizeof(uint64_t));
  unsigned int _t;
  g_fdp->ConsumeData(&_t, sizeof(unsigned int));
  int _ind;
  g_fdp->ConsumeData(&_ind, sizeof(int));
  int *result = NULL;
  result = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_result =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    result = (int *)calloc(count_0_result, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)result);
  }
  trustedDkgVerifyV2(__g_harness_eid, errStatus, err_string, public_shares,
                     s_share, encrypted_key, key_len, _t, _ind, result);
}
static void _harness_trustedCreateBlsKey(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  char *s_shares = NULL;
  s_shares = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_s_shares =
        ((6145) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    s_shares = (char *)calloc(count_0_s_shares, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)s_shares);
    g_fdp->ConsumeData((void *)s_shares, count_0_s_shares * sizeof(char));
  }
  uint8_t *encrypted_key = NULL;
  encrypted_key = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_key =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_key = (uint8_t *)calloc(count_0_encrypted_key, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_key);
    g_fdp->ConsumeData((void *)encrypted_key,
                       count_0_encrypted_key * sizeof(uint8_t));
  }
  uint64_t key_len;
  g_fdp->ConsumeData(&key_len, sizeof(uint64_t));
  uint8_t *encr_bls_key = NULL;
  encr_bls_key = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encr_bls_key =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encr_bls_key = (uint8_t *)calloc(count_0_encr_bls_key, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encr_bls_key);
  }
  uint64_t *enc_bls_key_len = NULL;
  enc_bls_key_len = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_enc_bls_key_len =
        ((1) * (sizeof(uint64_t)) + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    enc_bls_key_len =
        (uint64_t *)calloc(count_0_enc_bls_key_len, sizeof(uint64_t));
    g_alloc_mgr.push_back((uint8_t *)enc_bls_key_len);
  }
  trustedCreateBlsKey(__g_harness_eid, errStatus, err_string, s_shares,
                      encrypted_key, key_len, encr_bls_key, enc_bls_key_len);
}
static void _harness_trustedCreateBlsKeyV2(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  char *s_shares = NULL;
  s_shares = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_s_shares =
        ((6145) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    s_shares = (char *)calloc(count_0_s_shares, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)s_shares);
    g_fdp->ConsumeData((void *)s_shares, count_0_s_shares * sizeof(char));
  }
  uint8_t *encrypted_key = NULL;
  encrypted_key = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_key =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_key = (uint8_t *)calloc(count_0_encrypted_key, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_key);
    g_fdp->ConsumeData((void *)encrypted_key,
                       count_0_encrypted_key * sizeof(uint8_t));
  }
  uint64_t key_len;
  g_fdp->ConsumeData(&key_len, sizeof(uint64_t));
  uint8_t *encr_bls_key = NULL;
  encr_bls_key = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encr_bls_key =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encr_bls_key = (uint8_t *)calloc(count_0_encr_bls_key, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encr_bls_key);
  }
  uint64_t *enc_bls_key_len = NULL;
  enc_bls_key_len = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_enc_bls_key_len =
        ((1) * (sizeof(uint64_t)) + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    enc_bls_key_len =
        (uint64_t *)calloc(count_0_enc_bls_key_len, sizeof(uint64_t));
    g_alloc_mgr.push_back((uint8_t *)enc_bls_key_len);
  }
  trustedCreateBlsKeyV2(__g_harness_eid, errStatus, err_string, s_shares,
                        encrypted_key, key_len, encr_bls_key, enc_bls_key_len);
}
static void _harness_trustedBlsSignMessage(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((256) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  uint8_t *encrypted_key = NULL;
  encrypted_key = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_key =
        ((256) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_key = (uint8_t *)calloc(count_0_encrypted_key, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_key);
    g_fdp->ConsumeData((void *)encrypted_key,
                       count_0_encrypted_key * sizeof(uint8_t));
  }
  uint64_t enc_len;
  g_fdp->ConsumeData(&enc_len, sizeof(uint64_t));
  char *hashX = NULL;
  size_t hashX_strlen = g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  hashX = (char *)calloc(hashX_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)hashX);
  g_fdp->ConsumeData(hashX, hashX_strlen * sizeof(char));
  char *hashY = NULL;
  size_t hashY_strlen = g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  hashY = (char *)calloc(hashY_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)hashY);
  g_fdp->ConsumeData(hashY, hashY_strlen * sizeof(char));
  char *signature = NULL;
  signature = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_signature =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    signature = (char *)calloc(count_0_signature, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)signature);
  }
  trustedBlsSignMessage(__g_harness_eid, errStatus, err_string, encrypted_key,
                        enc_len, hashX, hashY, signature);
}
static void _harness_trustedGetBlsPubKey(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  uint8_t *encrypted_key = NULL;
  encrypted_key = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_key =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_key = (uint8_t *)calloc(count_0_encrypted_key, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_key);
    g_fdp->ConsumeData((void *)encrypted_key,
                       count_0_encrypted_key * sizeof(uint8_t));
  }
  uint64_t key_len;
  g_fdp->ConsumeData(&key_len, sizeof(uint64_t));
  char *bls_pub_key = NULL;
  bls_pub_key = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_bls_pub_key =
        ((320) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    bls_pub_key = (char *)calloc(count_0_bls_pub_key, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)bls_pub_key);
  }
  trustedGetBlsPubKey(__g_harness_eid, errStatus, err_string, encrypted_key,
                      key_len, bls_pub_key);
}
static void _harness_trustedGetDecryptionShare(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *err_string = NULL;
  err_string = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_err_string =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    err_string = (char *)calloc(count_0_err_string, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
  }
  uint8_t *encrypted_key = NULL;
  encrypted_key = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encrypted_key =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encrypted_key = (uint8_t *)calloc(count_0_encrypted_key, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_key);
    g_fdp->ConsumeData((void *)encrypted_key,
                       count_0_encrypted_key * sizeof(uint8_t));
  }
  char *public_decryption_value = NULL;
  public_decryption_value = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_public_decryption_value =
        ((320) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    public_decryption_value =
        (char *)calloc(count_0_public_decryption_value, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)public_decryption_value);
    g_fdp->ConsumeData((void *)public_decryption_value,
                       count_0_public_decryption_value * sizeof(char));
  }
  uint64_t key_len;
  g_fdp->ConsumeData(&key_len, sizeof(uint64_t));
  char *decrption_share = NULL;
  decrption_share = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_decrption_share =
        ((320) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    decrption_share = (char *)calloc(count_0_decrption_share, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)decrption_share);
  }
  trustedGetDecryptionShare(__g_harness_eid, errStatus, err_string,
                            encrypted_key, public_decryption_value, key_len,
                            decrption_share);
}
static void _harness_trustedGenerateBLSKey(void) {
  int *errStatus = NULL;
  errStatus = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errStatus =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    errStatus = (int *)calloc(count_0_errStatus, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)errStatus);
  }
  char *errString = NULL;
  errString = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_errString =
        ((1024) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    errString = (char *)calloc(count_0_errString, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)errString);
  }
  int *isExportable = NULL;
  isExportable = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_isExportable =
        ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    isExportable = (int *)calloc(count_0_isExportable, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)isExportable);
    g_fdp->ConsumeData((void *)isExportable,
                       count_0_isExportable * sizeof(int));
  }
  uint8_t *encryptedKey = NULL;
  encryptedKey = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encryptedKey =
        ((1024) * (sizeof(uint8_t)) + sizeof(uint8_t) - 1) / sizeof(uint8_t);
    encryptedKey = (uint8_t *)calloc(count_0_encryptedKey, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encryptedKey);
  }
  uint64_t *encLen = NULL;
  encLen = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_encLen =
        ((1) * (sizeof(uint64_t)) + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    encLen = (uint64_t *)calloc(count_0_encLen, sizeof(uint64_t));
    g_alloc_mgr.push_back((uint8_t *)encLen);
  }
  trustedGenerateBLSKey(__g_harness_eid, errStatus, errString, isExportable,
                        encryptedKey, encLen);
}

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

// Workflow 1: Generate ECDSA key, then use it for GetPubKey/Sign/Decrypt
// Targets: trustedGenerateEcdsaKey (11%), trustedGetPublicEcdsaKey (15%),
//          trustedEcdsaSign (23%), trustedDecryptKey (22%)
static void harness_ecdsa_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  // Generate ECDSA key (uses curve from init, AES_key from SEK)
  int is_exportable = g_fdp->ConsumeIntegralInRange<int>(0, 1);
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_key);
  uint64_t enc_len = 0;
  char *pub_key_x = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_key_x);
  char *pub_key_y = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_key_y);
  if (!encrypted_key || !pub_key_x || !pub_key_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, encrypted_key, &enc_len,
                          pub_key_x, pub_key_y);
  if (errStatus != 0 || enc_len == 0) return;

  // Use the generated key for a random operation
  int op = g_fdp->ConsumeIntegralInRange<int>(0, 2);
  switch (op) {
    case 0: {
      // GetPublicEcdsaKey with valid encrypted key
      char *out_x = (char *)calloc(1024, sizeof(char));
      g_alloc_mgr.push_back((uint8_t *)out_x);
      char *out_y = (char *)calloc(1024, sizeof(char));
      g_alloc_mgr.push_back((uint8_t *)out_y);
      if (out_x && out_y) {
        trustedGetPublicEcdsaKey(__g_harness_eid, &errStatus, err_string,
                                 encrypted_key, enc_len, out_x, out_y);
      }
      break;
    }
    case 1: {
      // EcdsaSign with valid encrypted key + fuzzed hex hash
      size_t hash_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 64);
      char *hash = (char *)calloc(hash_len + 1, sizeof(char));
      g_alloc_mgr.push_back((uint8_t *)hash);
      if (!hash) break;
      fill_hex_string(hash, hash_len);

      char *sig_r = (char *)calloc(1024, sizeof(char));
      g_alloc_mgr.push_back((uint8_t *)sig_r);
      char *sig_s = (char *)calloc(1024, sizeof(char));
      g_alloc_mgr.push_back((uint8_t *)sig_s);
      uint8_t *sig_v = (uint8_t *)calloc(1, sizeof(uint8_t));
      g_alloc_mgr.push_back(sig_v);
      int base = g_fdp->ConsumeIntegralInRange<int>(10, 16);
      if (sig_r && sig_s && sig_v) {
        trustedEcdsaSign(__g_harness_eid, &errStatus, err_string,
                         encrypted_key, enc_len, hash, sig_r, sig_s,
                         sig_v, base);
      }
      break;
    }
    case 2: {
      // DecryptKey with valid encrypted key
      char *key = (char *)calloc(1024, sizeof(char));
      g_alloc_mgr.push_back((uint8_t *)key);
      if (key) {
        trustedDecryptKey(__g_harness_eid, &errStatus, err_string,
                          encrypted_key, enc_len, key);
      }
      break;
    }
  }
}

// Workflow 2: Generate DKG secret, then Decrypt/GetPublicShares/GetEncryptedSecretShare
// Targets: trustedGenDkgSecret (28%), trustedDecryptDkgSecret (40%),
//          trustedGetPublicShares (28%), trustedGetEncryptedSecretShare (15%),
//          trustedGetEncryptedSecretShareV2 (14%)
static void harness_dkg_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  // Generate DKG secret with valid t in [1,16]
  uint8_t *encrypted_dkg_secret = (uint8_t *)calloc(3072, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_dkg_secret);
  uint64_t enc_len = 0;
  size_t t = g_fdp->ConsumeIntegralInRange<size_t>(1, 16);
  if (!encrypted_dkg_secret) return;

  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_dkg_secret, &enc_len, t);
  if (errStatus != 0 || enc_len == 0) return;

  int op = g_fdp->ConsumeIntegralInRange<int>(0, 2);
  switch (op) {
    case 0: {
      // DecryptDkgSecret with valid encrypted secret
      uint8_t *decrypted = (uint8_t *)calloc(3072, sizeof(uint8_t));
      g_alloc_mgr.push_back((uint8_t *)decrypted);
      if (decrypted) {
        trustedDecryptDkgSecret(__g_harness_eid, &errStatus, err_string,
                                encrypted_dkg_secret, enc_len, decrypted);
      }
      break;
    }
    case 1: {
      // GetPublicShares with valid encrypted secret and t > 0
      char *public_shares = (char *)calloc(10000, sizeof(char));
      g_alloc_mgr.push_back((uint8_t *)public_shares);
      if (public_shares) {
        trustedGetPublicShares(__g_harness_eid, &errStatus, err_string,
                               encrypted_dkg_secret, enc_len, public_shares,
                               (unsigned)t);
      }
      break;
    }
    case 2: {
      // GetEncryptedSecretShare/V2 with valid encrypted poly
      uint8_t *encrypted_skey = (uint8_t *)calloc(1024, sizeof(uint8_t));
      g_alloc_mgr.push_back((uint8_t *)encrypted_skey);
      uint64_t dec_len = 0;
      char *result_str = (char *)calloc(193, sizeof(char));
      g_alloc_mgr.push_back((uint8_t *)result_str);
      char *s_shareG2 = (char *)calloc(320, sizeof(char));
      g_alloc_mgr.push_back((uint8_t *)s_shareG2);
      // Always 128 chars: gen_session_key requires strnlen(pub_keyB, 128) >= 128
      char *pub_keyB = (char *)calloc(129, sizeof(char));
      g_alloc_mgr.push_back((uint8_t *)pub_keyB);
      if (!encrypted_skey || !result_str || !s_shareG2 || !pub_keyB) break;
      fill_hex_string(pub_keyB, 128);

      uint8_t n = g_fdp->ConsumeIntegralInRange<uint8_t>((uint8_t)t, 16);
      if (n < (uint8_t)t) n = (uint8_t)t;
      uint8_t ind = g_fdp->ConsumeIntegralInRange<uint8_t>(1, n > 0 ? n : 1);

      if (g_fdp->ConsumeProbability<double>() < 0.5) {
        trustedGetEncryptedSecretShare(
            __g_harness_eid, &errStatus, err_string,
            encrypted_dkg_secret, enc_len, encrypted_skey, &dec_len,
            result_str, s_shareG2, pub_keyB, (uint8_t)t, n, ind);
      } else {
        trustedGetEncryptedSecretShareV2(
            __g_harness_eid, &errStatus, err_string,
            encrypted_dkg_secret, enc_len, encrypted_skey, &dec_len,
            result_str, s_shareG2, pub_keyB, (uint8_t)t, n, ind);
      }
      break;
    }
  }
}

// Workflow 3: Generate BLS key, then Sign/GetPubKey
// Targets: trustedGenerateBLSKey (29%), trustedBlsSignMessage (22%),
//          trustedGetBlsPubKey (33%)
static void harness_bls_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  // Generate BLS key
  int is_exportable = g_fdp->ConsumeIntegralInRange<int>(0, 1);
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_key);
  uint64_t enc_len = 0;
  if (!encrypted_key) return;

  trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string,
                        &is_exportable, encrypted_key, &enc_len);
  if (errStatus != 0 || enc_len == 0) return;

  int op = g_fdp->ConsumeIntegralInRange<int>(0, 1);
  switch (op) {
    case 0: {
      // BlsSignMessage with valid key + fuzzed hash coordinates
      size_t hx_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 64);
      char *hashX = (char *)calloc(hx_len + 1, sizeof(char));
      g_alloc_mgr.push_back((uint8_t *)hashX);
      size_t hy_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 64);
      char *hashY = (char *)calloc(hy_len + 1, sizeof(char));
      g_alloc_mgr.push_back((uint8_t *)hashY);
      char *signature = (char *)calloc(1024, sizeof(char));
      g_alloc_mgr.push_back((uint8_t *)signature);
      if (!hashX || !hashY || !signature) break;
      fill_hex_string(hashX, hx_len);
      fill_hex_string(hashY, hy_len);
      trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                            encrypted_key, enc_len, hashX, hashY, signature);
      break;
    }
    case 1: {
      // GetBlsPubKey with valid key
      char *bls_pub_key = (char *)calloc(320, sizeof(char));
      g_alloc_mgr.push_back((uint8_t *)bls_pub_key);
      if (bls_pub_key) {
        trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string,
                            encrypted_key, enc_len, bls_pub_key);
      }
      break;
    }
  }
}

// Workflow 4: Generate ECDSA key, then CreateBlsKey with fuzzed s_shares
// Targets: trustedCreateBlsKey (11%), trustedCreateBlsKeyV2 (10%)
static void harness_create_bls_key_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  // Generate ECDSA key (needed for session key recovery in CreateBlsKey)
  int is_exportable = 1;
  uint8_t *ecdsa_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)ecdsa_key);
  uint64_t ecdsa_enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_x);
  char *pub_y = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_y);
  if (!ecdsa_key || !pub_x || !pub_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, ecdsa_key, &ecdsa_enc_len,
                          pub_x, pub_y);
  if (errStatus != 0 || ecdsa_enc_len == 0) return;

  // Generate s_shares (blocks of 192 hex chars each)
  int num_shares = g_fdp->ConsumeIntegralInRange<int>(1, 16);
  size_t shares_len = (size_t)192 * num_shares;
  char *s_shares = (char *)calloc(shares_len + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)s_shares);
  if (!s_shares) return;
  fill_hex_string(s_shares, shares_len);

  uint8_t *encr_bls_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encr_bls_key);
  uint64_t enc_bls_key_len = 0;
  if (!encr_bls_key) return;

  if (g_fdp->ConsumeProbability<double>() < 0.5) {
    trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string,
                        s_shares, ecdsa_key, ecdsa_enc_len,
                        encr_bls_key, &enc_bls_key_len);
  } else {
    trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string,
                          s_shares, ecdsa_key, ecdsa_enc_len,
                          encr_bls_key, &enc_bls_key_len);
  }
}

// Workflow 5: Generate ECDSA key, then DkgVerify with fuzzed shares
// Targets: trustedDkgVerify (22%), trustedDkgVerifyV2 (20%)
static void harness_dkg_verify_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  // Generate ECDSA key
  int is_exportable = 1;
  uint8_t *ecdsa_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)ecdsa_key);
  uint64_t ecdsa_enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_x);
  char *pub_y = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_y);
  if (!ecdsa_key || !pub_x || !pub_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, ecdsa_key, &ecdsa_enc_len,
                          pub_x, pub_y);
  if (errStatus != 0 || ecdsa_enc_len == 0) return;

  // Fuzzed public_shares and s_share (hex strings)
  size_t ps_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 512);
  char *public_shares = (char *)calloc(ps_len + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)public_shares);
  if (!public_shares) return;
  fill_hex_string(public_shares, ps_len);

  size_t ss_len = g_fdp->ConsumeIntegralInRange<size_t>(64, 192);
  char *s_share = (char *)calloc(ss_len + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)s_share);
  if (!s_share) return;
  fill_hex_string(s_share, ss_len);

  unsigned _t = g_fdp->ConsumeIntegralInRange<unsigned>(1, 16);
  int _ind = g_fdp->ConsumeIntegralInRange<int>(1, 16);
  int *result = (int *)calloc(1, sizeof(int));
  g_alloc_mgr.push_back((uint8_t *)result);
  if (!result) return;

  if (g_fdp->ConsumeProbability<double>() < 0.5) {
    trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                     public_shares, s_share, ecdsa_key, ecdsa_enc_len,
                     _t, _ind, result);
  } else {
    trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string,
                       public_shares, s_share, ecdsa_key, ecdsa_enc_len,
                       _t, _ind, result);
  }
}

// Workflow 6: Encrypt key then decrypt it
// Targets: trustedEncryptKey (25%), trustedDecryptKey (22%)
static void harness_encrypt_decrypt_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  // Encrypt a fuzzed key string
  size_t key_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 64);
  char *key = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)key);
  if (!key) return;
  fill_hex_string(key, key_len);

  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_key);
  uint64_t enc_len = 0;
  if (!encrypted_key) return;

  trustedEncryptKey(__g_harness_eid, &errStatus, err_string,
                    key, encrypted_key, &enc_len);
  if (errStatus != 0 || enc_len == 0) return;

  // Decrypt the encrypted key
  char *decrypted_key = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)decrypted_key);
  if (decrypted_key) {
    trustedDecryptKey(__g_harness_eid, &errStatus, err_string,
                      encrypted_key, enc_len, decrypted_key);
  }
}

// Workflow 7: DKG V2 workflow - HIGHEST PRIORITY (trustedDkgVerifyV2 is 0/10 edges)
// Targets: trustedDkgVerifyV2 (UNCOVERED), xor_decrypt_v2, hash_key paths
static void harness_dkg_verify_v2_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  // Generate ECDSA key (provides valid encrypted private key)
  int is_exportable = 1;
  uint8_t *ecdsa_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)ecdsa_key);
  uint64_t ecdsa_enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_x);
  char *pub_y = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_y);
  if (!ecdsa_key || !pub_x || !pub_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, ecdsa_key, &ecdsa_enc_len,
                          pub_x, pub_y);
  if (errStatus != 0 || ecdsa_enc_len == 0) return;

  // Fuzzed public_shares and s_share - use mixed hex to trigger error paths
  size_t ps_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 512);
  char *public_shares = (char *)calloc(ps_len + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)public_shares);
  if (!public_shares) return;
  if (g_fdp->ConsumeProbability<double>() < 0.7) {
    fill_hex_string(public_shares, ps_len);
  } else {
    fill_mixed_hex_string(public_shares, ps_len);
  }

  // s_share: must be exactly 192 chars (64 encr_sshare + 64 pubkey_x + 64 pubkey_y)
  // session_key_recover() requires strnlen(sshare, 193) >= 192; shorter strings skip
  // the ECDH path entirely, so fix at 192 to always exercise it.
  size_t ss_len = 192;
  char *s_share = (char *)calloc(ss_len + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)s_share);
  if (!s_share) return;
  fill_hex_string(s_share, ss_len);

  unsigned _t = g_fdp->ConsumeIntegralInRange<unsigned>(1, 16);
  int _ind = g_fdp->ConsumeIntegralInRange<int>(1, 16);
  int *result = (int *)calloc(1, sizeof(int));
  g_alloc_mgr.push_back((uint8_t *)result);
  if (!result) return;

  // ALWAYS call V2 - this is the uncovered function
  trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string,
                     public_shares, s_share, ecdsa_key, ecdsa_enc_len,
                     _t, _ind, result);
}

// Workflow 8: CreateBlsKeyV2 dedicated - V2 path barely covered (2/19 edges)
// Targets: trustedCreateBlsKeyV2, hash_key, xor_decrypt_v2
static void harness_create_bls_key_v2_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  // Generate ECDSA key
  int is_exportable = 1;
  uint8_t *ecdsa_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)ecdsa_key);
  uint64_t ecdsa_enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_x);
  char *pub_y = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_y);
  if (!ecdsa_key || !pub_x || !pub_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, ecdsa_key, &ecdsa_enc_len,
                          pub_x, pub_y);
  if (errStatus != 0 || ecdsa_enc_len == 0) return;

  // Generate s_shares with varied sizes to test boundary conditions
  // Each share block is 192 chars. Vary count 1-16
  int num_shares = g_fdp->ConsumeIntegralInRange<int>(1, 16);
  size_t shares_len = (size_t)192 * num_shares;
  char *s_shares = (char *)calloc(shares_len + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)s_shares);
  if (!s_shares) return;

  // Mix valid and invalid hex to trigger mpz_set_str failure path
  if (g_fdp->ConsumeProbability<double>() < 0.6) {
    fill_hex_string(s_shares, shares_len);
  } else {
    fill_mixed_hex_string(s_shares, shares_len);
  }

  uint8_t *encr_bls_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encr_bls_key);
  uint64_t enc_bls_key_len = 0;
  if (!encr_bls_key) return;

  // ALWAYS call V2
  trustedCreateBlsKeyV2(__g_harness_eid, &errStatus, err_string,
                        s_shares, ecdsa_key, ecdsa_enc_len,
                        encr_bls_key, &enc_bls_key_len);
}

// Workflow 9: GetEncryptedSecretShareV2 dedicated (2/14 edges, hit only once)
// Targets: trustedGetEncryptedSecretShareV2, xor_encrypt_v2, hash_key
static void harness_get_encrypted_secret_share_v2_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  // Generate DKG secret first (provides encrypted_poly)
  uint8_t *encrypted_dkg_secret = (uint8_t *)calloc(3072, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_dkg_secret);
  uint64_t enc_len = 0;
  size_t t = g_fdp->ConsumeIntegralInRange<size_t>(1, 16);
  if (!encrypted_dkg_secret) return;

  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_dkg_secret, &enc_len, t);
  if (errStatus != 0 || enc_len == 0) return;

  // Prepare output buffers
  uint8_t *encrypted_skey = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_skey);
  uint64_t dec_len = 0;
  char *result_str = (char *)calloc(193, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)result_str);
  char *s_shareG2 = (char *)calloc(320, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)s_shareG2);
  if (!encrypted_skey || !result_str || !s_shareG2) return;

  // pub_keyB: fuzzed hex public key
  size_t pk_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 128);
  char *pub_keyB = (char *)calloc(pk_len + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_keyB);
  if (!pub_keyB) return;
  fill_hex_string(pub_keyB, pk_len);

  uint8_t n = g_fdp->ConsumeIntegralInRange<uint8_t>((uint8_t)t, 16);
  if (n < (uint8_t)t) n = (uint8_t)t;
  uint8_t ind = g_fdp->ConsumeIntegralInRange<uint8_t>(1, n > 0 ? n : 1);

  // ALWAYS call V2
  trustedGetEncryptedSecretShareV2(
      __g_harness_eid, &errStatus, err_string,
      encrypted_dkg_secret, enc_len, encrypted_skey, &dec_len,
      result_str, s_shareG2, pub_keyB, (uint8_t)t, n, ind);
}

// Workflow 10 (removed): ECDSA multi-sign was removed because:
// - The enclave is RECREATED each fuzzing iteration, resetting sigCounter to 0 every time.
//   The sigCounter % 1000 path can therefore never be reached.
// - The 1001-iteration loop caused 20+ second per-iteration slowdowns, making LibFuzzer
//   effectively non-functional (LibFuzzer reported "no interesting inputs" after 2 iterations).

// Workflow 11: GetDecryptionShare with valid BLS key (currently 1 hit, 2/6 edges)
// Targets: trustedGetDecryptionShare, getDecryptionShare in DKGUtils
static void harness_decryption_share_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  // Generate BLS key (provides valid encrypted BLS private key)
  int is_exportable = g_fdp->ConsumeIntegralInRange<int>(0, 1);
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_key);
  uint64_t enc_len = 0;
  if (!encrypted_key) return;

  trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string,
                        &is_exportable, encrypted_key, &enc_len);
  if (errStatus != 0 || enc_len == 0) return;

  // public_decryption_value: fuzzed 320-byte hex string (G2 point repr)
  char *pub_dec_val = (char *)calloc(320, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_dec_val);
  char *dec_share = (char *)calloc(320, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)dec_share);
  if (!pub_dec_val || !dec_share) return;

  // Fill with hex - represents a serialized G2 point
  size_t fill_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 319);
  if (g_fdp->ConsumeProbability<double>() < 0.7) {
    fill_hex_string(pub_dec_val, fill_len);
  } else {
    fill_mixed_hex_string(pub_dec_val, fill_len);
  }

  trustedGetDecryptionShare(__g_harness_eid, &errStatus, err_string,
                            encrypted_key, pub_dec_val, enc_len,
                            dec_share);
}

// Workflow 12: Full V2 DKG round-trip - GenSecret -> GetEncryptedSecretShareV2 -> DkgVerifyV2
// Targets: Complete V2 code path end-to-end (all V2 functions in sequence)
static void harness_v2_full_roundtrip(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  // Step 1: Generate DKG poly
  uint8_t *encrypted_poly = (uint8_t *)calloc(3072, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_poly);
  uint64_t poly_enc_len = 0;
  size_t t = g_fdp->ConsumeIntegralInRange<size_t>(1, 8);
  if (!encrypted_poly) return;

  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_poly, &poly_enc_len, t);
  if (errStatus != 0 || poly_enc_len == 0) return;

  // Step 2: GetEncryptedSecretShareV2 (generates ECDSA key internally)
  uint8_t *encrypted_skey = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_skey);
  uint64_t skey_enc_len = 0;
  char *result_str = (char *)calloc(193, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)result_str);
  char *s_shareG2 = (char *)calloc(320, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)s_shareG2);
  if (!encrypted_skey || !result_str || !s_shareG2) return;

  // Generate a fake public key for the peer
  size_t pk_len = 128;
  char *pub_keyB = (char *)calloc(pk_len + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_keyB);
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
  g_alloc_mgr.push_back((uint8_t *)s_share);
  if (!s_share) return;
  memcpy(s_share, result_str, rs_len < 192 ? rs_len : 192);
  s_share[rs_len < 192 ? rs_len : 192] = '\0';

  // Fuzzed public_shares for Verification
  size_t ps_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 256);
  char *public_shares = (char *)calloc(ps_len + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)public_shares);
  if (!public_shares) return;
  fill_hex_string(public_shares, ps_len);

  int *result = (int *)calloc(1, sizeof(int));
  g_alloc_mgr.push_back((uint8_t *)result);
  if (!result) return;

  trustedDkgVerifyV2(__g_harness_eid, &errStatus, err_string,
                     public_shares, s_share, encrypted_skey, skey_enc_len,
                     (unsigned)t, (int)ind, result);
}

// Workflow 13: Dedicated trustedEncryptKey with various key formats
// Targets: trustedEncryptKey (2/8 edges), trustedDecryptKey exportable check
static void harness_encrypt_key_variations(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  // Encrypt with various key formats and lengths
  char *key = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)key);
  if (!key) return;

  int key_type = g_fdp->ConsumeIntegralInRange<int>(0, 3);
  size_t key_len;
  switch (key_type) {
    case 0: // Short key
      key_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 16);
      fill_hex_string(key, key_len);
      break;
    case 1: // Standard ECDSA key length (64 hex chars)
      key_len = 64;
      fill_hex_string(key, key_len);
      break;
    case 2: // Long key (near buffer limit)
      key_len = g_fdp->ConsumeIntegralInRange<size_t>(500, 900);
      fill_hex_string(key, key_len);
      break;
    case 3: // Key with non-hex chars to test error paths
      key_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 128);
      fill_mixed_hex_string(key, key_len);
      break;
  }

  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_key);
  uint64_t enc_len = 0;
  if (!encrypted_key) return;

  trustedEncryptKey(__g_harness_eid, &errStatus, err_string,
                    key, encrypted_key, &enc_len);
  if (errStatus != 0 || enc_len == 0) return;

  // Now decrypt it - tests trustedDecryptKey deeper paths
  char *decrypted_key = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)decrypted_key);
  if (decrypted_key) {
    errStatus = 0;
    trustedDecryptKey(__g_harness_eid, &errStatus, err_string,
                      encrypted_key, enc_len, decrypted_key);
  }
}

// ============================================================================
// Dedicated Bottleneck Harnesses (for completely uncovered functions)
// ============================================================================

// Dedicated: GetPublicEcdsaKey (0/70 edges, completely uncovered)
static void harness_ecdsa_get_pubkey(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  int is_exportable = 1;
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_key);
  uint64_t enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_x);
  char *pub_y = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_y);
  if (!encrypted_key || !pub_x || !pub_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, encrypted_key, &enc_len,
                          pub_x, pub_y);
  if (errStatus != 0 || enc_len == 0) return;

  char *out_x = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)out_x);
  char *out_y = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)out_y);
  if (!out_x || !out_y) return;

  trustedGetPublicEcdsaKey(__g_harness_eid, &errStatus, err_string,
                           encrypted_key, enc_len, out_x, out_y);
}

// Dedicated: EcdsaSign (0/93 edges, completely uncovered)
static void harness_ecdsa_sign_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  int is_exportable = 1;
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_key);
  uint64_t enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_x);
  char *pub_y = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_y);
  if (!encrypted_key || !pub_x || !pub_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, encrypted_key, &enc_len,
                          pub_x, pub_y);
  if (errStatus != 0 || enc_len == 0) return;

  size_t hash_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 64);
  char *hash = (char *)calloc(hash_len + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)hash);
  if (!hash) return;
  fill_hex_string(hash, hash_len);

  char *sig_r = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)sig_r);
  char *sig_s = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)sig_s);
  uint8_t *sig_v = (uint8_t *)calloc(1, sizeof(uint8_t));
  g_alloc_mgr.push_back(sig_v);
  if (!sig_r || !sig_s || !sig_v) return;

  int base = g_fdp->ConsumeIntegralInRange<int>(10, 16);
  trustedEcdsaSign(__g_harness_eid, &errStatus, err_string,
                   encrypted_key, enc_len, hash, sig_r, sig_s, sig_v, base);
}

// Dedicated: GenerateBLSKey standalone (0/70 edges, completely uncovered)
static void harness_bls_generate_standalone(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  int is_exportable = g_fdp->ConsumeIntegralInRange<int>(0, 1);
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_key);
  uint64_t enc_len = 0;
  if (!encrypted_key) return;

  trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string,
                        &is_exportable, encrypted_key, &enc_len);
}

// Dedicated: BlsSignMessage (0/80 edges, completely uncovered)
static void harness_bls_sign_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  int is_exportable = g_fdp->ConsumeIntegralInRange<int>(0, 1);
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_key);
  uint64_t enc_len = 0;
  if (!encrypted_key) return;

  trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string,
                        &is_exportable, encrypted_key, &enc_len);
  if (errStatus != 0 || enc_len == 0) return;

  size_t hx_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 64);
  char *hashX = (char *)calloc(hx_len + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)hashX);
  size_t hy_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 64);
  char *hashY = (char *)calloc(hy_len + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)hashY);
  char *signature = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)signature);
  if (!hashX || !hashY || !signature) return;
  fill_hex_string(hashX, hx_len);
  fill_hex_string(hashY, hy_len);

  trustedBlsSignMessage(__g_harness_eid, &errStatus, err_string,
                        encrypted_key, enc_len, hashX, hashY, signature);
}

// Dedicated: GetBlsPubKey (0/58 edges, completely uncovered)
static void harness_bls_pubkey_workflow(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  int is_exportable = g_fdp->ConsumeIntegralInRange<int>(0, 1);
  uint8_t *encrypted_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_key);
  uint64_t enc_len = 0;
  if (!encrypted_key) return;

  trustedGenerateBLSKey(__g_harness_eid, &errStatus, err_string,
                        &is_exportable, encrypted_key, &enc_len);
  if (errStatus != 0 || enc_len == 0) return;

  char *bls_pub_key = (char *)calloc(320, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)bls_pub_key);
  if (!bls_pub_key) return;

  trustedGetBlsPubKey(__g_harness_eid, &errStatus, err_string,
                      encrypted_key, enc_len, bls_pub_key);
}

// Dedicated: GetPublicShares (0/58 edges, completely uncovered)
static void harness_dkg_get_public_shares(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  uint8_t *encrypted_dkg_secret = (uint8_t *)calloc(3072, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_dkg_secret);
  uint64_t enc_len = 0;
  size_t t = g_fdp->ConsumeIntegralInRange<size_t>(1, 16);
  if (!encrypted_dkg_secret) return;

  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_dkg_secret, &enc_len, t);
  if (errStatus != 0 || enc_len == 0) return;

  char *public_shares = (char *)calloc(10000, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)public_shares);
  if (!public_shares) return;

  trustedGetPublicShares(__g_harness_eid, &errStatus, err_string,
                         encrypted_dkg_secret, enc_len, public_shares,
                         (unsigned)t);
}

// Dedicated: GetEncryptedSecretShare V1 (0/105 edges, completely uncovered)
static void harness_dkg_get_secret_share_v1(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  uint8_t *encrypted_dkg_secret = (uint8_t *)calloc(3072, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_dkg_secret);
  uint64_t enc_len = 0;
  size_t t = g_fdp->ConsumeIntegralInRange<size_t>(1, 16);
  if (!encrypted_dkg_secret) return;

  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_dkg_secret, &enc_len, t);
  if (errStatus != 0 || enc_len == 0) return;

  uint8_t *encrypted_skey = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_skey);
  uint64_t dec_len = 0;
  char *result_str = (char *)calloc(193, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)result_str);
  char *s_shareG2 = (char *)calloc(320, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)s_shareG2);
  // Always 128 chars: gen_session_key requires strnlen(pub_keyB, 128) >= 128.
  // With variable 1-128 and small seeds, FDP exhaustion returns min (1),
  // causing gen_session_key to fail with "pb_keyB is too short" every time.
  char *pub_keyB = (char *)calloc(129, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_keyB);
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
static void harness_create_bls_key_v1_only(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  int is_exportable = 1;
  uint8_t *ecdsa_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)ecdsa_key);
  uint64_t ecdsa_enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_x);
  char *pub_y = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_y);
  if (!ecdsa_key || !pub_x || !pub_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, ecdsa_key, &ecdsa_enc_len,
                          pub_x, pub_y);
  if (errStatus != 0 || ecdsa_enc_len == 0) return;

  int num_shares = g_fdp->ConsumeIntegralInRange<int>(1, 16);
  size_t shares_len = (size_t)192 * num_shares;
  char *s_shares = (char *)calloc(shares_len + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)s_shares);
  if (!s_shares) return;
  fill_hex_string(s_shares, shares_len);

  uint8_t *encr_bls_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encr_bls_key);
  uint64_t enc_bls_key_len = 0;
  if (!encr_bls_key) return;

  trustedCreateBlsKey(__g_harness_eid, &errStatus, err_string,
                      s_shares, ecdsa_key, ecdsa_enc_len,
                      encr_bls_key, &enc_bls_key_len);
}

// Dedicated: DkgVerify V1 (0/80 edges, completely uncovered)
static void harness_dkg_verify_v1_only(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  int is_exportable = 1;
  uint8_t *ecdsa_key = (uint8_t *)calloc(1024, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)ecdsa_key);
  uint64_t ecdsa_enc_len = 0;
  char *pub_x = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_x);
  char *pub_y = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)pub_y);
  if (!ecdsa_key || !pub_x || !pub_y) return;

  trustedGenerateEcdsaKey(__g_harness_eid, &errStatus, err_string,
                          &is_exportable, ecdsa_key, &ecdsa_enc_len,
                          pub_x, pub_y);
  if (errStatus != 0 || ecdsa_enc_len == 0) return;

  size_t ps_len = g_fdp->ConsumeIntegralInRange<size_t>(1, 512);
  char *public_shares = (char *)calloc(ps_len + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)public_shares);
  if (!public_shares) return;
  fill_hex_string(public_shares, ps_len);

  size_t ss_len = 192;
  char *s_share = (char *)calloc(ss_len + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)s_share);
  if (!s_share) return;
  fill_hex_string(s_share, ss_len);

  unsigned _t = g_fdp->ConsumeIntegralInRange<unsigned>(1, 16);
  int _ind = g_fdp->ConsumeIntegralInRange<int>(1, 16);
  int *result = (int *)calloc(1, sizeof(int));
  g_alloc_mgr.push_back((uint8_t *)result);
  if (!result) return;

  trustedDkgVerify(__g_harness_eid, &errStatus, err_string,
                   public_shares, s_share, ecdsa_key, ecdsa_enc_len,
                   _t, _ind, result);
}

// ============================================================================
// Additional Bottleneck Harnesses (DKG entry points)
// ============================================================================

// Standalone: Call trustedGenDkgSecret only (fast, no libff G2 ops)
// This is the minimal DKG entry-point to start covering DKG code paths.
static void harness_gen_dkg_secret_standalone(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  uint8_t *encrypted_dkg_secret = (uint8_t *)calloc(3072, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_dkg_secret);
  uint64_t enc_len = 0;
  if (!encrypted_dkg_secret) return;

  size_t t = g_fdp->ConsumeIntegralInRange<size_t>(1, 16);
  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_dkg_secret, &enc_len, t);
}

// Standalone: Call trustedGenDkgSecret then trustedDecryptDkgSecret
// Covers the decrypt path which is 0/5 edges.
static void harness_decrypt_dkg_secret_standalone(void) {
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;

  uint8_t *encrypted_dkg_secret = (uint8_t *)calloc(3072, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)encrypted_dkg_secret);
  uint64_t enc_len = 0;
  if (!encrypted_dkg_secret) return;

  size_t t = g_fdp->ConsumeIntegralInRange<size_t>(1, 16);
  trustedGenDkgSecret(__g_harness_eid, &errStatus, err_string,
                      encrypted_dkg_secret, &enc_len, t);
  if (errStatus != 0 || enc_len == 0) return;

  uint8_t *decrypted = (uint8_t *)calloc(3072, sizeof(uint8_t));
  g_alloc_mgr.push_back((uint8_t *)decrypted);
  if (!decrypted) return;

  trustedDecryptDkgSecret(__g_harness_eid, &errStatus, err_string,
                          encrypted_dkg_secret, enc_len, decrypted);
}

// ============================================================================
// Customized Initialization
// ============================================================================

// Dedicated: SetSEK workflow (trustedSetSEK has 0/46 edges - never covered)
// trustedSetSEK requires valid sgx_sealed_data_t; random bytes always fail
// sgx_unseal_data(). Uses g_sealed_sek_buf saved by preamble from trustedGenerateSEK
// or trustedSetSEKBackup. trustedSetSEK has its OWN CALL_ONCE counter (separate from
// trustedGenerateSEK's), so the first call to trustedSetSEK each iteration proceeds.
// SGX sealing uses SGX_KEYPOLICY_MRENCLAVE: same binary can unseal across instances.
static void harness_set_sek_workflow(void) {
  if (g_sealed_sek_len == 0) return;
  int errStatus = 0;
  char *err_string = (char *)calloc(1024, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)err_string);
  if (!err_string) return;
  trustedSetSEK(__g_harness_eid, &errStatus, err_string, g_sealed_sek_buf);
}

extern "C" void customized_init() {
  // ========================================================================
  // IMPORTANT: Order matters for small-seed coverage!
  //
  // ConsumeIntegralInRange<int>(0, total_weight-1) with total_weight=N consumes
  // ceil(log2(N)/8) bytes from seed. With 1-byte seeds (most of corpus), only
  // values 0-255 are produced. So harnesses with cumulative weight 0-255 are
  // the ONLY ones reachable with 1-byte seeds.
  //
  // Strategy: put the most important UNCOVERED functions FIRST in the registry
  // so that even 1-byte seeds select them.
  //
  // DKG functions are completely uncovered (0/N edges) because previous order
  // put them at cumulative positions 641-840, unreachable with 1-byte seeds.
  // ========================================================================

  // ========================================================================
  // Tier 1: DKG functions (0/N edges, completely uncovered) - MUST BE FIRST
  // These are reachable with 1-byte seeds (cumulative 0-299).
  // trustedGenDkgSecret, trustedDecryptDkgSecret, trustedGetPublicShares,
  // trustedGetEncryptedSecretShare (and V2), trustedSetEncryptedDkgPoly
  // ========================================================================

  // trustedGenDkgSecret (0/7 edges): standalone, fast (no libff G2 ops)
  test_harness_registry[test_harness_count++] = {harness_gen_dkg_secret_standalone, 100};

  // trustedGetPublicShares (0/7 edges): needs trustedGenDkgSecret first
  test_harness_registry[test_harness_count++] = {harness_dkg_get_public_shares, 100};

  // trustedGetEncryptedSecretShare (0/13 edges): needs trustedGenDkgSecret + pub_keyB
  test_harness_registry[test_harness_count++] = {harness_dkg_get_secret_share_v1, 100};

  // trustedDecryptDkgSecret (0/5 edges): gen then decrypt
  test_harness_registry[test_harness_count++] = {harness_decrypt_dkg_secret_standalone, 80};

  // trustedDkgVerifyV2 (0/10 edges): needs ECDSA key
  test_harness_registry[test_harness_count++] = {harness_dkg_verify_v2_workflow, 80};

  // trustedCreateBlsKeyV2 (0/19 edges): needs ECDSA key + shares
  test_harness_registry[test_harness_count++] = {harness_create_bls_key_v2_workflow, 80};

  // GetEncryptedSecretShareV2 (0/14 edges): needs trustedGenDkgSecret + pub_keyB
  test_harness_registry[test_harness_count++] = {harness_get_encrypted_secret_share_v2_workflow, 80};

  // Full V2 roundtrip: GenSecret → GetEncryptedSecretShareV2 → DkgVerifyV2
  test_harness_registry[test_harness_count++] = {harness_v2_full_roundtrip, 60};

  // DKG workflow: GenDkgSecret → Decrypt/GetPubShares/GetEncryptedSecretShare
  test_harness_registry[test_harness_count++] = {harness_dkg_workflow, 40};

  // ========================================================================
  // Tier 2: ECDSA/BLS functions (partial coverage, need valid keys) - positions 800+
  // Reachable with 2-byte seeds.
  // ========================================================================

  // ECDSA: GetPublicEcdsaKey (3/11), EcdsaSign (3/13)
  test_harness_registry[test_harness_count++] = {harness_ecdsa_get_pubkey, 30};
  test_harness_registry[test_harness_count++] = {harness_ecdsa_sign_workflow, 30};

  // BLS: GenerateBLSKey (6/15), BlsSignMessage (2/6), GetBlsPubKey (2/6)
  test_harness_registry[test_harness_count++] = {harness_bls_generate_standalone, 30};
  test_harness_registry[test_harness_count++] = {harness_bls_sign_workflow, 30};
  test_harness_registry[test_harness_count++] = {harness_bls_pubkey_workflow, 30};
  test_harness_registry[test_harness_count++] = {harness_decryption_share_workflow, 30};

  // CreateBlsKey V1 (5/18 edges): needs ECDSA key + shares
  test_harness_registry[test_harness_count++] = {harness_create_bls_key_v1_only, 30};

  // DkgVerify V1 (2/9 edges): needs ECDSA key
  test_harness_registry[test_harness_count++] = {harness_dkg_verify_v1_only, 30};

  // ========================================================================
  // Tier 3: Additional coverage paths - medium weight
  // ========================================================================

  // SetSEK (16/46 edges in sgx wrapper): valid sealed data from preamble
  test_harness_registry[test_harness_count++] = {harness_set_sek_workflow, 20};

  // EncryptKey/DecryptKey variations
  test_harness_registry[test_harness_count++] = {harness_encrypt_key_variations, 20};
  test_harness_registry[test_harness_count++] = {harness_encrypt_decrypt_workflow, 15};

  // Multi-op workflows
  test_harness_registry[test_harness_count++] = {harness_ecdsa_workflow, 10};
  test_harness_registry[test_harness_count++] = {harness_bls_workflow, 10};
  test_harness_registry[test_harness_count++] = {harness_create_bls_key_workflow, 5};
  test_harness_registry[test_harness_count++] = {harness_dkg_verify_workflow, 5};

  // ========================================================================
  // Tier 4: Auto-generated harnesses at low weight (error path coverage)
  // ========================================================================

  test_harness_registry[test_harness_count++] = {_harness_trustedGenerateEcdsaKey, 3};
  test_harness_registry[test_harness_count++] = {_harness_trustedEncryptKey, 3};
  test_harness_registry[test_harness_count++] = {_harness_trustedGenDkgSecret, 3};
  test_harness_registry[test_harness_count++] = {_harness_trustedGenerateBLSKey, 3};

  test_harness_registry[test_harness_count++] = {_harness_trustedGetPublicEcdsaKey, 2};
  test_harness_registry[test_harness_count++] = {_harness_trustedEcdsaSign, 2};
  test_harness_registry[test_harness_count++] = {_harness_trustedDecryptKey, 2};
  test_harness_registry[test_harness_count++] = {_harness_trustedDecryptDkgSecret, 2};
  test_harness_registry[test_harness_count++] = {_harness_trustedGetEncryptedSecretShare, 2};
  test_harness_registry[test_harness_count++] = {_harness_trustedGetEncryptedSecretShareV2, 2};
  test_harness_registry[test_harness_count++] = {_harness_trustedGetPublicShares, 2};
  test_harness_registry[test_harness_count++] = {_harness_trustedDkgVerify, 2};
  test_harness_registry[test_harness_count++] = {_harness_trustedDkgVerifyV2, 2};
  test_harness_registry[test_harness_count++] = {_harness_trustedCreateBlsKey, 2};
  test_harness_registry[test_harness_count++] = {_harness_trustedCreateBlsKeyV2, 2};
  test_harness_registry[test_harness_count++] = {_harness_trustedBlsSignMessage, 2};
  test_harness_registry[test_harness_count++] = {_harness_trustedGetBlsPubKey, 2};
  test_harness_registry[test_harness_count++] = {_harness_trustedGetDecryptionShare, 2};

  // ========================================================================
  // Step 5: Calculate total weight
  // ========================================================================

  if (test_harness_count == 0) {
    fprintf(stderr, "[!] Error: No test harnesses registered\n");
    abort();
  }

  total_weight = 0;
  for (unsigned int i = 0; i < test_harness_count; i++) {
    total_weight += test_harness_registry[i].weight;
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
  // ========================================================================
  // Step 1: Initialize the enclave (required for all operations)
  // Sets up curve, GMP memory functions, globalRandom
  // CRITICAL: Use fixed logLevel=0 to avoid consuming fuzz data.
  // Previous bug: fuzz data was consumed here, leaving nothing for harnesses.
  // ========================================================================
  trustedEnclaveInit(__g_harness_eid, 0);

  // ========================================================================
  // Step 2: Set up SEK (required for AES operations)
  // Alternate between trustedGenerateSEK and trustedSetSEKBackup using a
  // static counter instead of consuming fuzz data for the decision.
  // Previous bug: ConsumeProbability<double>() consumed ~8 bytes from a
  // 6-byte max input, exhausting all fuzz data before harness selection.
  // ========================================================================
  static unsigned long sek_counter = 0;
  sek_counter++;
  {
    int errStatus = 0;
    char *err_string = (char *)calloc(1024, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)err_string);
    uint8_t *encrypted_SEK = (uint8_t *)calloc(1024, sizeof(uint8_t));
    g_alloc_mgr.push_back((uint8_t *)encrypted_SEK);
    uint64_t enc_len = 0;

    if (err_string && encrypted_SEK) {
      if (sek_counter % 3 != 0) {
        // Path A: Generate random SEK (67% of iterations)
        char *hex_SEK = (char *)calloc(65, sizeof(char));
        g_alloc_mgr.push_back((uint8_t *)hex_SEK);
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
        g_alloc_mgr.push_back((uint8_t *)sek_hex);
        if (sek_hex) {
          // Use deterministic hex key - no fuzz data consumption
          memcpy(sek_hex, "aabbccdd11223344aabbccdd11223344", 32);
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

  // ========================================================================
  // Step 3: Weighted random selection of ONE test harness
  // ALL fuzz data is now available for the actual harness function.
  // Previous bug: remaining_bytes() < 4 caused early return with 6-byte
  // inputs after preamble consumed all data. Now preamble uses 0 bytes.
  // Single harness call per iteration (no loop) because with small inputs,
  // the harness needs all available data.
  // ========================================================================
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
