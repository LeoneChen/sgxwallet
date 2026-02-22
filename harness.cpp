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
// Customized Initialization
// ============================================================================
// This function is called once during fuzzer initialization
// (LLVMFuzzerInitialize).
//
// REQUIRED: Register all test harnesses by filling test_harness_registry[]
//
// Usage:
//   test_harness_registry[test_harness_count++] = {harness_function, weight};
//
// IMPORTANT:
// - This function is called BEFORE any fuzzing iterations start
// - DO NOT create or initialize the enclave here (__g_harness_eid will be 0)
// - DO NOT access g_fdp here (it's not initialized yet)
// - Keep initialization lightweight and fast
// - Weight MUST be > 0 for all harnesses
//
// Optional: Add custom initialization such as:
// - Environment variable configuration (setenv, putenv)
// - Global state initialization
// - Logging/debugging setup
// - Resource pre-allocation
// - Configuration file loading
// ============================================================================

extern "C" void customized_init() {
  // ========================================================================
  // Step 1: Register all test harnesses
  // ========================================================================
  test_harness_registry[test_harness_count++] = {_harness_trustedEnclaveInit,
                                                 10}; // Test trustedEnclaveInit
  test_harness_registry[test_harness_count++] = {_harness_trustedGenerateSEK,
                                                 10}; // Test trustedGenerateSEK
  test_harness_registry[test_harness_count++] = {_harness_trustedSetSEK,
                                                 10}; // Test trustedSetSEK
  test_harness_registry[test_harness_count++] = {
      _harness_trustedSetSEKBackup, 10}; // Test trustedSetSEKBackup
  test_harness_registry[test_harness_count++] = {
      _harness_trustedGenerateEcdsaKey, 10}; // Test trustedGenerateEcdsaKey
  test_harness_registry[test_harness_count++] = {
      _harness_trustedGetPublicEcdsaKey, 10}; // Test trustedGetPublicEcdsaKey
  test_harness_registry[test_harness_count++] = {_harness_trustedEcdsaSign,
                                                 10}; // Test trustedEcdsaSign
  test_harness_registry[test_harness_count++] = {_harness_trustedEncryptKey,
                                                 10}; // Test trustedEncryptKey
  test_harness_registry[test_harness_count++] = {_harness_trustedDecryptKey,
                                                 10}; // Test trustedDecryptKey
  test_harness_registry[test_harness_count++] = {
      _harness_trustedGenDkgSecret, 10}; // Test trustedGenDkgSecret
  test_harness_registry[test_harness_count++] = {
      _harness_trustedDecryptDkgSecret, 10}; // Test trustedDecryptDkgSecret
  test_harness_registry[test_harness_count++] = {
      _harness_trustedGetEncryptedSecretShare,
      10}; // Test trustedGetEncryptedSecretShare
  test_harness_registry[test_harness_count++] = {
      _harness_trustedGetEncryptedSecretShareV2,
      10}; // Test trustedGetEncryptedSecretShareV2
  test_harness_registry[test_harness_count++] = {
      _harness_trustedGetPublicShares, 10}; // Test trustedGetPublicShares
  test_harness_registry[test_harness_count++] = {_harness_trustedDkgVerify,
                                                 10}; // Test trustedDkgVerify
  test_harness_registry[test_harness_count++] = {_harness_trustedDkgVerifyV2,
                                                 10}; // Test trustedDkgVerifyV2
  test_harness_registry[test_harness_count++] = {
      _harness_trustedCreateBlsKey, 10}; // Test trustedCreateBlsKey
  test_harness_registry[test_harness_count++] = {
      _harness_trustedCreateBlsKeyV2, 10}; // Test trustedCreateBlsKeyV2
  test_harness_registry[test_harness_count++] = {
      _harness_trustedBlsSignMessage, 10}; // Test trustedBlsSignMessage
  test_harness_registry[test_harness_count++] = {
      _harness_trustedGetBlsPubKey, 10}; // Test trustedGetBlsPubKey
  test_harness_registry[test_harness_count++] = {
      _harness_trustedGetDecryptionShare, 10}; // Test trustedGetDecryptionShare
  test_harness_registry[test_harness_count++] = {
      _harness_trustedGenerateBLSKey, 10}; // Test trustedGenerateBLSKey

  // ========================================================================
  // Step 2: Calculate total weight for weighted random selection
  // ========================================================================

  // Sanity check: ensure at least one harness is registered
  if (test_harness_count == 0) {
    fprintf(stderr, "[!] Error: No test harnesses registered\n");
    abort();
  }

  total_weight = 0;
  for (unsigned int i = 0; i < test_harness_count; i++) {
    total_weight += test_harness_registry[i].weight;
  }

  // Sanity check: ensure total weight > 0
  if (total_weight == 0) {
    fprintf(stderr, "[!] Error: All harness weights are 0\n");
    abort();
  }

  // ========================================================================
  // Step 3: Custom initialization (optional)
  // ========================================================================
  // Examples:
  // - setenv("SGX_AESM_ADDR", "1", 1);
  // - freopen("/tmp/fuzzer.log", "w", stderr);
  // - Initialize global variables
  // - Pre-load configuration files
}

// ============================================================================
// Main Test Entry Point
// ============================================================================
// Called by LLVMFuzzerTestOneInput for each fuzzing iteration
// Performs weighted random selection of test harnesses
// ============================================================================

extern "C" void customized_harness(void) {
  // Weighted random selection
  do {
    int rand_val = g_fdp->ConsumeIntegralInRange<int>(0, total_weight - 1);
    int cumulative = 0;
    for (unsigned int i = 0; i < test_harness_count; i++) {
      cumulative += test_harness_registry[i].weight;
      if (rand_val < cumulative) {
        test_harness_registry[i].function();
        break;
      }
    }
  } while (g_fdp->remaining_bytes() > 0);
}
