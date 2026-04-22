/*
 * EnclaveFuzz - SGX Enclave Fuzzing Test Harness
 *
 * Generated for EDL: <EDL_FILENAME>
 * For EDL attribute reference, fuzzing strategies, and harness patterns,
 * see: EnclavePatch-Data/skills/enclavefuzz/references/harness_cookbook.md
 *
 * ============================================================================
 * Fuzzing Framework Architecture
 * ============================================================================
 *
 * Initialization (once):
 *     Static initializers (HARNESS_REGISTER macros) run before main(),
 *     populating test_harness_registry[] automatically.
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
 * Adding a Harness
 * ============================================================================
 *   1. Create harness_fns/harness_new_fn.h with function + HARNESS_REGISTER
 *   2. Add #include "harness_fns/harness_new_fn.h" below
 *
 * ============================================================================
 */

#include "FuzzedDataProvider.h"
// TODO (bootstrap): Replace with the APP-specific untrusted header.
// Derived from EDL_PATH basename: e.g. secure_enclave.edl → secure_enclave_u.h
// #include "<edl_basename>_u.h"
#include <sgx_urts.h>
#include <stdint.h>
#include <inttypes.h>
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

// ============================================================================
// Global Variables
// ============================================================================

extern FuzzedDataProvider *g_fdp;
extern sgx_enclave_id_t __g_harness_eid;

//============================================================================
// Test Harness Registration System
// ============================================================================

typedef void (*TestHarness)(void);

struct TestHarnessEntry {
  TestHarness function;
  int weight; // Selection weight (default: 50)
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
// Harness Includes
// ============================================================================
// TODO (bootstrap): Uncomment / add #include lines as harness_fns/ files are
// created. OCall wrappers first, then ECall harnesses in any order.
// ============================================================================
// #include "harness_fns/ocall_wrappers.h"
// #include "harness_fns/harness_ecall_foo.h"


// ============================================================================
// Main Test Entry Point
// ============================================================================
// Called by LLVMFuzzerTestOneInput for each fuzzing iteration.
// ============================================================================

extern "C" void customized_harness(void) {
  if (test_harness_count == 0) { fprintf(stderr, "[!] No harnesses registered\n"); abort(); }
  if (total_weight == 0) { fprintf(stderr, "[!] All harness weights are 0\n"); abort(); }
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
