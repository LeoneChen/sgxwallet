#pragma once

// ============================================================================
// OCall Wrappers
// ============================================================================
// These wrappers intercept OCalls and fuzz [out] parameters
// to test Enclave's resilience to untrusted data.
// Each wrapper is auto-linked by SGX via function name; no registration needed.
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
