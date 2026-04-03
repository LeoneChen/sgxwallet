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

