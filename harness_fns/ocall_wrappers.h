#pragma once

// OCall wrappers for sgxwallet
// Weak symbol names from secure_enclave_u.c:
//   _harness_oc_realloc, _harness_oc_printf, _harness_oc_free

#include <stdlib.h>

extern "C" uint64_t _harness_oc_realloc(void* optr, size_t osz, size_t nsz) {
    (void)osz;
    if (nsz == 0) {
        if (optr && (uint64_t)optr > 0x1000) {
            free(optr);
        }
        return 0;
    }
    if (!optr || (uint64_t)optr < 0x1000) {
        // NULL or legacy fake pointer from old wrapper - allocate fresh
        void* ptr = malloc(nsz);
        return ptr ? (uint64_t)ptr : 0;
    }
    void* ptr = realloc(optr, nsz);
    return ptr ? (uint64_t)ptr : 0;
}

extern "C" void _harness_oc_printf(const char* str) {
    (void)str;
    // No-op
}

extern "C" void _harness_oc_free(void* optr, size_t sz) {
    (void)sz;
    if (optr && (uint64_t)optr > 0x1000) {
        free(optr);
    }
}
