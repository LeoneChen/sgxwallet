#pragma once

static void harness_trustedEnclaveInit(void) {
    uint64_t logLevel = g_fdp->ConsumeIntegralInRange<uint64_t>(0, 5);
    trustedEnclaveInit(__g_harness_eid, logLevel);
}

// DISABLED: redundant with customized_harness() which already calls trustedEnclaveInit every iteration
// HARNESS_REGISTER(harness_trustedEnclaveInit, 30)
