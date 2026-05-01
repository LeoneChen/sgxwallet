// EnclaveFuzz harness.cpp — sgxwallet
//
// 框架提供：HARNESS_REGISTER 宏、registry、g_fdp、__g_harness_eid、arena allocator
// 本文件只负责：
//   1. 引入 EDL untrusted 头
//   2. 定义 pre_harness_init()（agent 可修改的全局初始化）
//   3. 定义全局变量（供 harness 共享）
//   4. 引入 harness_fns/*.h 完成注册
//
// 注意：agent 不可修改 customized_harness()（由框架 test.cpp 提供）

#include "harness_framework.h"
#include "secure_enclave_u.h"

// ============================================================================
// pre_harness_init() — enclave 级初始化
//
// 注意：框架每轮输入都会重建 enclave，enclave 内全局变量（curve、SEK 等）
// 都是新的。本函数只负责调用 trustedEnclaveInit 初始化 curve。
//
// 原则：harness 之间不共享宿主机全局状态，每个 harness 自给自足。
// ============================================================================

static void pre_harness_init(void) {
  // 每轮新 enclave，必须重新初始化 curve
  trustedEnclaveInit(__g_harness_eid, 1);
}

// ============================================================================
// Harness Includes（注册顺序 = 选择顺序）
// ============================================================================

#include "harness_fns/ocall_wrappers.h"
#include "harness_fns/harness_ecall_sek.h"
#include "harness_fns/harness_micro.h"
#include "harness_fns/harness_dkg_utils.h"
#include "harness_fns/harness_success_paths.h"
#include "harness_fns/harness_error_paths.h"
#include "harness_fns/harness_ecall_init.h"
#include "harness_fns/harness_ecall_ecdsa.h"
#include "harness_fns/harness_ecall_encrypt.h"
#include "harness_fns/harness_ecall_dkg.h"
#include "harness_fns/harness_ecall_bls.h"
#include "harness_fns/harness_workflow.h"
#include "harness_fns/harness_edge_cases.h"
