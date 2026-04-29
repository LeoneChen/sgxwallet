// EnclaveFuzz harness.cpp — 方便在测试每个 app 时管理 harness 函数
//
// 用法：
//   - 每个 harness 函数写在 harness_fns/<name>.h 里，并在头文件末尾用
//     HARNESS_REGISTER(fn, weight) 注册。
//   - 本文件 #include "harness_fns/<name>.h" 这些头，linker 就会触发静态初始化完成自动注册。
//   - harness 函数可以使用：
//       HARNESS_REGISTER(fn, weight)           注册 harness 函数 fn（weight 决定被选中的概率，初始值 50）
//       g_fdp                          FuzzedDataProvider* 类型，消费 fuzz 数据
//       __g_harness_eid                sgx_enclave_id_t 类型，是调用 ECall 时传入的 enclave id
//
// 示例：harness_fns/harness_xxx.h
//   #pragma once
//   static void harness_xxx(void) {
//       size_t len = g_fdp->ConsumeIntegralInRange<size_t>(0, 4096);
//       uint8_t *buf = (uint8_t *)calloc(1, len);
//       if (buf && len > 0) g_fdp->ConsumeData(buf, len);
//       ecall_xxx(__g_harness_eid, buf, len);
//   }
//   HARNESS_REGISTER(harness_xxx, 50)
//
// 详情见 enclavefuzz-skill/references/harness_cookbook.md。
//
// 注意：我们将 calloc/malloc/free 重定向到了基于我们的缓冲区的 arena allocator，避免 enclave 越界访问 host app 的 glibc 版本的堆内存，因为我们只关心 enclave 内的内存访问安全问题，不关心也不希望 host 本身被 host 的测试所破坏。

#include "harness_framework.h" // 引入所需的声明和宏定义

// ---- TODO (bootstrap) ----
// 1. 引入 EDL untrusted 头：#include "<edl_basename>_u.h"
// 2. 引入 harness_fns/ 各文件：#include "harness_fns/harness_xx.h"
// 3. 引入 ocall 维度的测试：#include "harness_fns/ocall_wrappers.h"
