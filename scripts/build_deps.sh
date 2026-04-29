#!/usr/bin/env bash
set -e

ENABLE_ASAN=0  # 默认不插桩，--asan 开启

# 解析参数
OPTS=$(getopt -o '' -l asan -n 'build_deps.sh' -- "$@")
eval set -- "$OPTS"
while true; do
    case "$1" in
        --asan) ENABLE_ASAN=1; shift ;;
        --) shift; break ;;
        *) break ;;
    esac
done

cd "$(dirname "$0")/.."
TOP_DIR=$(pwd)
echo "Starting build"
echo "Top directory is: $TOP_DIR"

SCRIPTS_DIR="$TOP_DIR/scripts"
GMP_DIR="$TOP_DIR/sgx-gmp"
ZMQ_DIR="$TOP_DIR/libzmq"
ZMQ_BUILD_DIR="$ZMQ_DIR/build"
LEVELDB_DIR="$TOP_DIR/leveldb"
LEVELDB_BUILD_DIR="$LEVELDB_DIR/build"
GMP_BUILD_DIR="$TOP_DIR/gmp-build"
TGMP_BUILD_DIR="$TOP_DIR/tgmp-build"
SDK_DIR="$TOP_DIR/sgx-sdk-build"
JSON_LIBS_DIR="$TOP_DIR/jsonrpc"
BLS_DIR="$TOP_DIR/libBLS"

echo "Cleaning"
rm -f install-sh compile missing depcomp
rm -rf "$GMP_BUILD_DIR" "$TGMP_BUILD_DIR" "$SDK_DIR"

cp configure.gmp "$GMP_DIR/configure"

echo "Build LibBLS"
cd "$BLS_DIR/deps" && DEBUG=0 ./build.sh
cd "$BLS_DIR" && cmake -H. -Bbuild -DBUILD_TESTS=OFF
cd "$BLS_DIR/build" && make -j$(nproc)

echo "Build ZMQ"
mkdir -p "$ZMQ_BUILD_DIR"
cd "$ZMQ_BUILD_DIR" && cmake -DDZMQ_EXPERIMENTAL=1 -DCMAKE_BUILD_TYPE=Release .. && cmake --build . -j$(nproc)

echo "Build LevelDB"
mkdir -p "$LEVELDB_BUILD_DIR"
cd "$LEVELDB_BUILD_DIR" && cmake -DCMAKE_BUILD_TYPE=Release .. && cmake --build . -j$(nproc)

echo "Build JSON"
cd "$JSON_LIBS_DIR" && DEBUG=0 ./build.sh

echo "Install Linux SDK"
cd "$SCRIPTS_DIR" && ./sgx_linux_x64_sdk_2.25.100.3.bin --prefix="$SDK_DIR"

echo "Make GMP"
cd "$GMP_DIR"
# Configure without instrumentation flags: configure runs test programs on the host,
# and -asan-enclave-v remaps shadow memory for SGX which crashes host processes.
# The instrumentation flags are injected at make time instead (automake always appends
# user CFLAGS after per-target _CFLAGS in the compile command).
if [ $ENABLE_ASAN -eq 1 ]; then
    INST_FLAGS="-Og -g -fsanitize=address -mllvm -asan-enclave-v -mllvm -asan-use-after-return=never -mllvm -asan-opt-globals=false -fsanitize-coverage=inline-8bit-counters,pc-table"
    GMP_CC="${TOP_DIR}/../../install/llvm-project/bin/clang"
    GMP_CXX="${TOP_DIR}/../../install/llvm-project/bin/clang++"
else
    INST_FLAGS="-Og -g"
    GMP_CC="gcc"
    GMP_CXX="g++"
fi
./configure --prefix="$TGMP_BUILD_DIR" --disable-shared --enable-static --with-pic \
    --enable-sgx --with-sgxsdk="$SDK_DIR/sgxsdk" CC="$GMP_CC" CXX="$GMP_CXX"
make install -j$(nproc) CFLAGS="$INST_FLAGS" CXXFLAGS="$INST_FLAGS"
make clean

./configure --prefix="$GMP_BUILD_DIR" --disable-shared --enable-static --with-pic \
    --with-sgxsdk="$SDK_DIR/sgxsdk"
make install -j$(nproc)
make clean

cd "$TOP_DIR"
cp third_party/gmp/sgx_tgmp.h.fixed "$TGMP_BUILD_DIR/include/sgx_tgmp.h"

echo "Build successful."
