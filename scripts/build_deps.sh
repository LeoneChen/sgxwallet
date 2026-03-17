#!/usr/bin/env bash
set -e

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
./configure --prefix="$TGMP_BUILD_DIR" --disable-shared --enable-static --with-pic \
    --enable-sgx --with-sgxsdk="$SDK_DIR/sgxsdk" CFLAGS="-Og -g" CXXFLAGS="-Og -g"
make install -j$(nproc)
make clean

./configure --prefix="$GMP_BUILD_DIR" --disable-shared --enable-static --with-pic \
    --with-sgxsdk="$SDK_DIR/sgxsdk"
make install -j$(nproc)
make clean

cd "$TOP_DIR"
cp third_party/gmp/sgx_tgmp.h.fixed "$TGMP_BUILD_DIR/include/sgx_tgmp.h"

echo "Build successful."
