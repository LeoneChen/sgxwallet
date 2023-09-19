#!/bin/bash
set -e

for ARG in "$@"
do
   KEY="$(echo $ARG | cut -f1 -d=)"
   VAL="$(echo $ARG | cut -f2 -d=)"
   export "$KEY"="$VAL"
done

SGXSDK_DIR=$(realpath ../../install)

MODE=${MODE:="RELEASE"}

echo "-- MODE: ${MODE}"

if [[ "${MODE}" = "DEBUG" ]]
then
    DEBUG_FLAG=" -O0 -g"
else
    DEBUG_FLAG=" -O2"
fi

./configure --with-sgxsdk=${SGXSDK_DIR} --enable-sgx-simulation CFLAGS="${DEBUG_FLAG}" CXXFLAGS="${DEBUG_FLAG}" CC=clang-13 CXX=clang++-13

make -j$(nproc)
