#!/bin/bash
set -e

./configure

make -j$(nproc)
# ~/SGXSan/Tool/GetLayout.sh secure_enclave_t.o secure_enclave.o Curves.o NumberTheory.o Point.o Signature.o DHDkg.o HKDF.o AESUtils.o DKGUtils.o TEUtils.o EnclaveCommon.o DomainParameters.o alt_bn128_init.o alt_bn128_g2.o alt_bn128_g1.o