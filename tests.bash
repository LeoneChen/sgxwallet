#!/bin/bash
set -e
./testw [bls-key-encrypt]
./testw [bls-key-encrypt-decrypt]
./testw [dkg-gen]
./testw [dkg-pub_shares]
#./testw [dkg-encr_sshares]
./testw [dkg-verify]
./testw [ecdsa_test]
./testw [test_test]
./testw [get_pub_ecdsa_key_test]
./testw [bls_dkg]
./testw [api_test]
./testw [getServerStatus_test]
./testw [many_threads_test]
./testw [ecdsa_api_test]
./testw [dkg_api_test]
./testw [is_poly_test]
./testw [aes_dkg]
#./testw [bls_sign]
./testw [AES-encrypt-decrypt]

