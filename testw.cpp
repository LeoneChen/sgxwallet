/*

Copyright 2018 Intel Corporation

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include <sgx_tgmp.h>
#include <sgx_trts.h>

#include "sgxwallet_common.h"
#include "create_enclave.h"
#include "secure_enclave_u.h"
#include "sgx_detect.h"
#include <gmp.h>
#include <sgx_urts.h>


#include "BLSCrypto.h"



#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/exponentiation/exponentiation.hpp>


#include <libff/algebra/fields/fp.hpp>

#include <dkg/dkg.h>

#define ENCLAVE_NAME "secure_enclave.signed.so"


#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "catch.hpp"

void usage() {
  fprintf(stderr, "usage: sgxwallet\n");
  exit(1);
}

sgx_launch_token_t token = {0};
sgx_enclave_id_t eid;
sgx_status_t status;
int updated;


std::string stringFromFr(libff::alt_bn128_Fr& el) {

    mpz_t t;
    mpz_init(t);

    el.as_bigint().to_mpz(t);

    char arr[mpz_sizeinbase(t, 10) + 2];

    char *tmp = mpz_get_str(arr, 10, t);
    mpz_clear(t);

    return std::string(tmp);
}


TEST_CASE( "BLS sign test", "[bls-sign]" ) {

  init_all();

  const char *key = "4160780231445160889237664391382223604184857153814275770598"
                    "791864649971919844";

  char* keyArray = (char*) calloc(128, 1);

  uint8_t* encryptedKey = (uint8_t*) calloc(1024, 1);

  char* errMsg = (char*) calloc(1024,1);

  strncpy((char *)keyArray, (char*)key, 128);

  int err_status = 0;

  unsigned  int enc_len = 0;

  status = encrypt_key(eid, &err_status, errMsg, keyArray, encryptedKey, &enc_len);

  REQUIRE(status == SGX_SUCCESS);

  printf("Encrypt key completed with status: %d %s \n", err_status, errMsg);
  printf(" Encrypted key len %d\n", enc_len);



  char result[2* BUF_LEN];

  carray2Hex(encryptedKey, enc_len, result);

  uint64_t dec_len = 0;

  uint8_t bin[BUF_LEN];

  REQUIRE(hex2carray(result, &dec_len, bin));

  for (uint64_t i=0; i < dec_len; i++) {
    REQUIRE(bin[i] == encryptedKey[i]);
  }

  REQUIRE(dec_len == enc_len);

  printf("Result: %s", result);

  printf("\n Length: %d \n", enc_len);
}


TEST_CASE( "DKG gen test", "[dkg-gen]" ) {

  init_all();

  uint8_t* encrypted_dkg_secret = (uint8_t*) calloc(DKG_MAX_SEALED_LEN, 1);

  char* errMsg = (char*) calloc(1024,1);
  int err_status = 0;
  uint32_t enc_len = 0;

  status = gen_dkg_secret (eid, &err_status, errMsg, encrypted_dkg_secret, &enc_len, 16);
  REQUIRE(status == SGX_SUCCESS);
  printf("gen_dkg_secret completed with status: %d %s \n", err_status, errMsg);
  printf("\n Length: %d \n", enc_len);

  char* secret = (char*)calloc(DKG_MAX_SEALED_LEN, sizeof(char));

  char* errMsg1 = (char*) calloc(1024,1);

  status = decrypt_dkg_secret(eid, &err_status, errMsg1, encrypted_dkg_secret, (uint8_t*)secret, enc_len);
  REQUIRE(status == SGX_SUCCESS);

  printf("\ndecrypt_dkg_secret completed with status: %d %s \n", err_status, errMsg1);
  printf("decrypted secret %s \n\n", secret);

  free(errMsg);
  free(errMsg1);
  free(encrypted_dkg_secret);
  free(secret);
}

std::vector<libff::alt_bn128_Fr> SplitStringToFr(const char* koefs, const char* symbol){
  std::string str(koefs);
  std::string delim(symbol);
  std::vector<libff::alt_bn128_Fr> tokens;
  size_t prev = 0, pos = 0;
  do
  {
    pos = str.find(delim, prev);
    if (pos == std::string::npos) pos = str.length();
    std::string token = str.substr(prev, pos-prev);
    if (!token.empty()) {
      libff::alt_bn128_Fr koef(token.c_str());
      tokens.push_back(koef);
    }
    prev = pos + delim.length();
  }
  while (pos < str.length() && prev < str.length());

  return tokens;
}

TEST_CASE( "DKG auto secret shares test", "[dkg-s_shares]" ) {

  init_all();

  uint8_t* encrypted_dkg_secret = (uint8_t*) calloc(DKG_MAX_SEALED_LEN, 1);

  char* errMsg = (char*) calloc(1024,1);
  int err_status = 0;
  uint32_t enc_len = 0;

  unsigned t = 3, n = 4;

  status = gen_dkg_secret (eid, &err_status, errMsg, encrypted_dkg_secret, &enc_len, 3);
  REQUIRE(status == SGX_SUCCESS);
  printf("gen_dkg_secret completed with status: %d %s \n", err_status, errMsg);
  printf("\n Length: %d \n", enc_len);


  char* errMsg1 = (char*) calloc(1024,1);

  char colon = ':';
  char* secret_shares = (char*)calloc(DKG_MAX_SEALED_LEN, sizeof(char));
  status = get_secret_shares(eid, &err_status, errMsg1, encrypted_dkg_secret, enc_len, secret_shares, t, n);
  REQUIRE(status == SGX_SUCCESS);
  printf("\nget_secret_shares: %d %s \n", err_status, errMsg1);
  printf("secret shares %s \n\n", secret_shares);

  std::vector <libff::alt_bn128_Fr> s_shares = SplitStringToFr( secret_shares, &colon);

  char* secret = (char*)calloc(DKG_MAX_SEALED_LEN, sizeof(char));
  status = decrypt_dkg_secret(eid, &err_status, errMsg1, encrypted_dkg_secret, (uint8_t*)secret, enc_len);
  REQUIRE(status == SGX_SUCCESS);
  printf("\ndecrypt_dkg_secret completed with status: %d %s \n", err_status, errMsg1);
  printf("decrypted secret %s \n\n", secret);

  signatures::Dkg dkg_obj(t,n);

  std::vector < libff::alt_bn128_Fr> poly = SplitStringToFr((char*)secret, &colon);
  std::vector < libff::alt_bn128_Fr> s_shares_dkg = dkg_obj.SecretKeyContribution(SplitStringToFr((char*)secret, &colon));

  REQUIRE(s_shares == s_shares_dkg);

  free(errMsg);
  free(errMsg1);
  free(encrypted_dkg_secret);
  free(secret_shares);

}

