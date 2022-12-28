/*
    Copyright (C) 2019-Present SKALE Labs

    This file is part of sgxwallet.

    sgxwallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sgxwallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with sgxwallet. If not, see <https://www.gnu.org/licenses/>.

    @file BLSEnclave.cpp
    @author Stan Kladko
    @date 2019
*/


/**
 * This file is generated by jsonrpcstub, DO NOT CHANGE IT MANUALLY!
 */

#ifndef JSONRPC_CPP_STUB_ABSTRACTSTUBSERVER_H_
#define JSONRPC_CPP_STUB_ABSTRACTSTUBSERVER_H_

#include <jsonrpccpp/server.h>

class AbstractStubServer : public jsonrpc::AbstractServer<AbstractStubServer>
{
    public:
        AbstractStubServer(jsonrpc::AbstractServerConnector &conn, jsonrpc::serverVersion_t type = jsonrpc::JSONRPC_SERVER_V2) : jsonrpc::AbstractServer<AbstractStubServer>(conn, type)
        {
          this->bindAndAddMethod(jsonrpc::Procedure("importBLSKeyShare", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT,"keyShare",jsonrpc::JSON_STRING,"keyShareName",jsonrpc::JSON_STRING, NULL), &AbstractStubServer::importBLSKeyShareI);
          this->bindAndAddMethod(jsonrpc::Procedure("blsSignMessageHash", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "keyShareName",jsonrpc::JSON_STRING,"messageHash",jsonrpc::JSON_STRING,"t",jsonrpc::JSON_INTEGER, "n",jsonrpc::JSON_INTEGER, NULL), &AbstractStubServer::blsSignMessageHashI);

          this->bindAndAddMethod(jsonrpc::Procedure("importECDSAKey", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT,"key",jsonrpc::JSON_STRING,"keyName",jsonrpc::JSON_STRING, NULL), &AbstractStubServer::importECDSAKeyI);
          this->bindAndAddMethod(jsonrpc::Procedure("generateECDSAKey", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT,  NULL), &AbstractStubServer::generateECDSAKeyI);
          this->bindAndAddMethod(jsonrpc::Procedure("getPublicECDSAKey", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "keyName",jsonrpc::JSON_STRING, NULL), &AbstractStubServer::getPublicECDSAKeyI);
          this->bindAndAddMethod(jsonrpc::Procedure("ecdsaSignMessageHash", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "base",jsonrpc::JSON_INTEGER,"keyName",jsonrpc::JSON_STRING,"messageHash",jsonrpc::JSON_STRING, NULL), &AbstractStubServer::ecdsaSignMessageHashI);

          this->bindAndAddMethod(jsonrpc::Procedure("generateDKGPoly", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "polyName",jsonrpc::JSON_STRING,"t",jsonrpc::JSON_INTEGER, NULL), &AbstractStubServer::generateDKGPolyI);
          this->bindAndAddMethod(jsonrpc::Procedure("getVerificationVector", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "polyName", jsonrpc::JSON_STRING, "t", jsonrpc::JSON_INTEGER, NULL), &AbstractStubServer::getVerificationVectorI);
          this->bindAndAddMethod(jsonrpc::Procedure("getSecretShare", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "polyName",jsonrpc::JSON_STRING,"publicKeys",jsonrpc::JSON_ARRAY, "n",jsonrpc::JSON_INTEGER,"t",jsonrpc::JSON_INTEGER, NULL), &AbstractStubServer::getSecretShareI);
          this->bindAndAddMethod(jsonrpc::Procedure("dkgVerification", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "publicShares",jsonrpc::JSON_STRING, "ethKeyName",jsonrpc::JSON_STRING, "secretShare",jsonrpc::JSON_STRING,"t",jsonrpc::JSON_INTEGER, "n",jsonrpc::JSON_INTEGER, "index",jsonrpc::JSON_INTEGER, NULL), &AbstractStubServer::dkgVerificationI);
          this->bindAndAddMethod(jsonrpc::Procedure("createBLSPrivateKey", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "blsKeyName",jsonrpc::JSON_STRING, "ethKeyName",jsonrpc::JSON_STRING, "polyName", jsonrpc::JSON_STRING, "secretShare",jsonrpc::JSON_STRING,"t", jsonrpc::JSON_INTEGER,"n",jsonrpc::JSON_INTEGER, NULL), &AbstractStubServer::createBLSPrivateKeyI);
          this->bindAndAddMethod(jsonrpc::Procedure("getBLSPublicKeyShare", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "blsKeyName",jsonrpc::JSON_STRING, NULL), &AbstractStubServer::getBLSPublicKeyShareI);
          this->bindAndAddMethod(jsonrpc::Procedure("calculateAllBLSPublicKeys", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "publicShares", jsonrpc::JSON_ARRAY, "n", jsonrpc::JSON_INTEGER, "t", jsonrpc::JSON_INTEGER, NULL), &AbstractStubServer::calculateAllBLSPublicKeysI);
          this->bindAndAddMethod(jsonrpc::Procedure("complaintResponse", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "polyName",jsonrpc::JSON_STRING,"t",jsonrpc::JSON_INTEGER, "n",jsonrpc::JSON_INTEGER, "ind",jsonrpc::JSON_INTEGER, NULL), &AbstractStubServer::complaintResponseI);
          this->bindAndAddMethod(jsonrpc::Procedure("multG2", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "x",jsonrpc::JSON_STRING, NULL), &AbstractStubServer::multG2I);
          this->bindAndAddMethod(jsonrpc::Procedure("isPolyExists", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "polyName",jsonrpc::JSON_STRING, NULL), &AbstractStubServer::isPolyExistsI);

          this->bindAndAddMethod(jsonrpc::Procedure("getServerStatus", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT,  NULL), &AbstractStubServer::getServerStatusI);
          this->bindAndAddMethod(jsonrpc::Procedure("getServerVersion", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT,  NULL), &AbstractStubServer::getServerVersionI);
          this->bindAndAddMethod(jsonrpc::Procedure("deleteBlsKey", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "blsKeyName", jsonrpc::JSON_STRING, NULL), &AbstractStubServer::deleteBlsKeyI);

          this->bindAndAddMethod(jsonrpc::Procedure("getSecretShareV2", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "polyName",jsonrpc::JSON_STRING,"publicKeys",jsonrpc::JSON_ARRAY, "n",jsonrpc::JSON_INTEGER,"t",jsonrpc::JSON_INTEGER, NULL), &AbstractStubServer::getSecretShareV2I);
          this->bindAndAddMethod(jsonrpc::Procedure("dkgVerificationV2", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "publicShares",jsonrpc::JSON_STRING, "ethKeyName",jsonrpc::JSON_STRING, "secretShare",jsonrpc::JSON_STRING,"t",jsonrpc::JSON_INTEGER, "n",jsonrpc::JSON_INTEGER, "index",jsonrpc::JSON_INTEGER, NULL), &AbstractStubServer::dkgVerificationV2I);
          this->bindAndAddMethod(jsonrpc::Procedure("createBLSPrivateKeyV2", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "blsKeyName",jsonrpc::JSON_STRING, "ethKeyName",jsonrpc::JSON_STRING, "polyName", jsonrpc::JSON_STRING, "secretShare",jsonrpc::JSON_STRING,"t", jsonrpc::JSON_INTEGER,"n",jsonrpc::JSON_INTEGER, NULL), &AbstractStubServer::createBLSPrivateKeyV2I);

          this->bindAndAddMethod(jsonrpc::Procedure("getDecryptionShares", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "blsKeyName",jsonrpc::JSON_STRING,"publicDecryptionValues",jsonrpc::JSON_ARRAY, NULL), &AbstractStubServer::getDecryptionSharesI);

          this->bindAndAddMethod(jsonrpc::Procedure("popProve", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "blsKeyName",jsonrpc::JSON_STRING, NULL), &AbstractStubServer::popProveI);
          this->bindAndAddMethod(jsonrpc::Procedure("generateBLSPrivateKey", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT, "blsKeyName",jsonrpc::JSON_STRING, NULL), &AbstractStubServer::generateBLSPrivateKeyI);
        }

        inline virtual void importBLSKeyShareI(const Json::Value &request, Json::Value &response)
        {
            response = this->importBLSKeyShare( request["keyShare"].asString(), request["keyShareName"].asString());
        }
        inline virtual void blsSignMessageHashI(const Json::Value &request, Json::Value &response)
        {
            response = this->blsSignMessageHash(request["keyShareName"].asString(), request["messageHash"].asString(), request["t"].asInt(), request["n"].asInt());
        }

        inline virtual void importECDSAKeyI(const Json::Value &request, Json::Value &response)
        {
            response = this->importECDSAKey( request["key"].asString(), request["keyName"].asString());
        }
        inline virtual void generateECDSAKeyI(const Json::Value &request, Json::Value &response)
        {
          (void)request;
          response = this->generateECDSAKey();
        }
         inline virtual void getPublicECDSAKeyI(const Json::Value &request, Json::Value &response)
        {
            response = this->getPublicECDSAKey(request["keyName"].asString());
        }
        inline virtual void ecdsaSignMessageHashI(const Json::Value &request, Json::Value &response)
        {
            response = this->ecdsaSignMessageHash(request["base"].asInt(), request["keyName"].asString(), request["messageHash"].asString());
        }

        inline virtual void generateDKGPolyI(const Json::Value &request, Json::Value &response)
        {
            response = this->generateDKGPoly(request["polyName"].asString(), request["t"].asInt());
        }
        inline virtual void getVerificationVectorI(const Json::Value &request, Json::Value &response)
        {
            response = this->getVerificationVector(request["polyName"].asString(), request["t"].asInt());
        }
        inline virtual void getSecretShareI(const Json::Value &request, Json::Value &response)
        {
            response = this->getSecretShare(request["polyName"].asString(), request["publicKeys"], request["t"].asInt(),request["n"].asInt());
        }
        inline virtual void dkgVerificationI(const Json::Value &request, Json::Value &response)
        {
            response = this->dkgVerification(request["publicShares"].asString(), request["ethKeyName"].asString(), request["secretShare"].asString(), request["t"].asInt(), request["n"].asInt(), request["index"].asInt());
        }
        inline virtual void createBLSPrivateKeyI(const Json::Value &request, Json::Value &response)
        {
            response = this->createBLSPrivateKey(request["blsKeyName"].asString(), request["ethKeyName"].asString(), request["polyName"].asString(),request["secretShare"].asString(),request["t"].asInt(), request["n"].asInt());
        }
        inline virtual void getBLSPublicKeyShareI(const Json::Value &request, Json::Value &response)
        {
          response = this->getBLSPublicKeyShare(request["blsKeyName"].asString());
        }
        inline virtual void calculateAllBLSPublicKeysI(const Json::Value& request, Json::Value& response) {
            response = this->calculateAllBLSPublicKeys(request["publicShares"], request["t"].asInt(), request["n"].asInt());
        }
        inline virtual void complaintResponseI(const Json::Value &request, Json::Value &response)
        {
          response = this->complaintResponse( request["polyName"].asString(), request["t"].asInt(), request["n"].asInt(), request["ind"].asInt());
        }
        inline virtual void multG2I(const Json::Value &request, Json::Value &response)
        {
            response = this->multG2(request["x"].asString());
        }
        inline virtual void isPolyExistsI(const Json::Value &request, Json::Value &response)
        {
            response = this->isPolyExists(request["polyName"].asString());
        }

        inline virtual void getServerStatusI(const Json::Value &request, Json::Value &response)
        {
          (void)request;
          response = this->getServerStatus();
        }

        inline virtual void getServerVersionI(const Json::Value &request, Json::Value &response)
        {
          (void)request;
          response = this->getServerVersion();
        }

        inline virtual void deleteBlsKeyI(const Json::Value& request, Json::Value& response) {
            response = this->deleteBlsKey(request["blsKeyName"].asString());
        }

        inline virtual void getSecretShareV2I(const Json::Value &request, Json::Value &response)
        {
            response = this->getSecretShareV2(request["polyName"].asString(), request["publicKeys"], request["t"].asInt(),request["n"].asInt());
        }
        inline virtual void dkgVerificationV2I(const Json::Value &request, Json::Value &response)
        {
            response = this->dkgVerificationV2(request["publicShares"].asString(), request["ethKeyName"].asString(), request["secretShare"].asString(), request["t"].asInt(), request["n"].asInt(), request["index"].asInt());
        }
        inline virtual void createBLSPrivateKeyV2I(const Json::Value &request, Json::Value &response)
        {
            response = this->createBLSPrivateKeyV2(request["blsKeyName"].asString(), request["ethKeyName"].asString(), request["polyName"].asString(),request["secretShare"].asString(),request["t"].asInt(), request["n"].asInt());
        }

        inline virtual void getDecryptionSharesI(const Json::Value &request, Json::Value &response)
        {
            response = this->getDecryptionShares(request["blsKeyName"].asString(), request["publicDecryptionValues"]);
        }

        inline virtual void popProveI(const Json::Value &request, Json::Value &response)
        {
            response = this->popProve(request["blsKeyName"].asString());
        }

        inline virtual void generateBLSPrivateKeyI(const Json::Value &request, Json::Value &response)
        {
            response = this->generateBLSPrivateKey(request["blsKeyName"].asString());
        }

        virtual Json::Value importBLSKeyShare(const std::string& keyShare, const std::string& keyShareName) = 0;
        virtual Json::Value blsSignMessageHash(const std::string& keyShareName, const std::string& messageHash, int t, int n ) = 0;
        virtual Json::Value importECDSAKey(const std::string& keyShare, const std::string& keyShareName) = 0;
        virtual Json::Value generateECDSAKey() = 0;
        virtual Json::Value getPublicECDSAKey(const std::string& keyName) = 0;
        virtual Json::Value ecdsaSignMessageHash(int base, const std::string& keyName, const std::string& messageHash) = 0;

        virtual Json::Value generateDKGPoly(const std::string& polyName, int t) = 0;
        virtual Json::Value getVerificationVector(const std::string& polyName, int t) = 0;
        virtual Json::Value getSecretShare(const std::string& polyName, const Json::Value& publicKeys, int t, int n) = 0;
        virtual Json::Value dkgVerification( const std::string& publicShares, const std::string& ethKeyName, const std::string& SecretShare, int t, int n, int index) = 0;
        virtual Json::Value createBLSPrivateKey(const std::string& blsKeyName, const std::string& ethKeyName, const std::string& polyName, const std::string& SecretShare, int t, int n) = 0;
        virtual Json::Value getBLSPublicKeyShare(const std::string& blsKeyName) = 0;
        virtual Json::Value calculateAllBLSPublicKeys(const Json::Value& publicShares, int t, int n) = 0;
        virtual Json::Value complaintResponse(const std::string& polyName, int t, int n, int ind) = 0;
        virtual Json::Value multG2(const std::string & x) = 0;
        virtual Json::Value isPolyExists(const std::string& polyName) = 0;

        virtual Json::Value getServerStatus() = 0;
        virtual Json::Value getServerVersion() = 0;
        virtual Json::Value deleteBlsKey(const std::string& name) = 0;

        virtual Json::Value getSecretShareV2(const std::string& polyName, const Json::Value& publicKeys, int t, int n) = 0;
        virtual Json::Value dkgVerificationV2( const std::string& publicShares, const std::string& ethKeyName, const std::string& SecretShare, int t, int n, int index) = 0;
        virtual Json::Value createBLSPrivateKeyV2(const std::string& blsKeyName, const std::string& ethKeyName, const std::string& polyName, const std::string & SecretShare, int t, int n) = 0;
        
        virtual Json::Value getDecryptionShares(const std::string& KeyName, const Json::Value& publicDecryptionValues) = 0;

        virtual Json::Value popProve(const std::string& blsKeyName) = 0;
        virtual Json::Value generateBLSPrivateKey(const std::string& blsKeyName) = 0;
};

#endif //JSONRPC_CPP_STUB_ABSTRACTSTUBSERVER_H_
