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
            this->bindAndAddMethod(jsonrpc::Procedure("importBLSKeyShare", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_STRING, "index",jsonrpc::JSON_INTEGER,"keyShare",jsonrpc::JSON_STRING,"keyShareName",jsonrpc::JSON_STRING,"n",jsonrpc::JSON_INTEGER,"t",jsonrpc::JSON_INTEGER, NULL), &AbstractStubServer::importBLSKeyShareI);
            this->bindAndAddMethod(jsonrpc::Procedure("blsSignMessageHash", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_STRING, "keyShareName",jsonrpc::JSON_STRING,"messageHash",jsonrpc::JSON_STRING, NULL), &AbstractStubServer::blsSignMessageHashI);
            this->bindAndAddMethod(jsonrpc::Procedure("importECDSAKey", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_STRING, "key",jsonrpc::JSON_STRING,"keyName",jsonrpc::JSON_STRING, NULL), &AbstractStubServer::importECDSAKeyI);
            this->bindAndAddMethod(jsonrpc::Procedure("generateECDSAKey", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_STRING, "keyName",jsonrpc::JSON_STRING, NULL), &AbstractStubServer::generateECDSAKeyI);
            this->bindAndAddMethod(jsonrpc::Procedure("ecdsaSignMessageHash", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_STRING, "keyShareName",jsonrpc::JSON_STRING,"messageHash",jsonrpc::JSON_STRING, NULL), &AbstractStubServer::ecdsaSignMessageHashI);
            this->bindAndAddMethod(jsonrpc::Procedure("sayHello", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_STRING, "name",jsonrpc::JSON_STRING, NULL), &AbstractStubServer::sayHelloI);
            this->bindAndAddNotification(jsonrpc::Procedure("notifyServer", jsonrpc::PARAMS_BY_NAME,  NULL), &AbstractStubServer::notifyServerI);
            this->bindAndAddMethod(jsonrpc::Procedure("addNumbers", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_INTEGER, "param1",jsonrpc::JSON_INTEGER,"param2",jsonrpc::JSON_INTEGER, NULL), &AbstractStubServer::addNumbersI);
            this->bindAndAddMethod(jsonrpc::Procedure("addNumbers2", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_REAL, "param1",jsonrpc::JSON_REAL,"param2",jsonrpc::JSON_REAL, NULL), &AbstractStubServer::addNumbers2I);
            this->bindAndAddMethod(jsonrpc::Procedure("isEqual", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_BOOLEAN, "param1",jsonrpc::JSON_STRING,"param2",jsonrpc::JSON_STRING, NULL), &AbstractStubServer::isEqualI);
            this->bindAndAddMethod(jsonrpc::Procedure("buildObject", jsonrpc::PARAMS_BY_POSITION, jsonrpc::JSON_OBJECT, "param1",jsonrpc::JSON_STRING,"param2",jsonrpc::JSON_INTEGER, NULL), &AbstractStubServer::buildObjectI);
            this->bindAndAddMethod(jsonrpc::Procedure("methodWithoutParameters", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_STRING,  NULL), &AbstractStubServer::methodWithoutParametersI);
        }

        inline virtual void importBLSKeyShareI(const Json::Value &request, Json::Value &response)
        {
            response = this->importBLSKeyShare(request["index"].asInt(), request["keyShare"].asString(), request["keyShareName"].asString(), request["n"].asInt(), request["t"].asInt());
        }
        inline virtual void blsSignMessageHashI(const Json::Value &request, Json::Value &response)
        {
            response = this->blsSignMessageHash(request["keyShareName"].asString(), request["messageHash"].asString());
        }
        inline virtual void importECDSAKeyI(const Json::Value &request, Json::Value &response)
        {
            response = this->importECDSAKey(request["key"].asString(), request["keyName"].asString());
        }
        inline virtual void generateECDSAKeyI(const Json::Value &request, Json::Value &response)
        {
            response = this->generateECDSAKey(request["keyName"].asString());
        }
        inline virtual void ecdsaSignMessageHashI(const Json::Value &request, Json::Value &response)
        {
            response = this->ecdsaSignMessageHash(request["keyShareName"].asString(), request["messageHash"].asString());
        }
        inline virtual void sayHelloI(const Json::Value &request, Json::Value &response)
        {
            response = this->sayHello(request["name"].asString());
        }
        inline virtual void notifyServerI(const Json::Value &request)
        {
            (void)request;
            this->notifyServer();
        }
        inline virtual void addNumbersI(const Json::Value &request, Json::Value &response)
        {
            response = this->addNumbers(request[0u].asInt(), request[1u].asInt());
        }
        inline virtual void addNumbers2I(const Json::Value &request, Json::Value &response)
        {
            response = this->addNumbers2(request[0u].asDouble(), request[1u].asDouble());
        }
        inline virtual void isEqualI(const Json::Value &request, Json::Value &response)
        {
            response = this->isEqual(request[0u].asString(), request[1u].asString());
        }
        inline virtual void buildObjectI(const Json::Value &request, Json::Value &response)
        {
            response = this->buildObject(request[0u].asString(), request[1u].asInt());
        }
        inline virtual void methodWithoutParametersI(const Json::Value &request, Json::Value &response)
        {
            (void)request;
            response = this->methodWithoutParameters();
        }
        virtual std::string importBLSKeyShare(int index, const std::string& keyShare, const std::string& keyShareName, int n, int t) = 0;
        virtual std::string blsSignMessageHash(const std::string& keyShareName, const std::string& messageHash) = 0;
        virtual std::string importECDSAKey(const std::string& key, const std::string& keyName) = 0;
        virtual std::string generateECDSAKey(const std::string& keyName) = 0;
        virtual std::string ecdsaSignMessageHash(const std::string& keyShareName, const std::string& messageHash) = 0;
        virtual std::string sayHello(const std::string& name) = 0;
        virtual void notifyServer() = 0;
        virtual int addNumbers(int param1, int param2) = 0;
        virtual double addNumbers2(double param1, double param2) = 0;
        virtual bool isEqual(const std::string& param1, const std::string& param2) = 0;
        virtual Json::Value buildObject(const std::string& param1, int param2) = 0;
        virtual std::string methodWithoutParameters() = 0;
};

#endif //JSONRPC_CPP_STUB_ABSTRACTSTUBSERVER_H_
