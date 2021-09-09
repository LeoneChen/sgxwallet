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
    along with sgxwallet.  If not, see <https://www.gnu.org/licenses/>.

    @file ZMQServer.cpp
    @author Stan Kladko
    @date 2019
*/

#include <fstream>
#include <streambuf>


#include "third_party/spdlog/spdlog.h"

#include "common.h"
#include "sgxwallet_common.h"

#include "SGXException.h"
#include "ExitRequestedException.h"
#include "ReqMessage.h"
#include "ZMQMessage.h"
#include "ZMQServer.h"


using namespace std;

shared_ptr <ZMQServer> ZMQServer::zmqServer = nullptr;

ZMQServer::ZMQServer(bool _checkSignature, bool _checkKeyOwnership, const string &_caCertFile)
        : checkSignature(_checkSignature), checkKeyOwnership(_checkKeyOwnership),
          caCertFile(_caCertFile), ctx(make_shared<zmq::context_t>(1)) {

    socket = make_shared<zmq::socket_t>(*ctx, ZMQ_ROUTER);

    if (_checkSignature) {
        CHECK_STATE(!_caCertFile.empty());
        ifstream t(_caCertFile);
        string str((istreambuf_iterator<char>(t)), istreambuf_iterator<char>());
        caCert = str;
        CHECK_STATE(!caCert.empty())
    }

    int linger = 0;

    zmq_setsockopt(*socket, ZMQ_LINGER, &linger, sizeof(linger));

    threadPool = make_shared<WorkerThreadPool>(1, this);

}

void ZMQServer::initListenSocket() {

    auto port = BASE_PORT + 5;

    spdlog::info("Starting zmq server on port {} ...", port);

    try {
        CHECK_STATE(socket);
        socket->bind("tcp://*:" + to_string(port));
    } catch (...) {
        spdlog::error("Zmq server task could not bind to port:{}", port);
        throw SGXException(ZMQ_COULD_NOT_BIND_FRONT_END, "Server task could not bind.");
    }

    spdlog::info("ZMQ server socket created and bound.");

}

void ZMQServer::run() {


    zmqServer->initListenSocket();

    spdlog::info("Started zmq read loop.");

    while (!isExitRequested) {
        try {
            zmqServer->doOneServerLoop();
        } catch (ExitRequestedException& e) {
            spdlog::info("Exit requested. Exiting server loop");
            break;
        }
        catch (...) {
            spdlog::error("doOneServerLoop threw exception. This should never happen!");
        }
    }

    spdlog::info("Exited zmq server loop");
}

std::atomic<bool> ZMQServer::isExitRequested(false);

void ZMQServer::exitZMQServer() {
    // if already exited do not exit
    spdlog::info("exitZMQServer called");
    if (isExitRequested.exchange(true)) {
        spdlog::info("Exit is already under way");
        return;
    }

    spdlog::info("Exiting ZMQServer");
    spdlog::info("Joining worker thread pool threads ...");
    zmqServer->threadPool->joinAll();
    spdlog::info("Joined worker thread pool threads");
    spdlog::info("Shutting down ZMQ contect");
    zmqServer->ctx->shutdown();
    spdlog::info("Shut down ZMQ contect");
    spdlog::info("Closing ZMQ server socket ...");
    zmqServer->socket->close();
    spdlog::info("Closed ZMQ server socket");
    spdlog::info("Closing ZMQ context ...");
    zmqServer->ctx->close();
    spdlog::info("Closed ZMQ context.");
    spdlog::info("Exited zmq server.");
}

void ZMQServer::initZMQServer(bool _checkSignature, bool _checkKeyOwnership) {
    static bool initedServer = false;
    CHECK_STATE(!initedServer)
    initedServer = true;

    spdlog::info("Initing zmq server.\n checkSignature is set to {}.\n checkKeyOwnership is set to {}",
                 _checkSignature, _checkKeyOwnership);

    string rootCAPath = "";

    if (_checkSignature) {
        rootCAPath = string(SGXDATA_FOLDER) + "cert_data/rootCA.pem";
        spdlog::info("Reading root CA from {}", rootCAPath);
        CHECK_STATE(access(rootCAPath.c_str(), F_OK) == 0);
        spdlog::info("Read CA.", rootCAPath);
    };

    spdlog::info("Initing zmq server ...");

    zmqServer = make_shared<ZMQServer>(_checkSignature, _checkKeyOwnership, rootCAPath);

    CHECK_STATE(zmqServer)
    serverThread = make_shared<thread>(std::bind(&ZMQServer::run, ZMQServer::zmqServer));
    serverThread->detach();

    spdlog::info("Releasing SGX worker threads  ...");

    zmqServer->releaseWorkers();

    spdlog::info("Released SGX worker threads.");

    spdlog::info("Inited zmq server.");
}

shared_ptr <std::thread> ZMQServer::serverThread = nullptr;

ZMQServer::~ZMQServer() {
    exitZMQServer();
}

void ZMQServer::checkForExit() {
    if (isExitRequested) {
        throw ExitRequestedException();
    }
}



PollResult ZMQServer::poll() {
    zmq_pollitem_t items[1];
    items[0].socket = *socket;
    items[0].events = ZMQ_POLLIN;

    int pollResult = 0;

    do {
        checkForExit();
        pollResult = zmq_poll(items, 1, 1);
    } while (pollResult == 0);

    return GOT_INCOMING_MSG;
}

string ZMQServer::receiveMessage(zmq::message_t& _identity) {
    if (!socket->recv(&_identity)) {
        checkForExit();
        // something terrible happened
        spdlog::error("Fatal error: socket->recv(&identity) returned false. Exiting.");
        exit(-11);
    }

    if (!_identity.more()) {
        checkForExit();
        // something terrible happened
        spdlog::error("Fatal error: zmq_msg_more(identity) returned false. Existing.");
        exit(-12);
    }

    zmq::message_t reqMsg;

    if (!socket->recv(&reqMsg, 0)) {
        checkForExit();
        // something terrible happened
        spdlog::error("Fatal error: socket.recv(&reqMsg, 0) returned false. Exiting");
        exit(-13);
    }

    auto result = string((char *) reqMsg.data(), reqMsg.size());

    CHECK_STATE(result.front() == '{')
    CHECK_STATE(result.back() == '}')
    return result;
}

void ZMQServer::sendToClient(Json::Value& _result,  zmq::message_t& _identity  ) {
    string replyStr;
    try {
        Json::FastWriter fastWriter;
        fastWriter.omitEndingLineFeed();

        replyStr = fastWriter.write(_result);

        CHECK_STATE(replyStr.size() > 2);
        CHECK_STATE(replyStr.front() == '{');
        CHECK_STATE(replyStr.back() == '}');

        if (!socket->send(_identity, ZMQ_SNDMORE)) {
            exit(-15);
        }
        if (!s_send(*socket, replyStr)) {
            exit(-16);
        }
    } catch (ExitRequestedException) {
        throw;
    } catch (std::exception &e) {
        checkForExit();
        spdlog::error("Exception in zmq server worker send :{}", e.what());
        exit(-17);
    } catch (...) {
        checkForExit();
        spdlog::error("Unklnown exception in zmq server worker send");
        exit(-18);
    }

}

void ZMQServer::doOneServerLoop() {

    Json::Value result;
    result["status"] = ZMQ_SERVER_ERROR;

    zmq::message_t identity;
    string msgStr;

    try {

        poll();

        msgStr = receiveMessage(identity);

        auto msg = ZMQMessage::parse(
                msgStr.c_str(), msgStr.size(), true, checkSignature, checkKeyOwnership);

        CHECK_STATE2(msg, ZMQ_COULD_NOT_PARSE);

        if ((dynamic_pointer_cast<BLSSignReqMessage>(msg)!= nullptr) ||
             dynamic_pointer_cast<ECDSASignReqMessage>(msg)) {
            spdlog::info("FUFUFUFUF");
        } else {
            spdlog::info("HAHAHA");
        }

        result = msg->process();
    } catch (ExitRequestedException) {
        throw;
    } catch (std::exception &e) {
        checkForExit();
        result["errorMessage"] = string(e.what());
        spdlog::error("Exception in zmq server :{}", e.what());
        spdlog::error("ID:" + string((char *) identity.data(), identity.size()));
        spdlog::error("Client request :" + msgStr);
    } catch (...) {
        checkForExit();
        spdlog::error("Error in zmq server ");
        result["errorMessage"] = "Error in zmq server ";
        spdlog::error("ID:" + string((char *) identity.data(), identity.size()));
        spdlog::error("Client request :" + msgStr);
    }

    sendToClient(result, identity);

}

void ZMQServer::workerThreadProcessNextMessage() {
    usleep(1000000);
    cerr << "WORKER LOOP" << endl;
}

void ZMQServer::workerThreadMessageProcessLoop(ZMQServer *_agent) {
    CHECK_STATE(_agent);
    _agent->waitOnGlobalStartBarrier();
    // do work forever until told to exit
    while (!isExitRequested) {
        try {
            _agent->workerThreadProcessNextMessage();
        } catch (ExitRequestedException &e) {
            break;
        } catch (Exception &e) {
            spdlog::error(string("Caught exception in worker thread loop:") + e.what());
        }
    }

    spdlog::info("Exit requested. Exiting worker thread.");
}