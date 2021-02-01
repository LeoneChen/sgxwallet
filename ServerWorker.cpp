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

    @file ServerWorker.cpp
    @author Stan Kladko
    @date 2021
*/


#include "common.h"
#include <json/writer.h>


#include <zmq.hpp>
#include "zhelpers.hpp"

#include "Log.h"
#include "ZMQMessage.h"

#include "ServerWorker.h"

std::atomic <uint64_t>  ServerWorker::workerCount(1);

ServerWorker::ServerWorker(zmq::context_t &ctx, int sock_type, bool _checkSignature,
                           const string& _caCert ) :            checkSignature(_checkSignature),
                           caCert(_caCert),
                                                                ctx_(ctx),
                                                                 worker_(ctx_, sock_type),
                                                                 isExitRequested(false) {

    if (checkSignature) {
        CHECK_STATE(!caCert.empty())
    }

    index = workerCount.fetch_add(1);
    int linger = 0;
    zmq_setsockopt(worker_, ZMQ_LINGER, &linger, sizeof(linger));
};

void ServerWorker::work() {
    worker_.connect("inproc://backend");

    std::string replyStr;


    while (!isExitRequested) {

        Json::Value result;
        int errStatus = -1 * (10000 + __LINE__);
        result["status"] = errStatus;
        result["errorMessage"] = "Server error";


        zmq::message_t identity;
        zmq::message_t identit2;
        zmq::message_t copied_id;

        try {

            zmq_pollitem_t items[1];
            items[0].socket = worker_;
            items[0].events = ZMQ_POLLIN;

            int pollResult = 0;

            do {
                pollResult = zmq_poll(items, 1, 1000);
                if (isExitRequested) {
                    goto clean;
                }
            } while (pollResult == 0);


            zmq::message_t msg;
            zmq::message_t copied_msg;
            worker_.recv(&identity);
            copied_id.copy(&identity);
            worker_.recv(&msg);

            int64_t more;
            size_t more_size = sizeof(more);
            auto rc = zmq_getsockopt(worker_, ZMQ_RCVMORE, &more, &more_size);
            CHECK_STATE(rc == 0);


            vector <uint8_t> msgData(msg.size() + 1, 0);

            memcpy(msgData.data(), msg.data(), msg.size());

            CHECK_STATE(msg.size() > 5 || msgData.at(0) == '{' || msgData[msg.size()] == '}');


            memcpy(msgData.data(), msg.data(), msg.size());

            auto parsedMsg = ZMQMessage::parse(
                    (const char *) msgData.data(), msg.size(), true);

            CHECK_STATE(parsedMsg);

            result = parsedMsg->process();

        } catch (SGXException &e) {
            result["status"] = e.getStatus();
            result["errorMessage"] = e.getMessage();
            spdlog::error("Exception in zmq server worker:{}", e.what());
        }
        catch (std::exception &e) {
            if (isExitRequested) {
                return;
            }
            result["errorMessage"] = string(e.what());
            spdlog::error("Exception in zmq server worker:{}", e.what());
        } catch (...) {
            if (isExitRequested) {
                goto clean;
            }
            spdlog::error("Error in zmq server worker");
            result["errorMessage"] = "Error in zmq server worker";
        }

        try {

            Json::FastWriter fastWriter;

            replyStr = fastWriter.write(result);
            replyStr = replyStr.substr(0, replyStr.size() - 1);

            CHECK_STATE(replyStr.size() > 2);
            CHECK_STATE(replyStr.front() == '{');
            CHECK_STATE(replyStr.back() == '}');
            zmq::message_t replyMsg(replyStr.c_str(), replyStr.size() + 1);

            worker_.send(copied_id, ZMQ_SNDMORE);
            worker_.send(replyMsg);

        } catch (std::exception &e) {
            if (isExitRequested) {
                goto clean;
            }
            spdlog::error("Exception in zmq server worker send :{}", e.what());
        } catch (...) {
            if (isExitRequested) {
                goto clean;
            }
            spdlog::error("Unklnown exception in zmq server worker send");
        }
    }

    clean:
    spdlog::info("Exited worker thread {}", index);
}


void ServerWorker::requestExit() {
    isExitRequested.exchange(true);
    zmq_close(worker_);
    spdlog::info("Closed worker socket {}", index);
}

