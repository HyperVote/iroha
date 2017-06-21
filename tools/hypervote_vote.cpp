/*
Copyright Soramitsu Co., Ltd. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <flatbuffers/flatbuffers.h>
#include <service/flatbuffer_service.h>
#include <grpc++/grpc++.h>
#include <utils/datetime.hpp>
#include <algorithm>
#include <memory>
#include <string>
#include <vector>
#include <endpoint.grpc.fb.h>
#include <main_generated.h>

using grpc::Channel;
using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ClientContext;
using grpc::Status;



#include "hypervote.hpp"



int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cout << "Plz IP " << std::endl;
    std::cout << "Usage: hypervote_vote ip-address " << std::endl;
    return 1;
  }
  std::cout << "IP:" << argv[1] << std::endl;


  auto client = HypervoteClient(
                  grpc::CreateChannel(std::string(argv[1]) + ":50051",
                                      grpc::InsecureChannelCredentials())
                                      );

  // Build a request with the name set.
  flatbuffers::FlatBufferBuilder fbb;
  
  
  auto publicKey = "SamplePublicKey";
  
  auto account_vec = flatbuffer_service::account::CreateAccount(
      publicKey, "alias", "prevPubKey", {"sig1", "sig2"}, 1);
  auto command = iroha::CreateAccountAddDirect(fbb, &account_vec);

  // The actual RPC.
  auto status = client.send( flatbuffer_service::transaction::CreateTransaction(
                        fbb, fbb.CreateString(creator), iroha::Command::AccountAdd,
                        command, fbb.CreateVector(sigs),
                        fbb.CreateVector(hash),
               &response );
  if (status.ok()) {
    auto msg = response.GetRoot()->message();
    std::cout << "RPC response: " << msg->str() << std::endl;
  } else {
    std::cout << "RPC failed" << std::endl;
  }
  return 0;
}