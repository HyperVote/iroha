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
#include <grpc++/grpc++.h>
#include <utils/datetime.hpp>
#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <endpoint.grpc.fb.h>
#include <endpoint_generated.h>
#include <main_generated.h>

using grpc::Channel;
using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ClientContext;
using grpc::Status;

////////////////////////
// hypervote

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <secblock.h>
using CryptoPP::SecByteBlock;

#include <elgamal.h>
using CryptoPP::ElGamal;
using CryptoPP::ElGamalKeys;

#include <cryptlib.h>
using CryptoPP::DecodingResult;
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;
using CryptoPP::StringSink;

#include <hex.h>
using CryptoPP::HexEncoder;

#include <misc.h>




#include "hypervote.hpp"





void printStatus( bool ok, flatbuffers::BufferRef<iroha::Response>& response ) { 
  if ( ok ) {
    auto msg = response.GetRoot()->message();
    std::cout << "RPC response: " << msg->str() << std::endl;
  } else {
    std::cout << "RPC failed" << std::endl;
  }
}





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
                                      
                                      

    /* adding peers can be done by editing config.json,
       or, at runtime, by 
    const auto peer = ::peer::Node( TargetIP,  OwnPublicKey, LedgerName);
    ::peer::transaction::isssue::add( toPeerIp, peer);
    */

    ////////////////////////////////////////////////
    // 1. Set-up
    //
    // the peer /group responsable to setup the voting session
    // will determine the Generator G (Account.G) and the prime number g  (Account.g);
    // has to generate a KeyPair of privateKey and publicKey (Account.h)
    
    // TODO: set some random peers with OpenBallot rights.
    // TODO: these are responsible of constructing the public key h = p^(r1*r2*..), where r1,r2.. are the peers secret keys.
    // r.i == peer::myself::getPrivateKey()
    
    
    std::string creator = generator::random_public_key();
    std::vector<std::string> pubkey(6);
    generate( pubkey.begin(), pubkey.end(), generator::random_public_key );

    for (auto &pk : pubkey )
      std::cout << pk << "\n";
    
    
    flatbuffers::BufferRef<iroha::Response> response;    
    flatbuffers::FlatBufferBuilder fbbAccount;

        std::cout << "0\n";
    
    auto command = generator::hypervote_AccountAdd( fbbAccount, pubkey[0] );
    
    std::cout << "1\n";
    
    auto tx_offset = generator::hypervote_transaction( fbbAccount,
                        iroha::Command::AccountAdd, command.Union(),
                        1, creator );
    std::cout << "2\n";
    auto status = client.send( tx_offset, &response );
    printStatus( status.ok(), response );
    
    std::cout << "3\n";    
    
    ////////////////////////////////////////////////
    // Generate keys
    AutoSeededRandomPool rng;  // this will be set in Receiver's Account.p
    std::cout << "Generating private key. This may take some time..." << endl;
    ElGamal::Decryptor decryptor;
    decryptor.AccessKey().GenerateRandomWithKeySize(rng, 1024);
    const ElGamalKeys::PrivateKey& privateKey = decryptor.AccessKey();

    // this will be set in Receiver's Account.h
    ElGamalKeys::PublicKey pk;
    privateKey.MakePublicKey(pk);
    
    ////////////////////////////////////////////////
    // 2. Save to receiver account
    
    
    
    ElGamal::Encryptor encryptor(pk);
    // const PublicKey& publicKey = encryptor.AccessKey();
 
    // save the Generator G
    SecByteBlock t(16);
    rng.GenerateBlock(t, t.size());

    std::string s;
    HexEncoder hex(new StringSink(s));

    hex.Put(t, t.size());
    hex.MessageEnd();

    
/*    
   
    
    
    
    
    
    
    ////////////////////////////////////////////////
    // Secret to protect : G^v
    static const int SECRET_SIZE = 256;
    SecByteBlock plaintext( SECRET_SIZE );
    memset( plaintext, G*'1|0', SECRET_SIZE );

    ////////////////////////////////////////////////
    // Encrypt
    // Create cipher text space
    size_t ecl = encryptor.CiphertextLength( plaintext.size() );
    assert( 0 != ecl );
    SecByteBlock ciphertext( ecl );
    encryptor.Encrypt( rng, plaintext, plaintext.size(), ciphertext );


/*

  

    ////////////////////////////
    // TRANSFER
  


    ////////////////////////////////////////////////
    // hypervote count values
  
    an = "hypervote";
    auto query_encryptedvote =  = iroha::CreateAssetQueryDirect(
        fbb, publicKey, ln.c_str(), dn.c_str(), an.c_str()
    );
     fbb.Finish(query_offset);
    auto query = flatbuffers::BufferRef<iroha::AssetQuery>(
            fbb.GetBufferPointer(),fbb.GetSize());

    flatbuffers::BufferRef<iroha::AssetResponse> response;

    // The actual RPC.
    auto status = stub->AccountGetAsset(&context, query, &response);
    if (status.ok()) {
        auto msg = response.GetRoot()->message();
        auto assets = response.GetRoot()->assets();
        std::cout << "RPC response: " << msg->str() << std::endl;
        for(const auto& a: *assets){
            if(reinterpret_cast<const iroha::Asset*>(a)->asset_type() == iroha::AnyAsset::EncryptedVote) {
                std::cout << "ledger:" << reinterpret_cast<const iroha::Asset*>(a)->
                        asset_as_EncryptedVote()->ledger_name()->str()
                    << " domain:" << reinterpret_cast<const iroha::Asset*>(a)->asset_as_EncryptedVote()->domain_name()->str()
                    << " asset:" << reinterpret_cast<const iroha::Asset*>(a)->asset_as_EncryptedVote()->session_name()->str()
                    << "   x:" << reinterpret_cast<const iroha::Asset*>(a)->asset_as_EncryptedVote()->x()->str() << 
                    << "   y:" << reinterpret_cast<const iroha::Asset*>(a)->asset_as_EncryptedVote()->y()->str() << std::endl;
                    
                std::string X = reinterpret_cast<const iroha::Asset*>(a)->asset_as_EncryptedVote()->x()->str();
                std::string Y = reinterpret_cast<const iroha::Asset*>(a)->asset_as_EncryptedVote()->y()->str();
                ////////////////////////////////////////////////
                // Decrypt
                SecByteBlock ciphertext( Y.size() );
                memcpy( ciphertext, Y.c_str(), Y.size() ); // copy the EncryptedVote
                //decryptor.AccessKey().GenerateRandomWithKeySize(rng, 2048);
                //const ElGamalKeys::PrivateKey& privateKey = decryptor.AccessKey();
                
                // Create recovered text space
                size_t dpl = decryptor.MaxPlaintextLength( ciphertext.size() );
                assert( 0 != dpl );
                SecByteBlock recovered( dpl );

                DecodingResult result = decryptor.Decrypt( rng,
                    ciphertext, ciphertext.size(), recovered );

                // At this point, we can set the size of the recovered
                //  data. Until decryption occurs (successfully), we
                //  only know its maximum size
                recovered.resize( result.messageLength );

                // If the assert fires, we won't get this far.
                recovered
            }
        }
    } else {
        std::cout << "RPC failed" << std::endl;
    }
    
*/
    
    return 0;
}
