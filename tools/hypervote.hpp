

#ifndef __HYPERVOTE_UTILS__
#define __HYPERVOTE_UTILS__

#include <algorithm>
#include <functional>
#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <utils/datetime.hpp>


#include <main_generated.h>

#include <transaction_generated.h>
// #include <flatbuffers/flatbuffers.h>
// #include <account_generated.h>




class HypervoteClient {
public:
  HypervoteClient(std::shared_ptr<grpc::Channel>&& channel)
    : stub(iroha::Sumeragi::NewStub(std::move(channel)))
  {}

  grpc::Status send(std::vector<uint8_t>& txbuf,
                    flatbuffers::BufferRef<iroha::Response>* response)
  {
    grpc::ClientContext context;
    flatbuffers::BufferRef<iroha::Transaction> request(
      txbuf.data(), txbuf.size()
    );
    return stub->Torii(&context, request, response);
  }

private:
  std::unique_ptr<iroha::Sumeragi::Stub> stub;
};




class HypervoteAssetQuery {
public:
  HypervoteAssetQuery(std::shared_ptr<grpc::Channel>&& channel)
    : stub(iroha::AssetRepository::NewStub(std::move(channel)))
  {}

  grpc::Status query(std::vector<uint8_t>& txbuf,
                    flatbuffers::BufferRef<iroha::AssetResponse>* response)
  {
    grpc::ClientContext context;
    flatbuffers::BufferRef<iroha::AssetQuery> request(
      txbuf.data(), txbuf.size()
    );
    return stub->AccountGetAsset(&context, request, response);
  }

private:
  std::unique_ptr<iroha::AssetRepository::Stub> stub;
};




size_t PUB_KEY_LENGTH_STR_ = 44;
unsigned int SEED_ = 1337; /* used by random_number */
size_t HASH_SIZE_BLOB_ = 32;
size_t SIGNATURE_LENGTH_BLOB_ = 44;
 
// hash::sha3_256_hex(raw_value);
// base64::encode(value);

/* Common utils */
namespace generator {

  /**
   * returns a number in a range [min, max)
   */
  int64_t random_number(int64_t min, int64_t max) {
    return min + (rand_r(&SEED_) % (max - min));
  }
  /**
   * returns a random string of size length, and characters in alphabet.
   */
  const char ALPHABET[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  std::string random_string(size_t length, std::string alphabet = ALPHABET) {
    assert(alphabet.size() > 0);
    std::string s;
    std::generate_n(std::back_inserter(s), length, [&alphabet]() {
      size_t i = (size_t)generator::random_number(0, alphabet.size());
      return (char)alphabet[i];
    });
    return s;
  }
  /**
   * returns a random public key
   */
  std::string random_base64_key(size_t length) {
    const char alph[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string s = generator::random_string( length, alph );
    if (s.size() % 4 == 0) {
      s.pop_back();
      s.push_back('=');
    }
    return s;
  }
  std::string random_public_key() { return random_base64_key(PUB_KEY_LENGTH_STR_); }
  /**
   * sign in blank 
   */  
  inline std::vector<uint8_t> random_blob(size_t length) {
    std::vector<uint8_t> v(length);
    std::generate_n(v.begin(), length, std::bind(random_number, 0, 256));
    return v;
  }
  inline flatbuffers::Offset<iroha::Signature> random_signature(
      flatbuffers::FlatBufferBuilder& fbb,
      const std::string pubk = random_public_key(),
      const std::vector<uint8_t> signature = random_blob(SIGNATURE_LENGTH_BLOB_),
      uint64_t timestamp = (uint64_t)random_number(0, 1 << 30)) {
    return iroha::CreateSignature(fbb, fbb.CreateString(pubk),
                                  fbb.CreateVector(signature), timestamp);
  }
  inline std::vector<flatbuffers::Offset<iroha::Signature>> random_signatures(
    flatbuffers::FlatBufferBuilder &fbb, int length = 10) {
    std::vector<flatbuffers::Offset<iroha::Signature>> ret;
    for (int i = 0; i < length; i++) {
      ret.push_back(random_signature(fbb));
    }
    return ret;
  }
  /**
   *
#include <crypto/hash.hpp>
#include <crypto/base64.hpp>
#include <crypto/signature.hpp>

  auto key_pair = signature::generateKeyPair();
  auto pubkey = base64::encode(key_pair.publicKey);
  auto pubkey_v = std::vector<uint8_t>(pubkey.begin(), pubkey.end());
  
  inline std::vector<uint8_t> random_signature(signature::KeyPair const& key_pair) {
    auto message = random_alphabets(50);
    auto res_str = signature::sign(message, key_pair);
    std::vector<uint8_t> res;
    for (auto e: res_str)
      res.push_back((unsigned char)e);
    return res;
  }
   */
  
  
  /* Asset utils */
  flatbuffers::Offset<iroha::AssetCreate> hypervote_AssetCreate(
      flatbuffers::FlatBufferBuilder& fbb,
      std::string session_name = "hypervote0",
      std::string domain_name = "ROMANIA", std::string ledger_name = "UPT",
      std::string session_votes = "0") {
    return iroha::CreateAssetCreate(fbb, fbb.CreateString(session_name),
                                    fbb.CreateString(domain_name),
                                    fbb.CreateString(ledger_name),
                                    fbb.CreateString(session_votes));
  }


  /* hypervote utils */
  std::vector<uint8_t> hypervote_EncryptedVoteCreate(
      std::string x = "0",
      std::string y = "0",
      std::string session_name = "hypervote0",
      std::string domain_name = "ROMANIA", std::string ledger_name = "UPT",
      std::string description = random_string((size_t)random_number(5, 100))) {
    flatbuffers::FlatBufferBuilder fbb(2048);
  
    auto vote = iroha::CreateEncryptedVote(
        fbb, fbb.CreateString(session_name), fbb.CreateString(domain_name),
        fbb.CreateString(ledger_name), fbb.CreateString(description),
        fbb.CreateString(x), fbb.CreateString(y) );
  
    fbb.Finish(vote);
  
    uint8_t* ptr = fbb.GetBufferPointer();
    return {ptr, ptr + fbb.GetSize()};
  }
  
  std::vector<uint8_t> asset_wrapper_EncryptedVote(
      std::string x = "0",
      std::string y = "0",
      std::string session_name = "hypervote0",
      std::string domain_name = "ROMANIA", std::string ledger_name = "UPT",
      std::string description = random_string(0)) {
    flatbuffers::FlatBufferBuilder fbb(2048);
  
  /*
    std::vector<std::uint8_t> vote = hypervote_EncryptedVoteCreate (
                          x, y, session_name, 
                          domain_name, ledger_name, description );
                          */
    auto asset = iroha::CreateAsset(
        fbb, iroha::AnyAsset::EncryptedVote, // fbb.CreateVector( vote ) )
                  iroha::CreateEncryptedVote(
                      fbb, fbb.CreateString(session_name), fbb.CreateString(domain_name),
                      fbb.CreateString(ledger_name), fbb.CreateString(description),
                      fbb.CreateString(x), fbb.CreateString(y))  .Union());
  
    fbb.Finish(asset);
  
    uint8_t* ptr = fbb.GetBufferPointer();
    return {ptr, ptr + fbb.GetSize()};
  }

  /* Account utils */
  flatbuffers::Offset<iroha::AccountAdd> hypervote_AccountAdd(
      flatbuffers::FlatBufferBuilder& fbb,
      std::string pubkey = random_public_key(),
      std::string alias = random_string(10),
      uint16_t signatories = (uint16_t) random_number(1, 10)) {
  
    flatbuffers::FlatBufferBuilder fbb_acc(2048);
    std::vector<std::string> sign(signatories);
    std::generate_n(sign.begin(), signatories, random_public_key);
  
    auto account = iroha::CreateAccount(
        fbb_acc, fbb_acc.CreateString(pubkey), fbb_acc.CreateString(""), fbb_acc.CreateString(alias),
        fbb_acc.CreateVectorOfStrings(sign), signatories);
    fbb_acc.Finish(account);
  
    uint8_t* ptr = fbb.GetBufferPointer();
    const std::vector<uint8_t> accountVec = {ptr, ptr + fbb.GetSize()};
    
    return iroha::CreateAccountAdd(fbb, fbb.CreateVector(accountVec));
  }


  /* Transaction utils */
  flatbuffers::Offset<iroha::Add> hypervote_Add(
      flatbuffers::FlatBufferBuilder& fbb,
      std::string accPubKey = random_public_key(),
      std::vector<uint8_t> asset = asset_wrapper_EncryptedVote() ) {
    return iroha::CreateAdd(fbb, fbb.CreateString(accPubKey),
                                 fbb.CreateVector(asset));
  }
  
  flatbuffers::Offset<iroha::Transfer> random_Transfer(
      flatbuffers::FlatBufferBuilder& fbb,
      std::vector<uint8_t> asset = asset_wrapper_EncryptedVote(),
      std::string sender = random_public_key(),
      std::string receiver = random_public_key()) {
    return iroha::CreateTransfer(fbb, fbb.CreateVector(asset),
                                      fbb.CreateString(sender),
                                      fbb.CreateString(receiver));
  }

  /**
   * Returns deserialized transaction (root flatbuffer)
   * @param fbb - a reference to flatbuffer builder.
   * @param cmd_type - one of iroha::Command
   * @param command - random_*(fbb).Union() where * is the same type as \p
   * cmd_type. Example: cmd_type=iroha::Command::PeerRemove,
   * command=random_PeerRemove(fbb).Union()
   * @param signatures - number of signatures
   * @param creator - random public key of a creator
   * @param hash - random hash of a transaction
   * @return ready to be transmitted/parsed root Transaction flatbuffer
   */
  std::vector<uint8_t> hypervote_transaction(
      flatbuffers::FlatBufferBuilder& fbb, iroha::Command cmd_type,
      flatbuffers::Offset<void> command, const size_t signatures = 5,
      std::string creator = random_public_key(),
      std::vector<uint8_t> hash = random_blob(HASH_SIZE_BLOB_)) {
    std::vector<flatbuffers::Offset<iroha::Signature>> sigs(signatures);
    std::generate_n(sigs.begin(), signatures,
                    [&fbb]() { return random_signature(fbb); });
  
    auto tx = iroha::CreateTransaction(fbb, fbb.CreateString(creator), cmd_type,
                                       command, fbb.CreateVector(sigs),
                                       fbb.CreateVector(hash));
  
    fbb.Finish(tx);
  
    uint8_t* ptr = fbb.GetBufferPointer();
    return {ptr, ptr + fbb.GetSize()};
  }
  
  /* Peers utils */
  std::string random_ip() {
    std::string s;
    s += std::to_string(random_number(0, 256));
    s += '.';
    s += std::to_string(random_number(0, 256));
    s += '.';
    s += std::to_string(random_number(0, 256));
    s += '.';
    s += std::to_string(random_number(0, 256));
    return s;
  }
  std::vector<uint8_t> random_peer(std::string ledger_name = random_string(10),
                                   std::string pubkey = random_public_key(),
                                   std::string ip = random_ip(),
                                   double trust = random_number(0, 10)) {
    flatbuffers::FlatBufferBuilder fbb(2048);
  
  
    auto peer = iroha::CreatePeer(fbb, fbb.CreateString(ledger_name),
                                  fbb.CreateString(pubkey),
                                  fbb.CreateString(ip), trust);
  
    fbb.Finish(peer);
  
    uint8_t* ptr = fbb.GetBufferPointer();
    return {ptr, ptr + fbb.GetSize()};
  }

} // namespace generator


/* for dump use flatbuffer_service.h */




#endif __HYPERVOTE_UTILS__