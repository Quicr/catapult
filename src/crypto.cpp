#include "catapult/crypto.hpp"
#include "catapult/cwt.hpp"
#include "catapult/logging.hpp"
#include "catapult/base64.hpp"

#include <cbor.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <array>
#include <cstring>
#include <memory>

namespace catapult {

// RAII deleter implementations
void EvpKeyDeleter::operator()(EVP_PKEY* key) const noexcept {
  if (key) EVP_PKEY_free(key);
}

void BioDeleter::operator()(BIO* bio) const noexcept {
  if (bio) BIO_free(bio);
}


/**
 * @brief RAII wrapper for OpenSSL contexts
 */
template<typename T, void(*Deleter)(T*)>
class OpenSSLWrapper {
public:
  explicit OpenSSLWrapper(T* ptr) : ptr_(ptr) {}
  ~OpenSSLWrapper() { if (ptr_) Deleter(ptr_); }
  
  // Move-only semantics
  OpenSSLWrapper(const OpenSSLWrapper&) = delete;
  OpenSSLWrapper& operator=(const OpenSSLWrapper&) = delete;
  OpenSSLWrapper(OpenSSLWrapper&& other) noexcept : ptr_(other.ptr_) { other.ptr_ = nullptr; }
  OpenSSLWrapper& operator=(OpenSSLWrapper&& other) noexcept {
    if (this != &other) {
      if (ptr_) Deleter(ptr_);
      ptr_ = other.ptr_;
      other.ptr_ = nullptr;
    }
    return *this;
  }
  
  T* get() const noexcept { return ptr_; }
  T* release() noexcept { T* tmp = ptr_; ptr_ = nullptr; return tmp; }
  
private:
  T* ptr_;
};

using EvpMdCtxWrapper = OpenSSLWrapper<EVP_MD_CTX, EVP_MD_CTX_free>;
using EvpPkeyCtxWrapper = OpenSSLWrapper<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using EvpCipherCtxWrapper = OpenSSLWrapper<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>;


std::vector<uint8_t> hashSha256(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
  SHA256(data.data(), data.size(), hash.data());
  return hash;
}

// Base structure builder - handles common CBOR operations
class SigStructureBuilder {
protected:
  CborItemPtr createArray(size_t size) {
    auto array = CborItemPtr(cbor_new_definite_array(size));
    if (!array) {
      throw InvalidCborError("Failed to create Sig_structure array");
    }
    return array;
  }
  
  void addString(CborItemPtr& array, const std::string& value) {
    auto item = CborItemPtr(cbor_build_string(value.c_str()));
    if (!item || !cbor_array_push(array.get(), item.release())) {
      throw InvalidCborError("Failed to add string to Sig_structure");
    }
  }
  
  void addByteString(CborItemPtr& array, const std::vector<uint8_t>& data) {
    auto item = CborItemPtr(cbor_build_bytestring(data.data(), data.size()));
    if (!item || !cbor_array_push(array.get(), item.release())) {
      throw InvalidCborError("Failed to add bytestring to Sig_structure");
    }
  }
  
  std::vector<uint8_t> serialize(CborItemPtr& structure) {
    unsigned char* raw_buffer;
    size_t buffer_size;
    size_t length = cbor_serialize_alloc(structure.get(), &raw_buffer, &buffer_size);
    
    if (length == 0) {
      CAT_LOG_ERROR("Sig_structure serialization failed");
      throw InvalidCborError("Failed to serialize Sig_structure");
    }
    
    auto buffer = CborBufferPtr(raw_buffer);
    return std::vector<uint8_t>(buffer.get(), buffer.get() + length);
  }

public:
  virtual ~SigStructureBuilder() = default;
  virtual std::vector<uint8_t> build() = 0;
};

// Single signature implementation
class SingleSignatureStructureBuilder : public SigStructureBuilder {
private:
  std::vector<uint8_t> protectedHeader_;
  std::vector<uint8_t> externalAAD_;
  std::vector<uint8_t> payload_;

public:
  SingleSignatureStructureBuilder(const std::vector<uint8_t>& protectedHeader,
                                  const std::vector<uint8_t>& externalAAD,
                                  const std::vector<uint8_t>& payload)
    : protectedHeader_(protectedHeader), externalAAD_(externalAAD), payload_(payload) {}
  
  std::vector<uint8_t> build() override {
    try {
      // Create 4-element array for COSE_Sign1
      auto sigStructure = createArray(4);
      
      // Add context "Signature1"
      addString(sigStructure, "Signature1");
      
      // Add body_protected
      addByteString(sigStructure, protectedHeader_);
      
      // Add external_aad
      addByteString(sigStructure, externalAAD_);
      
      // Add payload
      addByteString(sigStructure, payload_);
      
      return serialize(sigStructure);
      
    } catch (const std::exception& e) {
      CAT_LOG_ERROR("Failed to create COSE_Sign1 Sig_structure: {}", e.what());
      throw InvalidCborError(std::string("COSE_Sign1 Sig_structure creation failed: ") + e.what());
    }
  }
};

// Multi-signature implementation  
class MultiSignatureStructureBuilder : public SigStructureBuilder {
private:
  std::vector<uint8_t> bodyProtectedHeader_;
  std::vector<uint8_t> signatureProtectedHeader_;
  std::vector<uint8_t> externalAAD_;
  std::vector<uint8_t> payload_;

public:
  MultiSignatureStructureBuilder(const std::vector<uint8_t>& bodyProtectedHeader,
                                 const std::vector<uint8_t>& signatureProtectedHeader,
                                 const std::vector<uint8_t>& externalAAD,
                                 const std::vector<uint8_t>& payload)
    : bodyProtectedHeader_(bodyProtectedHeader), 
      signatureProtectedHeader_(signatureProtectedHeader),
      externalAAD_(externalAAD), 
      payload_(payload) {}
  
  std::vector<uint8_t> build() override {
    try {
      // Create 5-element array for COSE_Sign
      auto sigStructure = createArray(5);
      
      // Add context "Signature"
      addString(sigStructure, "Signature");
      
      // Add body_protected
      addByteString(sigStructure, bodyProtectedHeader_);
      
      // Add sign_protected
      addByteString(sigStructure, signatureProtectedHeader_);
      
      // Add external_aad
      addByteString(sigStructure, externalAAD_);
      
      // Add payload
      addByteString(sigStructure, payload_);
      
      return serialize(sigStructure);
      
    } catch (const std::exception& e) {
      CAT_LOG_ERROR("Failed to create COSE_Sign Sig_structure: {}", e.what());
      throw InvalidCborError(std::string("COSE_Sign Sig_structure creation failed: ") + e.what());
    }
  }
};

std::vector<uint8_t> createCoseSign1Input(const std::vector<uint8_t>& protectedHeader,
                                          const std::vector<uint8_t>& payload,
                                          const std::vector<uint8_t>& externalAAD) {
  SingleSignatureStructureBuilder builder(protectedHeader, externalAAD, payload);
  return builder.build();
}

std::vector<uint8_t> createCoseSignInput(const std::vector<uint8_t>& bodyProtectedHeader,
                                         const std::vector<uint8_t>& signatureProtectedHeader,
                                         const std::vector<uint8_t>& externalAAD,
                                         const std::vector<uint8_t>& payload) {
  MultiSignatureStructureBuilder builder(bodyProtectedHeader, signatureProtectedHeader, externalAAD, payload);
  return builder.build();
}

std::vector<uint8_t> createJwtSigningInput(const std::vector<uint8_t>& header,
                                          const std::vector<uint8_t>& payload) {
  // Legacy JWT-style signing input for testing purposes.
  std::string headerB64 = base64UrlEncode(header);
  std::string payloadB64 = base64UrlEncode(payload);
  std::string signingInput = headerB64 + "." + payloadB64;
  return std::vector<uint8_t>(signingInput.begin(), signingInput.end());
}

//
// HmacSha256Algorithm
//

SecureVector<uint8_t> HmacSha256Algorithm::generateSecureKey() {
  CAT_LOG_DEBUG("Generating secure HMAC256 key of {} bytes", crypto_constants::HMAC_KEY_SIZE);
  SecureVector<uint8_t> key(crypto_constants::HMAC_KEY_SIZE);
  if (RAND_bytes(key.data(), crypto_constants::HMAC_KEY_SIZE) != 1) {
    CAT_LOG_ERROR("Failed to generate random bytes for HMAC key");
    unsigned long err = ERR_get_error();
    if (err == 0) {
      throwOsError("RAND_bytes");
    } else {
      throw CryptoError("Failed to generate random key: OpenSSL error " + std::to_string(err));
    }
  }
  CAT_LOG_DEBUG("Successfully generated secure HMAC256 key");
  return key;
}

std::vector<uint8_t> HmacSha256Algorithm::generateKey() {
  std::vector<uint8_t> key(crypto_constants::HMAC_KEY_SIZE);
  if (RAND_bytes(key.data(), crypto_constants::HMAC_KEY_SIZE) != 1) {
    unsigned long err = ERR_get_error();
    if (err == 0) {
      throwOsError("RAND_bytes");
    } else {
      throw CryptoError("Failed to generate random key: OpenSSL error " + std::to_string(err));
    }
  }
  return key;
}

std::vector<uint8_t> HmacSha256Algorithm::signImpl(
    std::span<const uint8_t> data) const {
  // Use secure memory for intermediate computation to protect against memory analysis
  SecureVector<uint8_t> secure_result(EVP_MAX_MD_SIZE);
  unsigned int len;

  if (!HMAC(EVP_sha256(), key_.data(), key_.size(), data.data(), data.size(),
            secure_result.data(), &len)) {
    throw CryptoError("HMAC signing failed");
  }

  // Return regular vector for API compatibility (signature is not secret)
  return std::vector<uint8_t>(secure_result.begin(), secure_result.begin() + len);
}

bool HmacSha256Algorithm::verifyImpl(std::span<const uint8_t> data,
                                     std::span<const uint8_t> signature) const {
  try {
    auto computedSignature = signImpl(data);
    // Use constant-time comparison to prevent timing attacks
    return secure_utils::constantTimeEqual(std::span<const uint8_t>(computedSignature), signature);
  } catch (const CryptoError&) {
    return false;
  }
}

int64_t HmacSha256Algorithm::algorithmId() const { return ALG_HMAC256_256; }

// Default implementation for base class - throws error for non-encryption algorithms
std::vector<uint8_t> CryptographicAlgorithm::encryptImpl(std::span<const uint8_t>, 
                                                         std::span<const uint8_t>) const {
  throw CryptoError("Algorithm does not support encryption");
}

std::vector<uint8_t> CryptographicAlgorithm::decryptImpl(std::span<const uint8_t>, 
                                                         std::span<const uint8_t>) const {
  throw CryptoError("Algorithm does not support decryption");
}


//
// ES256 Implementation
//

struct Es256Algorithm::Impl {
  EvpKeyPtr privateKey;
  EvpKeyPtr publicKey;
  Impl() = default;
};

void Es256Algorithm::initializeImpl() {
  try {
    pImpl_ = std::make_unique<Impl>();
  } catch (const std::bad_alloc&) {
    throwOsError("Es256Algorithm constructor memory allocation");
  }
}

void Es256Algorithm::loadPrivateKey(const uint8_t* keyData, size_t keySize) {
  auto priv_bio = BioPtr(BIO_new_mem_buf(keyData, keySize));
  pImpl_->privateKey.reset(d2i_PrivateKey_bio(priv_bio.get(), nullptr));
  
  if (!pImpl_->privateKey) {
    throw CryptoError("Failed to load private key");
  }
}

void Es256Algorithm::loadPublicKey(const uint8_t* keyData, size_t keySize) {
  auto pub_bio = BioPtr(BIO_new_mem_buf(keyData, keySize));
  pImpl_->publicKey.reset(d2i_PUBKEY_bio(pub_bio.get(), nullptr));
  
  if (!pImpl_->publicKey) {
    throw CryptoError("Failed to load public key");
  }
}


Es256Algorithm::Es256Algorithm() {
  initializeImpl();
  auto keyPair = generateKeyPair();
  loadPrivateKey(keyPair.first.data(), keyPair.first.size());
  loadPublicKey(keyPair.second.data(), keyPair.second.size());
}

Es256Algorithm::Es256Algorithm(const std::vector<uint8_t>& privateKey,
                               const std::vector<uint8_t>& publicKey) {
  initializeImpl();
  loadPrivateKey(privateKey.data(), privateKey.size());
  loadPublicKey(publicKey.data(), publicKey.size());
}

Es256Algorithm::Es256Algorithm(const SecureVector<uint8_t>& privateKey,
                               const std::vector<uint8_t>& publicKey) {
  initializeImpl();
  loadPrivateKey(privateKey.data(), privateKey.size());
  loadPublicKey(publicKey.data(), publicKey.size());
}

Es256Algorithm::Es256Algorithm(const std::vector<uint8_t>& publicKey) {
  initializeImpl();
  loadPublicKey(publicKey.data(), publicKey.size());
}

Es256Algorithm::~Es256Algorithm() = default;

Es256Algorithm::Es256Algorithm(Es256Algorithm&& other) noexcept
    : pImpl_(std::move(other.pImpl_)) {}

Es256Algorithm& Es256Algorithm::operator=(Es256Algorithm&& other) noexcept {
  if (this != &other) {
    pImpl_ = std::move(other.pImpl_);
  }
  return *this;
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
Es256Algorithm::generateKeyPair() {
  CAT_LOG_DEBUG("Generating ES256 key pair");
  auto pctx = EvpPkeyCtxWrapper(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
  if (!pctx.get()) {
    CAT_LOG_ERROR("Failed to create EC key context for ES256");
    throw CryptoError("Failed to create EC key context");
  }

  if (EVP_PKEY_keygen_init(pctx.get()) <= 0) {
    throw CryptoError("Failed to initialize EC key generation");
  }

  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_X9_62_prime256v1) <= 0) {
    throw CryptoError("Failed to set EC curve");
  }

  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) {
    throw CryptoError("Failed to generate EC key pair");
  }

  // Extract private and public keys as DER using RAII wrappers
  auto priv_bio = BioPtr(BIO_new(BIO_s_mem()));
  auto pub_bio = BioPtr(BIO_new(BIO_s_mem()));
  auto pkey_wrapper = EvpKeyPtr(pkey);  // Wrap for automatic cleanup

  if (!priv_bio.get() || !pub_bio.get()) {
    throw CryptoError("Failed to create BIO objects");
  }

  if (!i2d_PrivateKey_bio(priv_bio.get(), pkey) || !i2d_PUBKEY_bio(pub_bio.get(), pkey)) {
    throw CryptoError("Failed to serialize keys");
  }

  char* priv_data;
  char* pub_data;
  long priv_len = BIO_get_mem_data(priv_bio.get(), &priv_data);
  long pub_len = BIO_get_mem_data(pub_bio.get(), &pub_data);

  std::vector<uint8_t> privateKey(priv_data, priv_data + priv_len);
  std::vector<uint8_t> publicKey(pub_data, pub_data + pub_len);

  return {privateKey, publicKey};
}

std::pair<SecureVector<uint8_t>, std::vector<uint8_t>>
Es256Algorithm::generateSecureKeyPair() {
  auto keyPair = generateKeyPair();
  
  // Convert private key to secure memory, keep public key in regular memory
  SecureVector<uint8_t> securePrivateKey(keyPair.first.begin(), keyPair.first.end());
  
  return std::make_pair(std::move(securePrivateKey), std::move(keyPair.second));
}

std::vector<uint8_t> Es256Algorithm::getPublicKey() const {
  if (!pImpl_->publicKey) {
    return std::vector<uint8_t>();
  }
  
  auto bio = BioPtr(BIO_new(BIO_s_mem()));
  if (!i2d_PUBKEY_bio(bio.get(), pImpl_->publicKey.get())) {
    return std::vector<uint8_t>();
  }
  
  char* data;
  long len = BIO_get_mem_data(bio.get(), &data);
  std::vector<uint8_t> result(data, data + len);
  
  return result;
}

std::vector<uint8_t> Es256Algorithm::signImpl(std::span<const uint8_t> data) const {
  if (!pImpl_->privateKey) {
    throw CryptoError("No private key available for signing");
  }

  auto mdctx = EvpMdCtxWrapper(EVP_MD_CTX_new());
  if (!mdctx.get()) throw CryptoError("Failed to create signing context");

  if (EVP_DigestSignInit(mdctx.get(), nullptr, EVP_sha256(), nullptr,
                         pImpl_->privateKey.get()) <= 0) {
    throw CryptoError("Failed to initialize signing");
  }

  if (EVP_DigestSignUpdate(mdctx.get(), data.data(), data.size()) <= 0) {
    throw CryptoError("Failed to update signing context");
  }

  size_t sigLen;
  if (EVP_DigestSignFinal(mdctx.get(), nullptr, &sigLen) <= 0) {
    throw CryptoError("Failed to determine signature length");
  }

  std::vector<uint8_t> signature(sigLen);
  if (EVP_DigestSignFinal(mdctx.get(), signature.data(), &sigLen) <= 0) {
    throw CryptoError("Failed to sign data");
  }

  signature.resize(sigLen);
  return signature;
}

bool Es256Algorithm::verifyImpl(std::span<const uint8_t> data,
                                std::span<const uint8_t> signature) const {
  if (!pImpl_->publicKey) {
    return false;
  }

  // Use RAII wrapper for automatic cleanup
  auto mdctx = EvpMdCtxWrapper(EVP_MD_CTX_new());
  if (!mdctx.get()) return false;

  if (EVP_DigestVerifyInit(mdctx.get(), nullptr, EVP_sha256(), nullptr,
                           pImpl_->publicKey.get()) <= 0) {
    return false;
  }

  if (EVP_DigestVerifyUpdate(mdctx.get(), data.data(), data.size()) <= 0) {
    return false;
  }

  int result = EVP_DigestVerifyFinal(mdctx.get(), signature.data(), signature.size());
  return result == 1;
}

int64_t Es256Algorithm::algorithmId() const { return ALG_ES256; }

//
// PS256 Implementation (RSA-PSS with SHA-256)
//

struct Ps256Algorithm::Impl {
  EvpKeyPtr privateKey;
  EvpKeyPtr publicKey;

  Impl() = default;
  
};


void Ps256Algorithm::initializeImpl() {
  try {
    pImpl_ = std::make_unique<Impl>();
  } catch (const std::bad_alloc&) {
    throwOsError("Ps256Algorithm constructor memory allocation");
  }
}

void Ps256Algorithm::loadPrivateKey(const uint8_t* keyData, size_t keySize) {
  auto priv_bio = BioPtr(BIO_new_mem_buf(keyData, keySize));
  if (!priv_bio) {
    throw CryptoError("Failed to create BIO for private key");
  }
  pImpl_->privateKey.reset(d2i_PrivateKey_bio(priv_bio.get(), nullptr));
  if (!pImpl_->privateKey) {
    throw CryptoError("Failed to load private key");
  }
}

void Ps256Algorithm::loadPublicKey(const uint8_t* keyData, size_t keySize) {
  auto pub_bio = BioPtr(BIO_new_mem_buf(keyData, keySize));
  if (!pub_bio) {
    throw CryptoError("Failed to create BIO for public key");
  }
  pImpl_->publicKey.reset(d2i_PUBKEY_bio(pub_bio.get(), nullptr));
  if (!pImpl_->publicKey) {
    throw CryptoError("Failed to load public key");
  }
}

Ps256Algorithm::Ps256Algorithm() {
  initializeImpl();
  auto keyPair = generateKeyPair();
  loadPrivateKey(keyPair.first.data(), keyPair.first.size());
  loadPublicKey(keyPair.second.data(), keyPair.second.size());
}

Ps256Algorithm::Ps256Algorithm(const std::vector<uint8_t>& privateKey,
                               const std::vector<uint8_t>& publicKey) {
  initializeImpl();
  loadPrivateKey(privateKey.data(), privateKey.size());
  loadPublicKey(publicKey.data(), publicKey.size());
}

Ps256Algorithm::Ps256Algorithm(const SecureVector<uint8_t>& privateKey,
                               const std::vector<uint8_t>& publicKey) {
  initializeImpl();
  loadPrivateKey(privateKey.data(), privateKey.size());
  loadPublicKey(publicKey.data(), publicKey.size());
}

Ps256Algorithm::Ps256Algorithm(const std::vector<uint8_t>& publicKey) {
  initializeImpl();
  loadPublicKey(publicKey.data(), publicKey.size());
}

Ps256Algorithm::~Ps256Algorithm() = default;

Ps256Algorithm::Ps256Algorithm(Ps256Algorithm&& other) noexcept
    : pImpl_(std::move(other.pImpl_)) {}

Ps256Algorithm& Ps256Algorithm::operator=(Ps256Algorithm&& other) noexcept {
  if (this != &other) {
    pImpl_ = std::move(other.pImpl_);
  }
  return *this;
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
Ps256Algorithm::generateKeyPair() {
  // Use RAII wrapper for automatic cleanup
  auto pctx = EvpPkeyCtxWrapper(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
  if (!pctx.get()) throw CryptoError("Failed to create RSA key context");

  if (EVP_PKEY_keygen_init(pctx.get()) <= 0) {
    throw CryptoError("Failed to initialize RSA key generation");
  }

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx.get(), 2048) <= 0) {
    throw CryptoError("Failed to set RSA key size");
  }

  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) {
    throw CryptoError("Failed to generate RSA key pair");
  }

  // Extract private and public keys as DER using RAII wrappers
  auto priv_bio = BioPtr(BIO_new(BIO_s_mem()));
  auto pub_bio = BioPtr(BIO_new(BIO_s_mem()));
  auto pkey_wrapper = EvpKeyPtr(pkey);  // Wrap for automatic cleanup

  if (!priv_bio.get() || !pub_bio.get()) {
    throw CryptoError("Failed to create BIO objects");
  }

  if (!i2d_PrivateKey_bio(priv_bio.get(), pkey) || !i2d_PUBKEY_bio(pub_bio.get(), pkey)) {
    throw CryptoError("Failed to serialize keys");
  }

  char* priv_data;
  char* pub_data;
  long priv_len = BIO_get_mem_data(priv_bio.get(), &priv_data);
  long pub_len = BIO_get_mem_data(pub_bio.get(), &pub_data);

  std::vector<uint8_t> privateKey(priv_data, priv_data + priv_len);
  std::vector<uint8_t> publicKey(pub_data, pub_data + pub_len);

  return {privateKey, publicKey};
}

std::pair<SecureVector<uint8_t>, std::vector<uint8_t>>
Ps256Algorithm::generateSecureKeyPair() {
  auto keyPair = generateKeyPair();
  
  // Convert private key to secure memory, keep public key in regular memory
  SecureVector<uint8_t> securePrivateKey(keyPair.first.begin(), keyPair.first.end());
  
  return std::make_pair(std::move(securePrivateKey), std::move(keyPair.second));
}

std::vector<uint8_t> Ps256Algorithm::getPublicKey() const {
  if (!pImpl_->publicKey) {
    return std::vector<uint8_t>();
  }
  
  auto bio = BioPtr(BIO_new(BIO_s_mem()));
  if (!i2d_PUBKEY_bio(bio.get(), pImpl_->publicKey.get())) {
    return std::vector<uint8_t>();
  }
  
  char* data;
  long len = BIO_get_mem_data(bio.get(), &data);
  std::vector<uint8_t> result(data, data + len);
  
  return result;
}

std::vector<uint8_t> Ps256Algorithm::signImpl(std::span<const uint8_t> data) const {
  if (!pImpl_->privateKey) {
    throw CryptoError("No private key available for signing");
  }

  // Use RAII wrapper for automatic cleanup
  auto pctx = EvpPkeyCtxWrapper(EVP_PKEY_CTX_new(pImpl_->privateKey.get(), nullptr));
  if (!pctx.get()) throw CryptoError("Failed to create signing context");

  if (EVP_PKEY_sign_init(pctx.get()) <= 0) {
    throw CryptoError("Failed to initialize signing");
  }

  if (EVP_PKEY_CTX_set_rsa_padding(pctx.get(), RSA_PKCS1_PSS_PADDING) <= 0) {
    throw CryptoError("Failed to set PSS padding");
  }

  if (EVP_PKEY_CTX_set_signature_md(pctx.get(), EVP_sha256()) <= 0) {
    throw CryptoError("Failed to set signature hash");
  }

  std::vector<uint8_t> dataVec(data.begin(), data.end());
  auto hash = hashSha256(dataVec);
  size_t sigLen;
  if (EVP_PKEY_sign(pctx.get(), nullptr, &sigLen, hash.data(), hash.size()) <= 0) {
    throw CryptoError("Failed to determine signature length");
  }

  std::vector<uint8_t> signature(sigLen);
  if (EVP_PKEY_sign(pctx.get(), signature.data(), &sigLen, hash.data(),
                    hash.size()) <= 0) {
    throw CryptoError("Failed to sign data");
  }

  signature.resize(sigLen);
  return signature;
}

bool Ps256Algorithm::verifyImpl(std::span<const uint8_t> data,
                                std::span<const uint8_t> signature) const {
  if (!pImpl_->publicKey) {
    return false;
  }

  // Use RAII wrapper for automatic cleanup
  auto pctx = EvpPkeyCtxWrapper(EVP_PKEY_CTX_new(pImpl_->publicKey.get(), nullptr));
  if (!pctx.get()) return false;

  if (EVP_PKEY_verify_init(pctx.get()) <= 0) {
    return false;
  }

  if (EVP_PKEY_CTX_set_rsa_padding(pctx.get(), RSA_PKCS1_PSS_PADDING) <= 0) {
    return false;
  }

  if (EVP_PKEY_CTX_set_signature_md(pctx.get(), EVP_sha256()) <= 0) {
    return false;
  }

  std::vector<uint8_t> dataVec(data.begin(), data.end());
  auto hash = hashSha256(dataVec);
  int result = EVP_PKEY_verify(pctx.get(), signature.data(), signature.size(),
                               hash.data(), hash.size());

  return result == 1;
}

int64_t Ps256Algorithm::algorithmId() const { return ALG_PS256; }

//
// AES-GCM Algorithm
//

AesGcmAlgorithm::AesGcmAlgorithm(const std::vector<uint8_t>& key, int64_t algorithmId)
  : key_(key.begin(), key.end()), algorithmId_(algorithmId) {

  if (!crypto_constants::is_valid_aes_key_size(key.size())) {
    throw CryptoError("Invalid AES key size");
  }
  
  // Validate algorithm ID matches key size
  switch (algorithmId) {
    case ALG_A128GCM:
      if (key.size() != crypto_constants::AES128_KEY_SIZE) {
        throw CryptoError("Key size doesn't match algorithm (A128GCM requires 128-bit key)");
      }
      break;
    case ALG_A192GCM:
      if (key.size() != crypto_constants::AES192_KEY_SIZE) {
        throw CryptoError("Key size doesn't match algorithm (A192GCM requires 192-bit key)");
      }
      break;
    case ALG_A256GCM:
      if (key.size() != crypto_constants::AES256_KEY_SIZE) {
        throw CryptoError("Key size doesn't match algorithm (A256GCM requires 256-bit key)");
      }
      break;
    default:
      throw CryptoError("Invalid AES-GCM algorithm identifier");
  }
}

AesGcmAlgorithm::AesGcmAlgorithm(SecureVector<uint8_t> key, int64_t algorithmId) 
  : key_(std::move(key)), algorithmId_(algorithmId) {
  if (!crypto_constants::is_valid_aes_key_size(key_.size())) {
    throw CryptoError("Invalid AES key size");
  }
}

SecureVector<uint8_t> AesGcmAlgorithm::generateSecureKey(size_t keySize) {
  if (!crypto_constants::is_valid_aes_key_size(keySize)) {
    throw CryptoError("Invalid AES key size");
  }
  
  CAT_LOG_DEBUG("Generating secure AES key of {} bytes", keySize);
  SecureVector<uint8_t> key(keySize);
  if (RAND_bytes(key.data(), keySize) != 1) {
    CAT_LOG_ERROR("Failed to generate random bytes for AES key");
    unsigned long err = ERR_get_error();
    if (err == 0) {
      throwOsError("RAND_bytes");
    } else {
      throw CryptoError("Failed to generate random key: OpenSSL error " + std::to_string(err));
    }
  }
  CAT_LOG_DEBUG("Successfully generated secure AES key");
  return key;
}

std::vector<uint8_t> AesGcmAlgorithm::generateIV() {
  // 12 bytes IV for AES-GCM only
  std::vector<uint8_t> iv(crypto_constants::GCM_IV_SIZE);
  if (RAND_bytes(iv.data(), crypto_constants::GCM_IV_SIZE) != 1) {
    unsigned long err = ERR_get_error();
    if (err == 0) {
      throwOsError("RAND_bytes");
    } else {
      throw CryptoError("Failed to generate random IV: OpenSSL error " + std::to_string(err));
    }
  }
  return iv;
}

std::vector<uint8_t> AesGcmAlgorithm::signImpl(std::span<const uint8_t>) const {
  throw CryptoError("AES-GCM algorithm does not support signing");
}

bool AesGcmAlgorithm::verifyImpl(std::span<const uint8_t>, std::span<const uint8_t>) const {
  throw CryptoError("AES-GCM algorithm does not support signature verification");
}

std::vector<uint8_t> AesGcmAlgorithm::encryptImpl(std::span<const uint8_t> data,
                                                  std::span<const uint8_t> iv) const {
  if (iv.size() != crypto_constants::GCM_IV_SIZE) {
    throw CryptoError("Invalid IV size for AES-GCM (must be 12 bytes)");
  }

  // Use RAII wrapper for automatic cleanup
  auto ctx = EvpCipherCtxWrapper(EVP_CIPHER_CTX_new());
  if (!ctx.get()) {
    throw CryptoError("Failed to create AES-GCM context");
  }
  
  // Determine cipher type based on key size
  const EVP_CIPHER* cipher;
  switch (key_.size()) {
    case crypto_constants::AES128_KEY_SIZE:
      cipher = EVP_aes_128_gcm();
      break;
    case crypto_constants::AES192_KEY_SIZE:
      cipher = EVP_aes_192_gcm();
      break;
    case crypto_constants::AES256_KEY_SIZE:
      cipher = EVP_aes_256_gcm();
      break;
    default:
      throw CryptoError("Invalid AES key size");
  }

  // Initialize encryption
  if (EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, key_.data(), iv.data()) != 1) {
    throw CryptoError("Failed to initialize AES-GCM encryption");
  }

  // Encrypt data
  std::vector<uint8_t> ciphertext(data.size() + crypto_constants::GCM_TAG_SIZE);
  int len;
  if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, data.data(), data.size()) != 1) {
    throw CryptoError("Failed to encrypt data");
  }
  int ciphertext_len = len;

  // Finalize encryption
  if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1) {
    throw CryptoError("Failed to finalize AES-GCM encryption");
  }
  ciphertext_len += len;

  // Get authentication tag
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, crypto_constants::GCM_TAG_SIZE, 
                         ciphertext.data() + ciphertext_len) != 1) {
    throw CryptoError("Failed to get AES-GCM authentication tag");
  }

  ciphertext.resize(ciphertext_len + crypto_constants::GCM_TAG_SIZE);
  return ciphertext;
}

std::vector<uint8_t> AesGcmAlgorithm::decryptImpl(std::span<const uint8_t> encryptedData,
                                                  std::span<const uint8_t> iv) const {
  if (iv.size() != crypto_constants::GCM_IV_SIZE) {
    throw CryptoError("Invalid IV size for AES-GCM (must be 12 bytes)");
  }
  
  if (encryptedData.size() < crypto_constants::GCM_TAG_SIZE) {
    throw CryptoError("Encrypted data too short (missing authentication tag)");
  }

  auto ctx = EvpCipherCtxWrapper(EVP_CIPHER_CTX_new());
  if (!ctx.get()) {
    throw CryptoError("Failed to create AES-GCM context");
  }
  
  // Determine cipher type based on key size
  const EVP_CIPHER* cipher;
  switch (key_.size()) {
    case crypto_constants::AES128_KEY_SIZE:
      cipher = EVP_aes_128_gcm();
      break;
    case crypto_constants::AES192_KEY_SIZE:
      cipher = EVP_aes_192_gcm();
      break;
    case crypto_constants::AES256_KEY_SIZE:
      cipher = EVP_aes_256_gcm();
      break;
    default:
      throw CryptoError("Invalid AES key size");
  }

  // Initialize decryption
  if (EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, key_.data(), iv.data()) != 1) {
    throw CryptoError("Failed to initialize AES-GCM decryption");
  }

  // Separate ciphertext and tag
  size_t ciphertext_len = encryptedData.size() - crypto_constants::GCM_TAG_SIZE;
  const uint8_t* ciphertext = encryptedData.data();
  const uint8_t* tag = encryptedData.data() + ciphertext_len;

  // Set authentication tag
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, crypto_constants::GCM_TAG_SIZE, 
                         const_cast<uint8_t*>(tag)) != 1) {
    throw CryptoError("Failed to set AES-GCM authentication tag");
  }

  // Decrypt data
  std::vector<uint8_t> plaintext(ciphertext_len);
  int len;
  if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext, ciphertext_len) != 1) {
    throw CryptoError("Failed to decrypt data");
  }
  int plaintext_len = len;

  // Finalize decryption (this verifies the authentication tag)
  int ret = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len);
  
  if (ret <= 0) {
    throw CryptoError("AES-GCM authentication tag verification failed");
  }
  plaintext_len += len;

  plaintext.resize(plaintext_len);
  return plaintext;
}

int64_t AesGcmAlgorithm::algorithmId() const { 
  return algorithmId_; 
}

//
// ChaCha20-Poly1305 Implementation
//

ChaCha20Poly1305Algorithm::ChaCha20Poly1305Algorithm(const std::vector<uint8_t>& key)
  : key_(key.begin(), key.end()) {
  if (key.size() != crypto_constants::ChaCha20_KEY_SIZE) {
    throw CryptoError("Invalid ChaCha20 key size (must be 32 bytes)");
  }
}

ChaCha20Poly1305Algorithm::ChaCha20Poly1305Algorithm(SecureVector<uint8_t> key) 
  : key_(std::move(key)) {
  if (key_.size() != crypto_constants::ChaCha20_KEY_SIZE) {
    throw CryptoError("Invalid ChaCha20 key size (must be 32 bytes)");
  }
}

SecureVector<uint8_t> ChaCha20Poly1305Algorithm::generateSecureKey() {
  CAT_LOG_DEBUG("Generating secure ChaCha20 key of {} bytes", crypto_constants::ChaCha20_KEY_SIZE);
  SecureVector<uint8_t> key(crypto_constants::ChaCha20_KEY_SIZE);
  if (RAND_bytes(key.data(), crypto_constants::ChaCha20_KEY_SIZE) != 1) {
    CAT_LOG_ERROR("Failed to generate random bytes for ChaCha20 key");
    unsigned long err = ERR_get_error();
    if (err == 0) {
      throwOsError("RAND_bytes");
    } else {
      throw CryptoError("Failed to generate random key: OpenSSL error " + std::to_string(err));
    }
  }
  CAT_LOG_DEBUG("Successfully generated secure ChaCha20 key");
  return key;
}

std::vector<uint8_t> ChaCha20Poly1305Algorithm::generateNonce() {
  std::vector<uint8_t> nonce(crypto_constants::ChaCha20_NONCE_SIZE);
  if (RAND_bytes(nonce.data(), crypto_constants::ChaCha20_NONCE_SIZE) != 1) {
    unsigned long err = ERR_get_error();
    if (err == 0) {
      throwOsError("RAND_bytes");
    } else {
      throw CryptoError("Failed to generate random nonce: OpenSSL error " + std::to_string(err));
    }
  }
  return nonce;
}

std::vector<uint8_t> ChaCha20Poly1305Algorithm::signImpl(std::span<const uint8_t>) const {
  throw CryptoError("ChaCha20-Poly1305 algorithm does not support signing");
}

bool ChaCha20Poly1305Algorithm::verifyImpl(std::span<const uint8_t>, std::span<const uint8_t>) const {
  throw CryptoError("ChaCha20-Poly1305 algorithm does not support signature verification");
}

std::vector<uint8_t> ChaCha20Poly1305Algorithm::encryptImpl(std::span<const uint8_t> data,
                                                            std::span<const uint8_t> nonce) const {
  if (nonce.size() != crypto_constants::ChaCha20_NONCE_SIZE) {
    throw CryptoError("Invalid nonce size for ChaCha20-Poly1305 (must be 12 bytes)");
  }

  auto ctx = EvpCipherCtxWrapper(EVP_CIPHER_CTX_new());
  if (!ctx.get()) {
    throw CryptoError("Failed to create ChaCha20-Poly1305 context");
  }

  // Initialize encryption
  if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, key_.data(), nonce.data()) != 1) {
    throw CryptoError("Failed to initialize ChaCha20-Poly1305 encryption");
  }

  // Encrypt data
  std::vector<uint8_t> ciphertext(data.size() + crypto_constants::ChaCha20_TAG_SIZE);
  int len;
  if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, data.data(), data.size()) != 1) {
    throw CryptoError("Failed to encrypt data");
  }
  int ciphertext_len = len;

  // Finalize encryption
  if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1) {
    throw CryptoError("Failed to finalize ChaCha20-Poly1305 encryption");
  }
  ciphertext_len += len;

  // Get authentication tag
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, crypto_constants::ChaCha20_TAG_SIZE, 
                         ciphertext.data() + ciphertext_len) != 1) {
    throw CryptoError("Failed to get ChaCha20-Poly1305 authentication tag");
  }

  ciphertext.resize(ciphertext_len + crypto_constants::ChaCha20_TAG_SIZE);
  return ciphertext;
}

std::vector<uint8_t> ChaCha20Poly1305Algorithm::decryptImpl(std::span<const uint8_t> encryptedData,
                                                            std::span<const uint8_t> nonce) const {
  if (nonce.size() != crypto_constants::ChaCha20_NONCE_SIZE) {
    throw CryptoError("Invalid nonce size for ChaCha20-Poly1305 (must be 12 bytes)");
  }
  
  if (encryptedData.size() < crypto_constants::ChaCha20_TAG_SIZE) {
    throw CryptoError("Encrypted data too short (missing authentication tag)");
  }

  // Use RAII wrapper for automatic cleanup
  auto ctx = EvpCipherCtxWrapper(EVP_CIPHER_CTX_new());
  if (!ctx.get()) {
    throw CryptoError("Failed to create ChaCha20-Poly1305 context");
  }

  // Initialize decryption
  if (EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, key_.data(), nonce.data()) != 1) {
    throw CryptoError("Failed to initialize ChaCha20-Poly1305 decryption");
  }

  // Separate ciphertext and tag
  size_t ciphertext_len = encryptedData.size() - crypto_constants::ChaCha20_TAG_SIZE;
  const uint8_t* ciphertext = encryptedData.data();
  const uint8_t* tag = encryptedData.data() + ciphertext_len;

  // Set authentication tag
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, crypto_constants::ChaCha20_TAG_SIZE, 
                         const_cast<uint8_t*>(tag)) != 1) {
    throw CryptoError("Failed to set ChaCha20-Poly1305 authentication tag");
  }

  // Decrypt data
  std::vector<uint8_t> plaintext(ciphertext_len);
  int len;
  if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext, ciphertext_len) != 1) {
    throw CryptoError("Failed to decrypt data");
  }
  int plaintext_len = len;

  // Finalize decryption (this verifies the authentication tag)
  int ret = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len);
  
  if (ret <= 0) {
    throw CryptoError("ChaCha20-Poly1305 authentication tag verification failed");
  }
  plaintext_len += len;

  plaintext.resize(plaintext_len);
  return plaintext;
}

int64_t ChaCha20Poly1305Algorithm::algorithmId() const { 
  return ALG_ChaCha20_Poly1305; 
}

}  // namespace catapult