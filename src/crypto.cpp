#include "catapult/crypto.hpp"
#include "catapult/logging.hpp"

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


std::vector<uint8_t> hashSha256(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
  SHA256(data.data(), data.size(), hash.data());
  return hash;
}

std::vector<uint8_t> createSigningInput(const std::vector<uint8_t>& header,
                                        const std::vector<uint8_t>& payload) {
  std::string headerB64 = base64UrlEncode(header);
  std::string payloadB64 = base64UrlEncode(payload);
  std::string signingInput = headerB64 + "." + payloadB64;
  return std::vector<uint8_t>(signingInput.begin(), signingInput.end());
}

// HMAC SHA256 Implementation - updated for secure memory handling

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

std::vector<uint8_t> HmacSha256Algorithm::sign(
    const std::vector<uint8_t>& data) {
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

bool HmacSha256Algorithm::verify(const std::vector<uint8_t>& data,
                                 const std::vector<uint8_t>& signature) {
  try {
    auto computedSignature = sign(data);
    // Use constant-time comparison to prevent timing attacks
    return secure_utils::constantTimeEqual(computedSignature, signature);
  } catch (const CryptoError&) {
    return false;
  }
}

int64_t HmacSha256Algorithm::algorithmId() const { return ALG_HMAC256_256; }

// ES256 Implementation with RAII
struct Es256Algorithm::Impl {
  EvpKeyPtr privateKey;
  EvpKeyPtr publicKey;

  Impl() = default;
  
  // No need for custom destructor - RAII handles cleanup
};


Es256Algorithm::Es256Algorithm() {
  try {
    pImpl_ = std::make_unique<Impl>();
    auto keyPair = generateKeyPair();
    
    // Load private key from DER format using RAII
    auto priv_bio = BioPtr(BIO_new_mem_buf(keyPair.first.data(), keyPair.first.size()));
    pImpl_->privateKey.reset(d2i_PrivateKey_bio(priv_bio.get(), nullptr));
    
    // Load public key from DER format using RAII
    auto pub_bio = BioPtr(BIO_new_mem_buf(keyPair.second.data(), keyPair.second.size()));
    pImpl_->publicKey.reset(d2i_PUBKEY_bio(pub_bio.get(), nullptr));
    
    if (!pImpl_->privateKey || !pImpl_->publicKey) {
      throw CryptoError("Failed to load generated keys");
    }
  } catch (const std::bad_alloc&) {
    throwOsError("Es256Algorithm constructor memory allocation");
  }
}

Es256Algorithm::Es256Algorithm(const std::vector<uint8_t>& privateKey,
                               const std::vector<uint8_t>& publicKey) {
  try {
    pImpl_ = std::make_unique<Impl>();
    // Load private key from DER format using RAII
    auto priv_bio = BioPtr(BIO_new_mem_buf(privateKey.data(), privateKey.size()));
    pImpl_->privateKey.reset(d2i_PrivateKey_bio(priv_bio.get(), nullptr));
    
    // Load public key from DER format using RAII
    auto pub_bio = BioPtr(BIO_new_mem_buf(publicKey.data(), publicKey.size()));
    pImpl_->publicKey.reset(d2i_PUBKEY_bio(pub_bio.get(), nullptr));
    
    if (!pImpl_->privateKey || !pImpl_->publicKey) {
      throw CryptoError("Failed to load provided keys");
    }
  } catch (const std::bad_alloc&) {
    throwOsError("Es256Algorithm constructor memory allocation");
  }
}

Es256Algorithm::Es256Algorithm(const SecureVector<uint8_t>& privateKey,
                               const std::vector<uint8_t>& publicKey) {
  try {
    pImpl_ = std::make_unique<Impl>();
    // Load private key from DER format using RAII
    auto priv_bio = BioPtr(BIO_new_mem_buf(privateKey.data(), privateKey.size()));
    pImpl_->privateKey.reset(d2i_PrivateKey_bio(priv_bio.get(), nullptr));
    
    // Load public key from DER format using RAII
    auto pub_bio = BioPtr(BIO_new_mem_buf(publicKey.data(), publicKey.size()));
    pImpl_->publicKey.reset(d2i_PUBKEY_bio(pub_bio.get(), nullptr));
    
    if (!pImpl_->privateKey || !pImpl_->publicKey) {
      throw CryptoError("Failed to load provided keys");
    }
  } catch (const std::bad_alloc&) {
    throwOsError("Es256Algorithm constructor memory allocation");
  }
}

Es256Algorithm::Es256Algorithm(const std::vector<uint8_t>& publicKey) {
  try {
    pImpl_ = std::make_unique<Impl>();
    // Load public key from DER format using RAII (no private key for verification-only)
    auto pub_bio = BioPtr(BIO_new_mem_buf(publicKey.data(), publicKey.size()));
    pImpl_->publicKey.reset(d2i_PUBKEY_bio(pub_bio.get(), nullptr));
    
    if (!pImpl_->publicKey) {
      throw CryptoError("Failed to load provided public key");
    }
  } catch (const std::bad_alloc&) {
    throwOsError("Es256Algorithm constructor memory allocation");
  }
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
  // Use RAII wrapper for automatic cleanup
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

  // pctx will be automatically freed by RAII wrapper

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

  // All resources automatically freed by RAII wrappers
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

std::vector<uint8_t> Es256Algorithm::sign(const std::vector<uint8_t>& data) {
  if (!pImpl_->privateKey) {
    throw CryptoError("No private key available for signing");
  }

  // Use RAII wrapper for automatic cleanup
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

bool Es256Algorithm::verify(const std::vector<uint8_t>& data,
                            const std::vector<uint8_t>& signature) {
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

// PS256 Implementation with RAII
struct Ps256Algorithm::Impl {
  EvpKeyPtr privateKey;
  EvpKeyPtr publicKey;

  Impl() = default;
  
  // No need for custom destructor - RAII handles cleanup
};


Ps256Algorithm::Ps256Algorithm() {
  try {
    pImpl_ = std::make_unique<Impl>();
    auto keyPair = generateKeyPair();
    
    // Load private key from DER format using RAII
    auto priv_bio = BioPtr(BIO_new_mem_buf(keyPair.first.data(), keyPair.first.size()));
    pImpl_->privateKey.reset(d2i_PrivateKey_bio(priv_bio.get(), nullptr));
    
    // Load public key from DER format using RAII
    auto pub_bio = BioPtr(BIO_new_mem_buf(keyPair.second.data(), keyPair.second.size()));
    pImpl_->publicKey.reset(d2i_PUBKEY_bio(pub_bio.get(), nullptr));
    
    if (!pImpl_->privateKey || !pImpl_->publicKey) {
      throw CryptoError("Failed to load generated keys");
    }
  } catch (const std::bad_alloc&) {
    throwOsError("Ps256Algorithm constructor memory allocation");
  }
}

Ps256Algorithm::Ps256Algorithm(const std::vector<uint8_t>& privateKey,
                               const std::vector<uint8_t>& publicKey) {
  try {
    pImpl_ = std::make_unique<Impl>();
    // Load private key from DER format using RAII
    auto priv_bio = BioPtr(BIO_new_mem_buf(privateKey.data(), privateKey.size()));
    pImpl_->privateKey.reset(d2i_PrivateKey_bio(priv_bio.get(), nullptr));
    
    // Load public key from DER format using RAII
    auto pub_bio = BioPtr(BIO_new_mem_buf(publicKey.data(), publicKey.size()));
    pImpl_->publicKey.reset(d2i_PUBKEY_bio(pub_bio.get(), nullptr));
    
    if (!pImpl_->privateKey || !pImpl_->publicKey) {
      throw CryptoError("Failed to load provided keys");
    }
  } catch (const std::bad_alloc&) {
    throwOsError("Ps256Algorithm constructor memory allocation");
  }
}

Ps256Algorithm::Ps256Algorithm(const SecureVector<uint8_t>& privateKey,
                               const std::vector<uint8_t>& publicKey) {
  try {
    pImpl_ = std::make_unique<Impl>();
    // Load private key from DER format using RAII
    auto priv_bio = BioPtr(BIO_new_mem_buf(privateKey.data(), privateKey.size()));
    pImpl_->privateKey.reset(d2i_PrivateKey_bio(priv_bio.get(), nullptr));
    
    // Load public key from DER format using RAII
    auto pub_bio = BioPtr(BIO_new_mem_buf(publicKey.data(), publicKey.size()));
    pImpl_->publicKey.reset(d2i_PUBKEY_bio(pub_bio.get(), nullptr));
    
    if (!pImpl_->privateKey || !pImpl_->publicKey) {
      throw CryptoError("Failed to load provided keys");
    }
  } catch (const std::bad_alloc&) {
    throwOsError("Ps256Algorithm constructor memory allocation");
  }
}

Ps256Algorithm::Ps256Algorithm(const std::vector<uint8_t>& publicKey) {
  try {
    pImpl_ = std::make_unique<Impl>();
    // Load public key from DER format using RAII (no private key for verification-only)
    auto pub_bio = BioPtr(BIO_new_mem_buf(publicKey.data(), publicKey.size()));
    pImpl_->publicKey.reset(d2i_PUBKEY_bio(pub_bio.get(), nullptr));
    
    if (!pImpl_->publicKey) {
      throw CryptoError("Failed to load provided public key");
    }
  } catch (const std::bad_alloc&) {
    throwOsError("Ps256Algorithm constructor memory allocation");
  }
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

  // pctx will be automatically freed by RAII wrapper

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

  // All resources automatically freed by RAII wrappers
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

std::vector<uint8_t> Ps256Algorithm::sign(const std::vector<uint8_t>& data) {
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

  auto hash = hashSha256(data);
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

bool Ps256Algorithm::verify(const std::vector<uint8_t>& data,
                            const std::vector<uint8_t>& signature) {
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

  auto hash = hashSha256(data);
  int result = EVP_PKEY_verify(pctx.get(), signature.data(), signature.size(),
                               hash.data(), hash.size());

  return result == 1;
}

int64_t Ps256Algorithm::algorithmId() const { return ALG_PS256; }

}  // namespace catapult