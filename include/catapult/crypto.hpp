/**
 * @file cat_crypto.hpp
 * @brief Cryptographic algorithms and utilities for CAT tokens
 */

#pragma once

#include <concepts>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <cstring>
#include <cstdlib>
#include "memory_pool.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#include "error.hpp"
#include "base64.hpp"
#include "secure_vector.hpp"

// Forward declarations for OpenSSL types
typedef struct evp_pkey_st EVP_PKEY;
typedef struct bio_st BIO;

namespace catapult {

/// COSE Algorithm Identifiers with compile-time validation
constexpr int64_t ALG_HMAC256_256 = 5;  ///< HMAC 256/256
constexpr int64_t ALG_ES256 = -7;        ///< ECDSA w/ SHA-256
constexpr int64_t ALG_PS256 = -37;       ///< RSASSA-PSS w/ SHA-256

// Compile-time key size validation with enhanced safety
namespace crypto_constants {
  constexpr size_t HMAC_KEY_SIZE = 32;      ///< HMAC-SHA256 recommended key size
  constexpr size_t ES256_KEY_SIZE = 32;     ///< P-256 private key size
  constexpr size_t PS256_MIN_KEY_SIZE = 256; ///< RSA minimum key size in bytes
  
  consteval bool is_valid_hmac_key_size(size_t size) noexcept {
    return size >= 16 && size <= 64; // NIST recommendations
  }
  
  consteval bool is_valid_rsa_key_size(size_t size) noexcept {
    return size >= 256 && size <= 512; // 2048-4096 bits
  }
  
}

static_assert(crypto_constants::is_valid_hmac_key_size(crypto_constants::HMAC_KEY_SIZE),
              "HMAC key size is invalid");
static_assert(crypto_constants::is_valid_rsa_key_size(crypto_constants::PS256_MIN_KEY_SIZE), 
              "RSA minimum key size is invalid");
static_assert(crypto_constants::ES256_KEY_SIZE == 32,
              "ES256 key size must be exactly 32 bytes for P-256");


/**
 * @brief RAII wrapper for OpenSSL EVP_PKEY with shared ownership
 */
struct EvpKeyDeleter {
  void operator()(EVP_PKEY* key) const noexcept;
};
using EvpKeyPtr = std::unique_ptr<EVP_PKEY, EvpKeyDeleter>;
using SharedEvpKeyPtr = std::shared_ptr<EVP_PKEY>;

/**
 * @brief RAII wrapper for OpenSSL BIO
 */
struct BioDeleter {
  void operator()(BIO* bio) const noexcept;
};
using BioPtr = std::unique_ptr<BIO, BioDeleter>;


/**
 * @brief Concept for cryptographic algorithm data types
 */
template<typename T>
concept CryptoData = requires(T t) {
  std::data(t);
  std::size(t);
  typename T::value_type;
  requires std::same_as<typename T::value_type, uint8_t>;
};

/**
 * @brief Abstract base class for cryptographic algorithms
 */
class CryptographicAlgorithm {
 public:
  virtual ~CryptographicAlgorithm() = default;
  
  /**
   * @brief Sign data with the algorithm
   * @param data Data to sign
   * @return Signature bytes
   */
  template<CryptoData T>
  std::vector<uint8_t> sign(const T& data) {
    return signImpl({std::data(data), std::size(data)});
  }
  
  virtual std::vector<uint8_t> sign(const std::vector<uint8_t>& data) = 0;
  
  /**
   * @brief Verify a signature
   * @param data Original data
   * @param signature Signature to verify
   * @return True if signature is valid
   */
  template<CryptoData T1, CryptoData T2>
  bool verify(const T1& data, const T2& signature) {
    return verifyImpl({std::data(data), std::size(data)}, 
                     {std::data(signature), std::size(signature)});
  }
  
  virtual bool verify(const std::vector<uint8_t>& data,
                      const std::vector<uint8_t>& signature) = 0;
  
  /**
   * @brief Get the COSE algorithm identifier
   * @return Algorithm ID
   */
  virtual int64_t algorithmId() const = 0;

protected:
  virtual std::vector<uint8_t> signImpl(std::span<const uint8_t> data) {
    return sign(std::vector<uint8_t>(data.begin(), data.end()));
  }
  
  virtual bool verifyImpl(std::span<const uint8_t> data, 
                         std::span<const uint8_t> signature) {
    return verify(std::vector<uint8_t>(data.begin(), data.end()),
                 std::vector<uint8_t>(signature.begin(), signature.end()));
  }
};

/**
 * @brief HMAC-SHA256 algorithm implementation with secure memory handling
 */
class HmacSha256Algorithm : public CryptographicAlgorithm {
 private:
  SecureVector<uint8_t> key_;  ///< HMAC key with secure allocator

 public:
  /**
   * @brief Construct with existing key
   * @param key HMAC key bytes
   */
  explicit HmacSha256Algorithm(const std::vector<uint8_t>& key) : key_(key.begin(), key.end()) {
    static_assert(crypto_constants::is_valid_hmac_key_size(crypto_constants::HMAC_KEY_SIZE));
    if (key.size() < 16 || key.size() > 64) {
      throw CryptoError("Invalid HMAC key size");
    }
  }
  
  /**
   * @brief Construct with secure key vector
   */
  explicit HmacSha256Algorithm(SecureVector<uint8_t> key) : key_(std::move(key)) {
    if (key_.size() < 16 || key_.size() > 64) {
      throw CryptoError("Invalid HMAC key size");
    }
  }
  
  /**
   * @brief Generate a random HMAC key with secure storage
   * @return Generated key bytes in secure vector
   */
  static SecureVector<uint8_t> generateSecureKey();
  
  /**
   * @brief Generate a random HMAC key (backward compatibility)
   * @deprecated Use generateSecureKey() for better security
   * @return Generated key bytes
   */
  [[deprecated("Use generateSecureKey() for enhanced security")]]
  static std::vector<uint8_t> generateKey();

  std::vector<uint8_t> sign(const std::vector<uint8_t>& data) override;
  bool verify(const std::vector<uint8_t>& data,
              const std::vector<uint8_t>& signature) override;
  int64_t algorithmId() const override;
  
  /**
   * @brief Secure destructor - keys are automatically zeroed by SecureAllocator
   */
  ~HmacSha256Algorithm() override = default;
};

class Es256Algorithm : public CryptographicAlgorithm {
 public:
  struct Impl;  // Made public for memory pool access

 private:
  std::unique_ptr<Impl> pImpl_;

 public:
  Es256Algorithm();
  Es256Algorithm(const std::vector<uint8_t>& privateKey,
                 const std::vector<uint8_t>& publicKey);
  /**
   * @brief Constructor with secure private key storage
   */
  Es256Algorithm(const SecureVector<uint8_t>& privateKey,
                 const std::vector<uint8_t>& publicKey);

  explicit Es256Algorithm(
      const std::vector<uint8_t>& publicKey);  // For verification only
  ~Es256Algorithm();

  // Move constructor and assignment
  Es256Algorithm(Es256Algorithm&& other) noexcept;
  Es256Algorithm& operator=(Es256Algorithm&& other) noexcept;

  // Delete copy constructor and assignment
  Es256Algorithm(const Es256Algorithm&) = delete;
  Es256Algorithm& operator=(const Es256Algorithm&) = delete;

  static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeyPair();
  
  /**
   * @brief Generate ES256 key pair with secure memory for private key
   * @return Pair of (private key, public key) where private key uses secure storage
   */
  static std::pair<SecureVector<uint8_t>, std::vector<uint8_t>> generateSecureKeyPair();
  
  std::vector<uint8_t> getPublicKey() const;

  std::vector<uint8_t> sign(const std::vector<uint8_t>& data) override;
  bool verify(const std::vector<uint8_t>& data,
              const std::vector<uint8_t>& signature) override;
  int64_t algorithmId() const override;
};

class Ps256Algorithm : public CryptographicAlgorithm {
 public:
  struct Impl;  // Made public for memory pool access

 private:
  std::unique_ptr<Impl> pImpl_;

 public:
  Ps256Algorithm();
  Ps256Algorithm(const std::vector<uint8_t>& privateKey,
                 const std::vector<uint8_t>& publicKey);
  /**
   * @brief Constructor with secure private key storage
   */
  Ps256Algorithm(const SecureVector<uint8_t>& privateKey,
                 const std::vector<uint8_t>& publicKey);
  explicit Ps256Algorithm(
      const std::vector<uint8_t>& publicKey);  // For verification only
  ~Ps256Algorithm();

  // Move constructor and assignment
  Ps256Algorithm(Ps256Algorithm&& other) noexcept;
  Ps256Algorithm& operator=(Ps256Algorithm&& other) noexcept;

  // Delete copy constructor and assignment
  Ps256Algorithm(const Ps256Algorithm&) = delete;
  Ps256Algorithm& operator=(const Ps256Algorithm&) = delete;

  static std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
  generateKeyPair();
  
  /**
   * @brief Generate PS256 key pair with secure memory for private key
   * @return Pair of (private key, public key) where private key uses secure storage
   */
  static std::pair<SecureVector<uint8_t>, std::vector<uint8_t>>
  generateSecureKeyPair();
  
  std::vector<uint8_t> getPublicKey() const;

  std::vector<uint8_t> sign(const std::vector<uint8_t>& data) override;
  bool verify(const std::vector<uint8_t>& data,
              const std::vector<uint8_t>& signature) override;
  int64_t algorithmId() const override;
};

/**
 * @brief Create signing input for COSE signing
 * @param header COSE header bytes
 * @param payload Payload bytes
 * @return Combined signing input
 */
std::vector<uint8_t> createSigningInput(const std::vector<uint8_t>& header,
                                        const std::vector<uint8_t>& payload);

/**
 * @brief Compute SHA-256 hash
 * @param data Input data
 * @return Hash bytes
 */
std::vector<uint8_t> hashSha256(const std::vector<uint8_t>& data);

// Memory pool support for crypto implementation objects
// Note: These functions use internal implementation details and are only used within crypto.cpp

}  // namespace catapult