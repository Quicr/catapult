/**
 * @file cat_crypto.hpp
 * @brief Cryptographic algorithms and utilities for CAT tokens
 */

#pragma once

#include <concepts>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "memory_pool.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#include "base64.hpp"
#include "error.hpp"
#include "secure_vector.hpp"

// Forward declarations for OpenSSL types
typedef struct evp_pkey_st EVP_PKEY;
typedef struct bio_st BIO;

namespace catapult {

/// COSE Algorithm Identifiers
constexpr int64_t ALG_HMAC256_256 = 5;  ///< HMAC 256/256
constexpr int64_t ALG_ES256 = -7;       ///< ECDSA w/ SHA-256
constexpr int64_t ALG_PS256 = -37;      ///< RSASSA-PSS w/ SHA-256
constexpr int64_t ALG_A128GCM =
    1;  ///< AES-GCM mode w/ 128-bit key, 128-bit tag
constexpr int64_t ALG_A192GCM =
    2;  ///< AES-GCM mode w/ 192-bit key, 128-bit tag
constexpr int64_t ALG_A256GCM =
    3;  ///< AES-GCM mode w/ 256-bit key, 128-bit tag
constexpr int64_t ALG_ChaCha20_Poly1305 =
    24;  ///< ChaCha20-Poly1305 w/ 256-bit key, 128-bit tag

namespace crypto_constants {
constexpr size_t HMAC_KEY_SIZE = 32;   ///< HMAC-SHA256 recommended key size
constexpr size_t ES256_KEY_SIZE = 32;  ///< P-256 private key size
constexpr size_t PS256_MIN_KEY_SIZE = 256;  ///< RSA minimum key size in bytes
constexpr size_t AES128_KEY_SIZE = 16;      ///< AES-128 key size in bytes
constexpr size_t AES192_KEY_SIZE = 24;      ///< AES-192 key size in bytes
constexpr size_t AES256_KEY_SIZE = 32;      ///< AES-256 key size in bytes
constexpr size_t ChaCha20_KEY_SIZE = 32;    ///< ChaCha20 key size in bytes
constexpr size_t GCM_IV_SIZE = 12;          ///< GCM IV size in bytes (96 bits)
constexpr size_t GCM_TAG_SIZE = 16;  ///< GCM authentication tag size in bytes
constexpr size_t ChaCha20_NONCE_SIZE =
    12;  ///< ChaCha20-Poly1305 nonce size in bytes
constexpr size_t ChaCha20_TAG_SIZE =
    16;  ///< ChaCha20-Poly1305 tag size in bytes

constexpr bool is_valid_hmac_key_size(size_t size) noexcept {
  return size >= 16 && size <= 64;  // NIST recommendations
}

consteval bool is_valid_rsa_key_size(size_t size) noexcept {
  return size >= 256 && size <= 512;  // 2048-4096 bits
}

constexpr bool is_valid_aes_key_size(size_t size) noexcept {
  return size == AES128_KEY_SIZE || size == AES192_KEY_SIZE ||
         size == AES256_KEY_SIZE;
}

}  // namespace crypto_constants

static_assert(
    crypto_constants::is_valid_hmac_key_size(crypto_constants::HMAC_KEY_SIZE),
    "HMAC key size is invalid");
static_assert(crypto_constants::is_valid_rsa_key_size(
                  crypto_constants::PS256_MIN_KEY_SIZE),
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
template <typename T>
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
  template <CryptoData T>
  std::vector<uint8_t> sign(const T& data) const {
    return signImpl({std::data(data), std::size(data)});
  }

  /**
   * @brief Verify a signature
   * @param data Original data
   * @param signature Signature to verify
   * @return True if signature is valid
   */
  template <CryptoData T1, CryptoData T2>
  bool verify(const T1& data, const T2& signature) const {
    return verifyImpl({std::data(data), std::size(data)},
                      {std::data(signature), std::size(signature)});
  }

  /**
   * @brief Encrypt data with the algorithm
   * @param data Data to encrypt
   * @param iv Initialization vector (for AEAD algorithms)
   * @return Encrypted data with authentication tag
   * @throws CryptoError if algorithm doesn't support encryption
   */
  template <CryptoData T1, CryptoData T2>
  std::vector<uint8_t> encrypt(const T1& data, const T2& iv) const {
    return encryptImpl({std::data(data), std::size(data)},
                       {std::data(iv), std::size(iv)});
  }

  /**
   * @brief Decrypt data with the algorithm
   * @param encryptedData Encrypted data with authentication tag
   * @param iv Initialization vector (for AEAD algorithms)
   * @return Decrypted data
   * @throws CryptoError if decryption fails or algorithm doesn't support
   * decryption
   */
  template <CryptoData T1, CryptoData T2>
  std::vector<uint8_t> decrypt(const T1& encryptedData, const T2& iv) const {
    return decryptImpl({std::data(encryptedData), std::size(encryptedData)},
                       {std::data(iv), std::size(iv)});
  }

  /**
   * @brief Get the COSE algorithm identifier
   * @return Algorithm ID
   */
  virtual int64_t algorithmId() const = 0;

  /**
   * @brief Check if this algorithm supports encryption
   * @return True if algorithm supports encryption
   */
  virtual bool supportsEncryption() const { return false; }

 protected:
  // Pure virtual implementation methods that derived classes must implement
  virtual std::vector<uint8_t> signImpl(
      std::span<const uint8_t> data) const = 0;
  virtual bool verifyImpl(std::span<const uint8_t> data,
                          std::span<const uint8_t> signature) const = 0;
  virtual std::vector<uint8_t> encryptImpl(std::span<const uint8_t> data,
                                           std::span<const uint8_t> iv) const;
  virtual std::vector<uint8_t> decryptImpl(
      std::span<const uint8_t> encryptedData,
      std::span<const uint8_t> iv) const;
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
  explicit HmacSha256Algorithm(const std::vector<uint8_t>& key)
      : key_(key.begin(), key.end()) {
    if (!crypto_constants::is_valid_hmac_key_size(key.size())) {
      throw CryptoError("Invalid HMAC key size");
    }
  }

  /**
   * @brief Construct with secure key vector
   */
  explicit HmacSha256Algorithm(SecureVector<uint8_t> key)
      : key_(std::move(key)) {
    if (!crypto_constants::is_valid_hmac_key_size(key_.size())) {
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

  std::vector<uint8_t> signImpl(std::span<const uint8_t> data) const override;
  bool verifyImpl(std::span<const uint8_t> data,
                  std::span<const uint8_t> signature) const override;
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

  void loadPrivateKey(const uint8_t* keyData, size_t keySize);
  void loadPublicKey(const uint8_t* keyData, size_t keySize);
  void initializeImpl();

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

  static std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
  generateKeyPair();

  /**
   * @brief Generate ES256 key pair with secure memory for private key
   * @return Pair of (private key, public key) where private key uses secure
   * storage
   */
  static std::pair<SecureVector<uint8_t>, std::vector<uint8_t>>
  generateSecureKeyPair();

  std::vector<uint8_t> getPublicKey() const;

  std::vector<uint8_t> signImpl(std::span<const uint8_t> data) const override;
  bool verifyImpl(std::span<const uint8_t> data,
                  std::span<const uint8_t> signature) const override;
  int64_t algorithmId() const override;
};

class Ps256Algorithm : public CryptographicAlgorithm {
 public:
  struct Impl;  // Made public for memory pool access

 private:
  std::unique_ptr<Impl> pImpl_;

  void initializeImpl();
  void loadPrivateKey(const uint8_t* keyData, size_t keySize);
  void loadPublicKey(const uint8_t* keyData, size_t keySize);

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
   * @return Pair of (private key, public key) where private key uses secure
   * storage
   */
  static std::pair<SecureVector<uint8_t>, std::vector<uint8_t>>
  generateSecureKeyPair();

  std::vector<uint8_t> getPublicKey() const;

  std::vector<uint8_t> signImpl(std::span<const uint8_t> data) const override;
  bool verifyImpl(std::span<const uint8_t> data,
                  std::span<const uint8_t> signature) const override;
  int64_t algorithmId() const override;
};

/**
 * @brief Create COSE Sig_structure for COSE_Sign (multi-signature) (RFC8152
 * Section 4.4)
 * @param bodyProtectedHeader Protected header from the COSE_Sign body
 * @param signatureProtectedHeader Signature-specific protected header
 * @param externalAAD External authenticated data as bytes (empty if not used)
 * @param payload Payload bytes
 * @return COSE Sig_structure as CBOR-encoded bytes for COSE_Sign
 */
std::vector<uint8_t> createCoseSignInput(
    const std::vector<uint8_t>& bodyProtectedHeader,
    const std::vector<uint8_t>& signatureProtectedHeader,
    const std::vector<uint8_t>& externalAAD,
    const std::vector<uint8_t>& payload);

/**
 * @brief Create COSE Sig_structure for COSE_Sign1 (single signature)
 * @param protectedHeader Protected header attributes as CBOR bytes
 * @param payload Payload bytes
 * @param externalAAD External authenticated data (defaults to empty)
 * @return COSE Sig_structure as CBOR-encoded bytes
 */
std::vector<uint8_t> createCoseSign1Input(
    const std::vector<uint8_t>& protectedHeader,
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& externalAAD = {});

/**
 * @brief Create JWT-style signing input (legacy, for backward compatibility)
 * @param header Header bytes (will be base64url encoded)
 * @param payload Payload bytes (will be base64url encoded)
 * @return JWT-style signing input (header.payload)
 * @deprecated Use COSE-compliant createCoseSign1Input for new code
 */
std::vector<uint8_t> createJwtSigningInput(const std::vector<uint8_t>& header,
                                           const std::vector<uint8_t>& payload);

/**
 * @brief Compute SHA-256 hash
 * @param data Input data
 * @return Hash bytes
 */
std::vector<uint8_t> hashSha256(const std::vector<uint8_t>& data);

/**
 * @brief AES-GCM algorithm implementation for AEAD encryption
 */
class AesGcmAlgorithm : public CryptographicAlgorithm {
 private:
  SecureVector<uint8_t> key_;  ///< AES key with secure allocator
  int64_t algorithmId_;        ///< COSE algorithm identifier

 public:
  /**
   * @brief Construct with existing key
   * @param key AES key bytes (16, 24, or 32 bytes)
   * @param algorithmId COSE algorithm identifier (ALG_A128GCM, ALG_A192GCM,
   * ALG_A256GCM)
   */
  explicit AesGcmAlgorithm(const std::vector<uint8_t>& key,
                           int64_t algorithmId);

  /**
   * @brief Construct with secure key vector
   */
  explicit AesGcmAlgorithm(SecureVector<uint8_t> key, int64_t algorithmId);

  /**
   * @brief Generate a random AES key with secure storage
   * @param keySize Key size in bytes (16, 24, or 32)
   * @return Generated key bytes in secure vector
   */
  static SecureVector<uint8_t> generateSecureKey(size_t keySize);

  /**
   * @brief Generate a random IV for AES-GCM
   * @return 12-byte IV
   */
  static std::vector<uint8_t> generateIV();

  // Signing/verification not supported for encryption-only algorithm
  std::vector<uint8_t> signImpl(std::span<const uint8_t> data) const override;
  bool verifyImpl(std::span<const uint8_t> data,
                  std::span<const uint8_t> signature) const override;

  // Encryption/decryption support
  std::vector<uint8_t> encryptImpl(std::span<const uint8_t> data,
                                   std::span<const uint8_t> iv) const override;
  std::vector<uint8_t> decryptImpl(std::span<const uint8_t> encryptedData,
                                   std::span<const uint8_t> iv) const override;

  int64_t algorithmId() const override;
  bool supportsEncryption() const override { return true; }
};

/**
 * @brief ChaCha20-Poly1305 algorithm implementation for AEAD encryption
 */
class ChaCha20Poly1305Algorithm : public CryptographicAlgorithm {
 private:
  SecureVector<uint8_t> key_;  ///< ChaCha20 key with secure allocator

 public:
  /**
   * @brief Construct with existing key
   * @param key ChaCha20 key bytes (32 bytes)
   */
  explicit ChaCha20Poly1305Algorithm(const std::vector<uint8_t>& key);

  /**
   * @brief Construct with secure key vector
   */
  explicit ChaCha20Poly1305Algorithm(SecureVector<uint8_t> key);

  /**
   * @brief Generate a random ChaCha20 key with secure storage
   * @return Generated key bytes in secure vector
   */
  static SecureVector<uint8_t> generateSecureKey();

  /**
   * @brief Generate a random nonce for ChaCha20-Poly1305
   * @return 12-byte nonce
   */
  static std::vector<uint8_t> generateNonce();

  // Signing/verification not supported for encryption-only algorithm
  std::vector<uint8_t> signImpl(std::span<const uint8_t> data) const override;
  bool verifyImpl(std::span<const uint8_t> data,
                  std::span<const uint8_t> signature) const override;

  // Encryption/decryption support
  std::vector<uint8_t> encryptImpl(std::span<const uint8_t> data,
                                   std::span<const uint8_t> iv) const override;
  std::vector<uint8_t> decryptImpl(std::span<const uint8_t> encryptedData,
                                   std::span<const uint8_t> iv) const override;

  int64_t algorithmId() const override;
  bool supportsEncryption() const override { return true; }
};

}  // namespace catapult