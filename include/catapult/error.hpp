/**
 * @file cat_error.hpp
 * @brief Error classes and exception hierarchy for CAT implementation
 */

#pragma once

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>

namespace catapult {

/**
 * @brief Error codes for programmatic error handling
 */
enum class CatErrorCode : uint32_t {
  SUCCESS = 0,
  INVALID_TOKEN_FORMAT = 1000,
  INVALID_CBOR = 1001,
  INVALID_BASE64 = 1002,
  SIGNATURE_VERIFICATION_FAILED = 2000,
  TOKEN_EXPIRED = 2001,
  TOKEN_NOT_YET_VALID = 2002,
  INVALID_AUDIENCE = 2003,
  INVALID_ISSUER = 2004,
  MISSING_REQUIRED_CLAIM = 2005,
  INVALID_CLAIM_VALUE = 2006,
  UNSUPPORTED_ALGORITHM = 3000,
  CRYPTO_OPERATION_FAILED = 3001,
  GEOGRAPHIC_VALIDATION_FAILED = 4000,
  REPLAY_ATTACK_DETECTED = 5000,
  USAGE_LIMIT_EXCEEDED = 5001,
  OS_ERROR = 6000,
  MEMORY_ERROR = 6001,
  IO_ERROR = 6002,
  PERMISSION_ERROR = 6003,
  RESOURCE_EXHAUSTED = 6004,
  SYSTEM_CALL_FAILED = 6005
};

/**
 * @brief Convert error code to string description
 */
constexpr std::string_view errorCodeToString(CatErrorCode code) noexcept {
  switch (code) {
    case CatErrorCode::SUCCESS:
      return "Success";
    case CatErrorCode::INVALID_TOKEN_FORMAT:
      return "Invalid token format";
    case CatErrorCode::INVALID_CBOR:
      return "Invalid CBOR encoding";
    case CatErrorCode::INVALID_BASE64:
      return "Invalid base64 encoding";
    case CatErrorCode::SIGNATURE_VERIFICATION_FAILED:
      return "Signature verification failed";
    case CatErrorCode::TOKEN_EXPIRED:
      return "Token has expired";
    case CatErrorCode::TOKEN_NOT_YET_VALID:
      return "Token is not yet valid";
    case CatErrorCode::INVALID_AUDIENCE:
      return "Invalid audience";
    case CatErrorCode::INVALID_ISSUER:
      return "Invalid issuer";
    case CatErrorCode::MISSING_REQUIRED_CLAIM:
      return "Missing required claim";
    case CatErrorCode::INVALID_CLAIM_VALUE:
      return "Invalid claim value";
    case CatErrorCode::UNSUPPORTED_ALGORITHM:
      return "Unsupported algorithm";
    case CatErrorCode::CRYPTO_OPERATION_FAILED:
      return "Cryptographic operation failed";
    case CatErrorCode::GEOGRAPHIC_VALIDATION_FAILED:
      return "Geographic validation failed";
    case CatErrorCode::REPLAY_ATTACK_DETECTED:
      return "Replay attack detected";
    case CatErrorCode::USAGE_LIMIT_EXCEEDED:
      return "Usage limit exceeded";
    case CatErrorCode::OS_ERROR:
      return "Operating system error";
    case CatErrorCode::MEMORY_ERROR:
      return "Memory allocation error";
    case CatErrorCode::IO_ERROR:
      return "Input/output error";
    case CatErrorCode::PERMISSION_ERROR:
      return "Permission denied";
    case CatErrorCode::RESOURCE_EXHAUSTED:
      return "System resource exhausted";
    case CatErrorCode::SYSTEM_CALL_FAILED:
      return "System call failed";
    default:
      return "Unknown error";
  }
}

/**
 * @brief Base exception class for all CAT-related errors
 */
class CatError : public std::runtime_error {
 public:
  /**
   * @brief Construct a CAT error with message and error code
   * @param code Error code
   * @param message Error description (optional, uses default if empty)
   */
  explicit CatError(CatErrorCode code, std::string_view message = {})
      : std::runtime_error(message.empty()
                               ? std::string(errorCodeToString(code))
                               : std::string(message)),
        error_code_(code) {}

  /**
   * @brief Get the error code
   * @return The error code
   */
  [[nodiscard]] CatErrorCode errorCode() const noexcept { return error_code_; }

 private:
  CatErrorCode error_code_;
};

/**
 * @brief Exception for invalid token format
 */
class InvalidTokenFormatError : public CatError {
 public:
  InvalidTokenFormatError() : CatError(CatErrorCode::INVALID_TOKEN_FORMAT) {}
};

class InvalidCborError : public CatError {
 public:
  explicit InvalidCborError(std::string_view details)
      : CatError(
            CatErrorCode::INVALID_CBOR,
            std::string("Invalid CBOR encoding: ") + std::string(details)) {}
};

class InvalidBase64Error : public CatError {
 public:
  explicit InvalidBase64Error(std::string_view details)
      : CatError(
            CatErrorCode::INVALID_BASE64,
            std::string("Invalid base64 encoding: ") + std::string(details)) {}
};

/**
 * @brief Exception for signature verification failures
 */
class SignatureVerificationError : public CatError {
 public:
  SignatureVerificationError()
      : CatError(CatErrorCode::SIGNATURE_VERIFICATION_FAILED) {}
};

/**
 * @brief Exception for expired tokens
 */
class TokenExpiredError : public CatError {
 public:
  TokenExpiredError() : CatError(CatErrorCode::TOKEN_EXPIRED) {}
};

class TokenNotYetValidError : public CatError {
 public:
  TokenNotYetValidError() : CatError(CatErrorCode::TOKEN_NOT_YET_VALID) {}
};

class InvalidAudienceError : public CatError {
 public:
  InvalidAudienceError() : CatError(CatErrorCode::INVALID_AUDIENCE) {}
};

class InvalidIssuerError : public CatError {
 public:
  InvalidIssuerError() : CatError(CatErrorCode::INVALID_ISSUER) {}
};

class MissingRequiredClaimError : public CatError {
 public:
  explicit MissingRequiredClaimError(std::string_view claim)
      : CatError(CatErrorCode::MISSING_REQUIRED_CLAIM,
                 std::string("Missing required claim: ") + std::string(claim)) {
  }
};

class InvalidClaimValueError : public CatError {
 public:
  explicit InvalidClaimValueError(std::string_view details)
      : CatError(CatErrorCode::INVALID_CLAIM_VALUE,
                 std::string("Invalid claim value: ") + std::string(details)) {}
};

class UnsupportedAlgorithmError : public CatError {
 public:
  explicit UnsupportedAlgorithmError(std::string_view algorithm)
      : CatError(
            CatErrorCode::UNSUPPORTED_ALGORITHM,
            std::string("Unsupported algorithm: ") + std::string(algorithm)) {}
};

/**
 * @brief Exception for cryptographic operation failures
 */
class CryptoError : public CatError {
 public:
  explicit CryptoError(std::string_view details)
      : CatError(CatErrorCode::CRYPTO_OPERATION_FAILED,
                 std::string("Cryptographic operation failed: ") +
                     std::string(details)) {}
};

class GeographicValidationError : public CatError {
 public:
  explicit GeographicValidationError(std::string_view details)
      : CatError(CatErrorCode::GEOGRAPHIC_VALIDATION_FAILED,
                 std::string("Geographic validation failed: ") +
                     std::string(details)) {}
};

class ReplayAttackError : public CatError {
 public:
  ReplayAttackError() : CatError(CatErrorCode::REPLAY_ATTACK_DETECTED) {}
};

class UsageLimitExceededError : public CatError {
 public:
  UsageLimitExceededError() : CatError(CatErrorCode::USAGE_LIMIT_EXCEEDED) {}
};

/**
 * @brief Exception for OS-related errors
 */
class OsError : public CatError {
 public:
  explicit OsError(std::string_view details)
      : CatError(
            CatErrorCode::OS_ERROR,
            std::string("Operating system error: ") + std::string(details)) {}
};

/**
 * @brief Exception for memory allocation errors
 */
class MemoryError : public CatError {
 public:
  explicit MemoryError(std::string_view details)
      : CatError(
            CatErrorCode::MEMORY_ERROR,
            std::string("Memory allocation error: ") + std::string(details)) {}
};

/**
 * @brief Exception for I/O errors
 */
class IoError : public CatError {
 public:
  explicit IoError(std::string_view details)
      : CatError(CatErrorCode::IO_ERROR,
                 std::string("Input/output error: ") + std::string(details)) {}
};

/**
 * @brief Exception for permission errors
 */
class PermissionError : public CatError {
 public:
  explicit PermissionError(std::string_view details)
      : CatError(CatErrorCode::PERMISSION_ERROR,
                 std::string("Permission denied: ") + std::string(details)) {}
};

/**
 * @brief Exception for resource exhaustion
 */
class ResourceExhaustedError : public CatError {
 public:
  explicit ResourceExhaustedError(std::string_view details)
      : CatError(CatErrorCode::RESOURCE_EXHAUSTED,
                 std::string("System resource exhausted: ") +
                     std::string(details)) {}
};

/**
 * @brief Exception for system call failures
 */
class SystemCallError : public CatError {
 public:
  explicit SystemCallError(std::string_view details)
      : CatError(CatErrorCode::SYSTEM_CALL_FAILED,
                 std::string("System call failed: ") + std::string(details)) {}
};

/**
 * @brief Result type for better error handling without exceptions
 * Inspired by Rust's Result and C++23's std::expected
 */
template <typename T, typename E = CatError>
class Result {
 public:
  // Constructors
  Result(const T& value) : data_(value) {}
  Result(T&& value) : data_(std::move(value)) {}
  Result(const E& error) : data_(error) {}
  Result(E&& error) : data_(std::move(error)) {}

  // Static factory methods
  static Result success(T value) { return Result(std::move(value)); }
  static Result error(E error) { return Result(std::move(error)); }

  // Query methods
  bool isSuccess() const noexcept { return std::holds_alternative<T>(data_); }
  bool isError() const noexcept { return std::holds_alternative<E>(data_); }
  explicit operator bool() const noexcept { return isSuccess(); }

  // Value access (throws if error)
  const T& value() const& {
    if (isError()) {
      throw std::get<E>(data_);
    }
    return std::get<T>(data_);
  }

  T& value() & {
    if (isError()) {
      throw std::get<E>(data_);
    }
    return std::get<T>(data_);
  }

  T&& value() && {
    if (isError()) {
      throw std::get<E>(data_);
    }
    return std::move(std::get<T>(data_));
  }

  // Safe value access
  const T& valueOr(const T& defaultValue) const& noexcept {
    return isSuccess() ? std::get<T>(data_) : defaultValue;
  }

  T valueOr(T&& defaultValue) && noexcept {
    return isSuccess() ? std::move(std::get<T>(data_))
                       : std::move(defaultValue);
  }

  // Error access
  const E& error() const& {
    if (isSuccess()) {
      throw std::logic_error("Accessing error on successful result");
    }
    return std::get<E>(data_);
  }

  // Transform operations
  template <typename F>
  auto map(F&& func) -> Result<decltype(func(std::declval<T>())), E> {
    if (isSuccess()) {
      return Result<decltype(func(std::declval<T>())), E>::success(
          func(std::get<T>(data_)));
    }
    return Result<decltype(func(std::declval<T>())), E>::error(
        std::get<E>(data_));
  }

  template <typename F>
  auto flatMap(F&& func) -> decltype(func(std::declval<T>())) {
    if (isSuccess()) {
      return func(std::get<T>(data_));
    }
    return decltype(func(std::declval<T>()))::error(std::get<E>(data_));
  }

 private:
  std::variant<T, E> data_;
};

/**
 * @brief Convenience type aliases for common Result patterns
 */
template <typename T>
using CatResult = Result<T, CatError>;

using VoidResult = CatResult<std::monostate>;

/**
 * @brief Helper function to create successful void result
 */
inline VoidResult success() { return VoidResult::success(std::monostate{}); }

/**
 * @brief Helper function to throw appropriate OS exception based on errno
 */
inline void throwOsError(const std::string& operation, int error_code = errno) {
#ifdef _WIN32
  std::string error_msg;
  char buffer[256];
  if (strerror_s(buffer, sizeof(buffer), error_code) == 0) {
    error_msg = buffer;
  } else {
    error_msg = "Unknown error";
  }
#else
  std::string error_msg = std::strerror(error_code);
#endif

  switch (error_code) {
    case EACCES:
#ifndef _WIN32
    case EPERM:
#endif
      throw PermissionError(operation + ": " + error_msg);
    case ENOMEM:
      throw MemoryError(operation + ": " + error_msg);
    case EMFILE:
#ifndef _WIN32
    case ENFILE:
#endif
    case ENOSPC:
#ifdef EDQUOT
    case EDQUOT:
#endif
      throw ResourceExhaustedError(operation + ": " + error_msg);
    case EIO:
    case ENOENT:
#ifndef _WIN32
    case EISDIR:
    case ENOTDIR:
#endif
      throw IoError(operation + ": " + error_msg);
    default:
      throw SystemCallError(operation + ": " + error_msg);
  }
}

}  // namespace catapult