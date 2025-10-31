#include "catapult/cwt.hpp"

#include <cbor.h>

#include <algorithm>

#include "catapult/crypto.hpp"
#include "catapult/logging.hpp"
#include "catapult/base64.hpp"
#include "catapult/dpop.hpp"

namespace catapult {

// RAII deleter implementations
void CborItemDeleter::operator()(cbor_item_t* item) const noexcept {
  if (item) {
      cbor_decref(&item);
  }
}

void CborBufferDeleter::operator()(unsigned char* buffer) const noexcept {
  if (buffer) {
      free(buffer);
  }
}

/**
 * @brief RAII CBOR map builder
 */
class CborMapBuilder {
public:
  explicit CborMapBuilder(size_t initial_capacity = 20) 
    : root_(cbor_new_definite_map(initial_capacity)) {
    if (!root_) {
      CAT_LOG_ERROR("Failed to create CBOR map with capacity {}", initial_capacity);
      if (errno == ENOMEM) {
        throwOsError("cbor_new_definite_map");
      } else {
        throw InvalidCborError("Failed to create CBOR map");
      }
    }
  }
  
  ~CborMapBuilder() = default;

  CborMapBuilder(const CborMapBuilder&) = delete;
  CborMapBuilder& operator=(const CborMapBuilder&) = delete;
  CborMapBuilder(CborMapBuilder&&) = default;
  CborMapBuilder& operator=(CborMapBuilder&&) = default;
  
  /**
   * @brief Add a claim
   */
  /**
   * @brief Add claim using ClaimIdentifier type for compile-time safety
   */
  template<typename ClaimType, typename T>
  void addClaim(T&& value) requires CborEncodable<T> {
    static_assert(ClaimType::value > 0, "Claim ID must be positive");
    static_assert(ClaimType::value <= 65535, "Claim ID must be within valid range");
    
    if constexpr (requires { value.has_value(); }) {
      // Handle optional types (std::optional, etc.)
      if (!value.has_value()) {
        CAT_LOG_TRACE("Skipping claim {} - no value provided", ClaimType::value);
        return;
      }
      addClaimImpl(ClaimType::value, std::forward<T>(value).value());
    } else {
      // Handle direct values
      addClaimImpl(ClaimType::value, std::forward<T>(value));
    }
  }
  
  CborItemPtr release() {
    return std::move(root_);
  }
  
private:
  CborItemPtr root_;
  
  void addClaimImpl(int64_t claim_id, const std::string& value) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    auto val = CborItemPtr(cbor_build_string(value.c_str()));
    addPair(std::move(key), std::move(val));
  }
  
  void addClaimImpl(int64_t claim_id, const std::vector<std::string>& values) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    auto array = CborItemPtr(cbor_new_definite_array(values.size()));
    
    for (const auto& val : values) {
      auto str_item = CborItemPtr(cbor_build_string(val.c_str()));
      if (!cbor_array_push(array.get(), str_item.release())) {
        throw InvalidCborError("Failed to add string to array");
      }
    }
    
    addPair(std::move(key), std::move(array));
  }
  
  void addClaimImpl(int64_t claim_id, int64_t value) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    auto val = CborItemPtr(cbor_build_uint64(value));
    addPair(std::move(key), std::move(val));
  }
  
  void addClaimImpl(int64_t claim_id, uint32_t value) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    auto val = CborItemPtr(cbor_build_uint32(value));
    addPair(std::move(key), std::move(val));
  }
  
  void addClaimImpl(int64_t claim_id, bool value) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    auto val = CborItemPtr(cbor_build_bool(value));
    addPair(std::move(key), std::move(val));
  }
  
  void addClaimImpl(int64_t claim_id, const GeoCoordinate& coord) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    auto coord_map = CborItemPtr(cbor_new_definite_map(coord.accuracy ? 3 : 2));
    
    // Add latitude
    auto lat_key = CborItemPtr(cbor_build_string("lat"));
    auto lat_val = CborItemPtr(cbor_build_float8(coord.lat));
    addPairToMap(coord_map.get(), std::move(lat_key), std::move(lat_val));
    
    // Add longitude  
    auto lon_key = CborItemPtr(cbor_build_string("lon"));
    auto lon_val = CborItemPtr(cbor_build_float8(coord.lon));
    addPairToMap(coord_map.get(), std::move(lon_key), std::move(lon_val));
    
    // Add accuracy if present
    if (coord.accuracy) {
      auto acc_key = CborItemPtr(cbor_build_string("accuracy"));
      auto acc_val = CborItemPtr(cbor_build_float8(*coord.accuracy));
      addPairToMap(coord_map.get(), std::move(acc_key), std::move(acc_val));
    }
    
    addPair(std::move(key), std::move(coord_map));
  }
  
  void addPair(CborItemPtr key, CborItemPtr value) {
    addPairToMap(root_.get(), std::move(key), std::move(value));
  }
  
  void addPairToMap(cbor_item_t* map, CborItemPtr key, CborItemPtr value) {
    struct cbor_pair pair = {key.release(), value.release()};
    if (!cbor_map_add(map, pair)) {
      cbor_decref(&pair.key);
      cbor_decref(&pair.value);
      throw InvalidCborError("Failed to add pair to CBOR map");
    }
  }
};

/**
 * @brief Compile-time claim processing
 */
template<typename TokenType>
class ClaimProcessor {
public:
  static void processAllClaims(CborMapBuilder& builder, const TokenType& token) {
    using namespace claim_validation;

    // Process core claims using ClaimIdentifier types
    builder.addClaim<IssuerClaim>(token.core.iss);
    builder.addClaim<AudienceClaim>(token.core.aud);
    builder.addClaim<ExpirationClaim>(token.core.exp);
    builder.addClaim<NotBeforeClaim>(token.core.nbf);
    builder.addClaim<CwtIdClaim>(token.core.cti);
    
    // Process CAT claims using ClaimIdentifier types
    builder.addClaim<CatReplayClaim>(token.cat.catreplay);
    builder.addClaim<CatProofClaim>(token.cat.catpor);
    builder.addClaim<CatVersionClaim>(token.cat.catv);
    builder.addClaim<CatUsageClaim>(token.cat.catu);
    builder.addClaim<CatGeoCoordClaim>(token.cat.catgeocoord);
    builder.addClaim<GeohashClaim>(token.cat.geohash);
    
    // Compile-time validation that all used claims are in the registry
    static_assert(StandardClaimRegistry::contains<IssuerClaim::value>(), 
                  "IssuerClaim not in registry");
    static_assert(StandardClaimRegistry::contains<AudienceClaim::value>(), 
                  "AudienceClaim not in registry");
    static_assert(StandardClaimRegistry::contains<ExpirationClaim::value>(), 
                  "ExpirationClaim not in registry");
    static_assert(StandardClaimRegistry::contains<NotBeforeClaim::value>(), 
                  "NotBeforeClaim not in registry");
    static_assert(StandardClaimRegistry::contains<CwtIdClaim::value>(), 
                  "CwtIdClaim not in registry");
    static_assert(StandardClaimRegistry::contains<CatReplayClaim::value>(), 
                  "CatReplayClaim not in registry");
    static_assert(StandardClaimRegistry::contains<CatProofClaim::value>(), 
                  "CatProofClaim not in registry");
    static_assert(StandardClaimRegistry::contains<CatVersionClaim::value>(), 
                  "CatVersionClaim not in registry");
    static_assert(StandardClaimRegistry::contains<CatUsageClaim::value>(), 
                  "CatUsageClaim not in registry");
    static_assert(StandardClaimRegistry::contains<CatGeoCoordClaim::value>(), 
                  "CatGeoCoordClaim not in registry");
    static_assert(StandardClaimRegistry::contains<GeohashClaim::value>(), 
                  "GeohashClaim not in registry");
  }
};

Cwt::Cwt(int64_t alg, const CatToken& token) : header(alg), payload(token) {}

Cwt& Cwt::withKeyId(const std::string& kid) {
  header.kid = kid;
  return *this;
}

Cwt& Cwt::addSignature(const CryptographicAlgorithm& algorithm, 
                       const std::vector<uint8_t>& signatureHeader) {
  try {
    // Create payload and body header for signing
    auto payloadBytes = encodePayload();
    auto bodyHeader = createCoseHeader();
    
    // Create signature-specific header or use empty one
    std::vector<uint8_t> sigHeader = signatureHeader;
    if (sigHeader.empty()) {
      // Create minimal signature header with just algorithm
      auto headerMap = CborItemPtr(cbor_new_definite_map(1));
      auto alg_key = CborItemPtr(cbor_build_uint8(1));
      CborItemPtr alg_val;
      if (algorithm.algorithmId() > 0) {
        alg_val = CborItemPtr(cbor_build_uint64(algorithm.algorithmId()));
      } else {
        alg_val = CborItemPtr(cbor_build_negint64(-algorithm.algorithmId() - 1));
      }
      
      struct cbor_pair alg_pair = {alg_key.release(), alg_val.release()};
      if (!cbor_map_add(headerMap.get(), alg_pair)) {
        cbor_decref(&alg_pair.key);
        cbor_decref(&alg_pair.value);
        throw InvalidCborError("Failed to add algorithm to signature header");
      }
      
      unsigned char* raw_buffer;
      size_t buffer_size;
      size_t length = cbor_serialize_alloc(headerMap.get(), &raw_buffer, &buffer_size);
      if (length == 0) {
        throw InvalidCborError("Failed to serialize signature header");
      }
      
      auto buffer = CborBufferPtr(raw_buffer);
      sigHeader = std::vector<uint8_t>(buffer.get(), buffer.get() + length);
    }
    
    // Create COSE Sig_structure for COSE_Sign (multi-signature)
    // Use the specialized function for proper COSE_Sign structure
    auto signingInput = createCoseSignInput(bodyHeader, sigHeader, {}, payloadBytes);
    
    // Sign the data
    auto signatureBytes = algorithm.sign(signingInput);
    
    // Add to signatures array with algorithm ID
    signatures.emplace_back(sigHeader, signatureBytes, algorithm.algorithmId());
    
    return *this;
    
  } catch (const std::exception& e) {
    CAT_LOG_ERROR("Failed to add signature: {}", e.what());
    throw CryptoError(std::string("Signature addition failed: ") + e.what());
  }
}

std::vector<uint8_t> Cwt::encodePayload() const {
  try {
    CborMapBuilder builder(20);  // Reserve space for up to 20 claims
    
    // Process all claims using compile-time dispatch
    ClaimProcessor<CatToken>::processAllClaims(builder, payload);
    
    // Get the CBOR root and serialize
    auto root = builder.release();
    
    unsigned char* raw_buffer;
    size_t buffer_size;
    size_t length = cbor_serialize_alloc(root.get(), &raw_buffer, &buffer_size);
    
    if (length == 0) {
      CAT_LOG_ERROR("CBOR serialization failed - length is 0");
      if (raw_buffer == nullptr && errno == ENOMEM) {
        throwOsError("cbor_serialize_alloc");
      } else {
        throw InvalidCborError("Failed to serialize CBOR data");
      }
    }
    
    CAT_LOG_DEBUG("CBOR serialization successful, {} bytes generated", length);
    
    auto buffer = CborBufferPtr(raw_buffer);
    auto result = std::vector<uint8_t>(buffer.get(), buffer.get() + length);
    
    return result;
    
  } catch (const std::exception& e) {
    throw InvalidCborError(std::string("CBOR encoding failed: ") + e.what());
  }
}

CatToken Cwt::decodePayload(const std::vector<uint8_t>& cborData) {
  // Early validation
  if (cborData.empty()) {
    throw InvalidCborError("Empty CBOR data");
  }

  struct cbor_load_result result;
  cbor_item_t* raw_item = cbor_load(cborData.data(), cborData.size(), &result);

  if (result.error.code != CBOR_ERR_NONE) {
    if (result.error.code == CBOR_ERR_MEMERROR) {
      throwOsError("cbor_load memory allocation");
    } else {
      throw InvalidCborError("Failed to parse CBOR data");
    }
  }

  // Use RAII wrapper for automatic cleanup
  CborItemPtr item(raw_item);

  if (!cbor_isa_map(item.get())) {
    throw InvalidTokenFormatError();
  }

  // Helper lambda for extracting strings without allocating temporary string
  auto extract_string = [](cbor_item_t* str_item) -> std::string {
    if (!str_item) return {};
    const char* data = reinterpret_cast<const char*>(cbor_string_handle(str_item));
    size_t length = cbor_string_length(str_item);
    return {data, length};
  };

  auto extract_bytestring = [](cbor_item_t* str_item) -> std::string {
    if (!str_item) return {};
    const char* data = reinterpret_cast<const char*>(cbor_bytestring_handle(str_item));
    size_t length = cbor_bytestring_length(str_item);
    return {data, length};
  };

  // Parse into CatToken
  CatToken token;
  struct cbor_pair* pairs = cbor_map_handle(item.get());
  size_t map_size = cbor_map_size(item.get());

  // Bounds check
  if (!pairs || map_size == 0) {
    return token;
  }

  for (size_t i = 0; i < map_size; i++) {
    cbor_item_t* key_item = pairs[i].key;
    cbor_item_t* value_item = pairs[i].value;

    if (!cbor_isa_uint(key_item)) {
      continue;
    }

    uint64_t claim_id = cbor_get_uint64(key_item);

    switch (claim_id) {
      case CLAIM_ISS:
        if (cbor_isa_string(value_item)) {
          token.core.iss = extract_string(value_item);
        }
        break;

      case CLAIM_AUD:
        if (cbor_isa_array(value_item)) {
          size_t array_size = cbor_array_size(value_item);
          cbor_item_t** array_handle = cbor_array_handle(value_item);
          
          if (array_handle && array_size > 0) {
            std::vector<std::string> audiences;
            audiences.reserve(array_size); // Pre-allocate capacity

            for (size_t j = 0; j < array_size; j++) {
              if (cbor_isa_string(array_handle[j])) {
                audiences.emplace_back(extract_string(array_handle[j]));
              }
            }
            token.core.aud = std::move(audiences);
          }
        }
        break;

      case CLAIM_EXP:
        if (cbor_isa_uint(value_item)) {
          token.core.exp = cbor_get_uint64(value_item);
        }
        break;

      case CLAIM_NBF:
        if (cbor_isa_uint(value_item)) {
          token.core.nbf = cbor_get_uint64(value_item);
        }
        break;

      case CLAIM_CTI:
        if (cbor_isa_bytestring(value_item)) {
          token.core.cti = extract_bytestring(value_item);
        } else if (cbor_isa_string(value_item)) {
          token.core.cti = extract_string(value_item);
        }
        break;

      case CLAIM_CATREPLAY:
        if (cbor_isa_string(value_item)) {
          token.cat.catreplay = extract_string(value_item);
        }
        break;

      case CLAIM_CATPOR:
        if (cbor_is_bool(value_item)) {
          token.cat.catpor = cbor_get_bool(value_item);
        }
        break;

      case CLAIM_CATV:
        if (cbor_isa_string(value_item)) {
          token.cat.catv = extract_string(value_item);
        }
        break;

      case CLAIM_CATU:
        if (cbor_isa_uint(value_item)) {
          token.cat.catu = static_cast<uint32_t>(cbor_get_uint32(value_item));
        }
        break;

      case CLAIM_CATGEOCOORD:
        if (cbor_isa_map(value_item)) {
          GeoCoordinate coord;
          struct cbor_pair* coord_pairs = cbor_map_handle(value_item);
          size_t coord_map_size = cbor_map_size(value_item);
          
          if (coord_pairs && coord_map_size > 0) {
            for (size_t k = 0; k < coord_map_size; k++) {
              cbor_item_t* coord_key = coord_pairs[k].key;
              cbor_item_t* coord_value = coord_pairs[k].value;
              
              if (!cbor_isa_string(coord_key) || !cbor_isa_float_ctrl(coord_value)) {
                continue;
              }
              
              // Use string_view to avoid allocation for comparison
              const char* key_data = reinterpret_cast<const char*>(cbor_string_handle(coord_key));
              size_t key_len = cbor_string_length(coord_key);
              std::string_view key_view(key_data, key_len);
              
              double value = cbor_float_get_float8(coord_value);
              
              if (key_view == "lat") {
                coord.lat = value;
              } else if (key_view == "lon") {
                coord.lon = value;
              } else if (key_view == "accuracy") {
                coord.accuracy = value;
              }
            }
            token.cat.catgeocoord = coord;
          }
        }
        break;

      case CLAIM_GEOHASH:
        if (cbor_isa_string(value_item)) {
          token.cat.geohash = extract_string(value_item);
        }
        break;
    }
  }

  return token;
}

std::vector<uint8_t> Cwt::createCoseHeader() const {
  try {
    // Create COSE header map manually
    size_t header_fields = 1; // alg is required
    if (header.kid.has_value()) header_fields++;
    if (header.typ.has_value()) header_fields++;
    
    auto headerMap = CborItemPtr(cbor_new_definite_map(header_fields));
    
    // Add algorithm (label 1, required)
    auto alg_key = CborItemPtr(cbor_build_uint8(1));
    CborItemPtr alg_val;
    if (header.alg > 0) {
      alg_val = CborItemPtr(cbor_build_uint64(header.alg));
    } else {
      alg_val = CborItemPtr(cbor_build_negint64(-header.alg - 1));
    }
    
    struct cbor_pair alg_pair = {alg_key.release(), alg_val.release()};
    if (!cbor_map_add(headerMap.get(), alg_pair)) {
      cbor_decref(&alg_pair.key);
      cbor_decref(&alg_pair.value);
      throw InvalidCborError("Failed to add algorithm to COSE header");
    }
    
    // Add key ID if present (label 4)
    if (header.kid.has_value()) {
      auto kid_key = CborItemPtr(cbor_build_uint8(4));
      auto kid_val = CborItemPtr(cbor_build_string(header.kid->c_str()));
      
      struct cbor_pair kid_pair = {kid_key.release(), kid_val.release()};
      if (!cbor_map_add(headerMap.get(), kid_pair)) {
        cbor_decref(&kid_pair.key);
        cbor_decref(&kid_pair.value);
        throw InvalidCborError("Failed to add key ID to COSE header");
      }
    }
    
    // Add content type if present (label 16)
    if (header.typ.has_value()) {
      auto typ_key = CborItemPtr(cbor_build_uint8(16));
      auto typ_val = CborItemPtr(cbor_build_string(header.typ->c_str()));
      
      struct cbor_pair typ_pair = {typ_key.release(), typ_val.release()};
      if (!cbor_map_add(headerMap.get(), typ_pair)) {
        cbor_decref(&typ_pair.key);
        cbor_decref(&typ_pair.value);
        throw InvalidCborError("Failed to add content type to COSE header");
      }
    }
    
    // Serialize to buffer
    unsigned char* raw_buffer;
    size_t buffer_size;
    size_t length = cbor_serialize_alloc(headerMap.get(), &raw_buffer, &buffer_size);
    
    if (length == 0) {
      CAT_LOG_ERROR("COSE header serialization failed");
      throw InvalidCborError("Failed to serialize COSE header");
    }
    
    auto buffer = CborBufferPtr(raw_buffer);
    return std::vector<uint8_t>(buffer.get(), buffer.get() + length);
    
  } catch (const std::exception& e) {
    throw InvalidCborError(std::string("COSE header creation failed: ") + e.what());
  }
}

std::string Cwt::createCwt(CwtMode mode, const CryptographicAlgorithm& algorithm) const {
  try {
    CAT_LOG_DEBUG("Creating CWT with mode {}", static_cast<int>(mode));
    
    // Step 1: Create COSE header
    auto coseHeader = createCoseHeader();
    
    // Step 2: Encode payload
    auto payload = encodePayload();
    
    // Step 3 & 4: Handle different COSE modes with appropriate signing input
    std::vector<uint8_t> signature;
    std::vector<uint8_t> encryptedPayload;
    std::vector<uint8_t> iv;
    
    switch (mode) {
      case CwtMode::Signed:
      case CwtMode::MACed: {
        // Use COSE_Sign1 Sig_structure for single signatures
        auto signingInput = createCoseSign1Input(coseHeader, payload);
        signature = algorithm.sign(signingInput);
        break;
      }
      case CwtMode::MultiSigned:
        // For COSE_Sign, signatures should already be added via addSignature()
        if (signatures.empty()) {
          throw CryptoError("No signatures available for COSE_Sign mode. Use addSignature() first.");
        }
        break;
      case CwtMode::Encrypted:
        if (!algorithm.supportsEncryption()) {
          throw CryptoError("Algorithm does not support encryption");
        }
        
        // Generate IV/nonce for AEAD encryption
        if (algorithm.algorithmId() == ALG_A128GCM || 
            algorithm.algorithmId() == ALG_A192GCM || 
            algorithm.algorithmId() == ALG_A256GCM) {
          iv = AesGcmAlgorithm::generateIV();
        } else if (algorithm.algorithmId() == ALG_ChaCha20_Poly1305) {
          iv = ChaCha20Poly1305Algorithm::generateNonce();
        } else {
          throw CryptoError("Unsupported encryption algorithm");
        }
        
        // Encrypt the payload directly (COSE_Encrypt0 doesn't use signing input)
        encryptedPayload = algorithm.encrypt(payload, iv);
        break;
    }
    
    // Step 5: Create COSE structure based on mode
    CborItemPtr coseStructure;
    
    if (mode == CwtMode::MultiSigned) {
      // For COSE_Sign: [protected_header, unprotected_header, payload, signatures_array]
      coseStructure = CborItemPtr(cbor_new_definite_array(4));
      
      // Add protected header (encoded as bstr)
      auto protectedHeader = CborItemPtr(cbor_build_bytestring(coseHeader.data(), coseHeader.size()));
      if (!cbor_array_push(coseStructure.get(), protectedHeader.release())) {
        throw InvalidCborError("Failed to add protected header to COSE_Sign structure");
      }
      
      // Add empty unprotected header (map)
      auto unprotectedHeader = CborItemPtr(cbor_new_definite_map(0));
      if (!cbor_array_push(coseStructure.get(), unprotectedHeader.release())) {
        throw InvalidCborError("Failed to add unprotected header to COSE_Sign structure");
      }
      
      // Add payload (encoded as bstr)
      auto payloadBstr = CborItemPtr(cbor_build_bytestring(payload.data(), payload.size()));
      if (!cbor_array_push(coseStructure.get(), payloadBstr.release())) {
        throw InvalidCborError("Failed to add payload to COSE_Sign structure");
      }
      
      // Add signatures array
      auto signaturesArray = CborItemPtr(cbor_new_definite_array(signatures.size()));
      for (const auto& sig : signatures) {
        // Each signature is: [protected_header, unprotected_header, signature]
        auto sigStructure = CborItemPtr(cbor_new_definite_array(3));
        
        // Add signature protected header
        auto sigProtectedHeader = CborItemPtr(cbor_build_bytestring(sig.protectedHeader.data(), 
                                                                   sig.protectedHeader.size()));
        if (!cbor_array_push(sigStructure.get(), sigProtectedHeader.release())) {
          throw InvalidCborError("Failed to add signature protected header");
        }
        
        // Add empty signature unprotected header
        auto sigUnprotectedHeader = CborItemPtr(cbor_new_definite_map(0));
        if (!cbor_array_push(sigStructure.get(), sigUnprotectedHeader.release())) {
          throw InvalidCborError("Failed to add signature unprotected header");
        }
        
        // Add signature bytes
        auto sigBytes = CborItemPtr(cbor_build_bytestring(sig.signature.data(), sig.signature.size()));
        if (!cbor_array_push(sigStructure.get(), sigBytes.release())) {
          throw InvalidCborError("Failed to add signature bytes");
        }
        
        // Add this signature to the signatures array
        if (!cbor_array_push(signaturesArray.get(), sigStructure.release())) {
          throw InvalidCborError("Failed to add signature to signatures array");
        }
      }
      
      // Add signatures array to main structure
      if (!cbor_array_push(coseStructure.get(), signaturesArray.release())) {
        throw InvalidCborError("Failed to add signatures array to COSE_Sign structure");
      }
    } else if (mode == CwtMode::Encrypted) {
      // For COSE_Encrypt0: [protected_header, unprotected_header, ciphertext]
      coseStructure = CborItemPtr(cbor_new_definite_array(3));
      
      // Add protected header (encoded as bstr)
      auto protectedHeader = CborItemPtr(cbor_build_bytestring(coseHeader.data(), coseHeader.size()));
      if (!cbor_array_push(coseStructure.get(), protectedHeader.release())) {
        throw InvalidCborError("Failed to add protected header to COSE_Encrypt0 structure");
      }
      
      // Add unprotected header with IV (map)
      auto unprotectedHeader = CborItemPtr(cbor_new_definite_map(1));
      auto ivKey = CborItemPtr(cbor_build_uint8(5)); // COSE header label for IV
      auto ivVal = CborItemPtr(cbor_build_bytestring(iv.data(), iv.size()));
      struct cbor_pair iv_pair = {ivKey.release(), ivVal.release()};
      if (!cbor_map_add(unprotectedHeader.get(), iv_pair)) {
        cbor_decref(&iv_pair.key);
        cbor_decref(&iv_pair.value);
        throw InvalidCborError("Failed to add IV to unprotected header");
      }
      
      if (!cbor_array_push(coseStructure.get(), unprotectedHeader.release())) {
        throw InvalidCborError("Failed to add unprotected header to COSE_Encrypt0 structure");
      }
      
      // Add encrypted payload (encoded as bstr)
      auto ciphertextBstr = CborItemPtr(cbor_build_bytestring(encryptedPayload.data(), encryptedPayload.size()));
      if (!cbor_array_push(coseStructure.get(), ciphertextBstr.release())) {
        throw InvalidCborError("Failed to add ciphertext to COSE_Encrypt0 structure");
      }
    } else {
      // For COSE_Sign1/COSE_Mac0: [protected_header, unprotected_header, payload, signature]
      coseStructure = CborItemPtr(cbor_new_definite_array(4));
      
      // Add protected header (encoded as bstr)
      auto protectedHeader = CborItemPtr(cbor_build_bytestring(coseHeader.data(), coseHeader.size()));
      if (!cbor_array_push(coseStructure.get(), protectedHeader.release())) {
        throw InvalidCborError("Failed to add protected header to COSE structure");
      }
      
      // Add empty unprotected header (map)
      auto unprotectedHeader = CborItemPtr(cbor_new_definite_map(0));
      if (!cbor_array_push(coseStructure.get(), unprotectedHeader.release())) {
        throw InvalidCborError("Failed to add unprotected header to COSE structure");
      }
      
      // Add payload (encoded as bstr)
      auto payloadBstr = CborItemPtr(cbor_build_bytestring(payload.data(), payload.size()));
      if (!cbor_array_push(coseStructure.get(), payloadBstr.release())) {
        throw InvalidCborError("Failed to add payload to COSE structure");
      }
      
      // Add signature (encoded as bstr)
      auto signatureBstr = CborItemPtr(cbor_build_bytestring(signature.data(), signature.size()));
      if (!cbor_array_push(coseStructure.get(), signatureBstr.release())) {
        throw InvalidCborError("Failed to add signature to COSE structure");
      }
    }
    
    // Step 6: Serialize COSE structure
    unsigned char* raw_buffer;
    size_t buffer_size;
    size_t length = cbor_serialize_alloc(coseStructure.get(), &raw_buffer, &buffer_size);
    
    if (length == 0) {
      throw InvalidCborError("Failed to serialize COSE structure");
    }
    
    auto buffer = CborBufferPtr(raw_buffer);
    std::vector<uint8_t> coseBytes(buffer.get(), buffer.get() + length);
    
    // Step 7: Base64url encode according to RFC 4648 Section 5
    std::string result = base64UrlEncode(coseBytes);
    
    CAT_LOG_DEBUG("Created CWT token of {} bytes, base64url length {}", 
                  coseBytes.size(), result.size());
    
    return result;
    
  } catch (const std::exception& e) {
    CAT_LOG_ERROR("CWT creation failed: {}", e.what());
    throw CryptoError(std::string("CWT creation failed: ") + e.what());
  }
}

Cwt Cwt::validateCwt(const std::string& encodedCwt, 
                     const CryptographicAlgorithm& algorithm) {
  try {
    CAT_LOG_DEBUG("Validating CWT token of {} characters", encodedCwt.size());
    
    // Step 1: Base64url decode according to RFC 4648 Section 5
    auto coseBytes = base64UrlDecode(encodedCwt);
    
    // Step 2: Parse COSE structure
    struct cbor_load_result result;
    cbor_item_t* coseItem = cbor_load(coseBytes.data(), coseBytes.size(), &result);
    
    if (result.error.code != CBOR_ERR_NONE) {
      throw InvalidCborError("Failed to parse COSE structure");
    }
    
    // Step 3: Handle different COSE structures
    std::vector<uint8_t> protectedHeaderBytes;
    std::vector<uint8_t> payloadBytes;
    bool isEncrypted = false;
    bool isMultiSigned = false;
    std::vector<CoseSignature> validatedSignatures;
    
    size_t arraySize = cbor_array_size(coseItem);
    
    if (arraySize == 3) {
      // COSE_Encrypt0: [protected_header, unprotected_header, ciphertext]
      if (!algorithm.supportsEncryption()) {
        cbor_decref(&coseItem);
        throw CryptoError("Algorithm does not support decryption for COSE_Encrypt0");
      }
      isEncrypted = true;
      
      cbor_item_t** coseArray = cbor_array_handle(coseItem);
      
      // Protected header (bytestring)
      if (!cbor_isa_bytestring(coseArray[0])) {
        cbor_decref(&coseItem);
        throw InvalidTokenFormatError();
      }
      protectedHeaderBytes = std::vector<uint8_t>(
        cbor_bytestring_handle(coseArray[0]),
        cbor_bytestring_handle(coseArray[0]) + cbor_bytestring_length(coseArray[0])
      );
      
      // Extract IV from unprotected header (map)
      if (!cbor_isa_map(coseArray[1])) {
        cbor_decref(&coseItem);
        throw InvalidTokenFormatError();
      }
      
      std::vector<uint8_t> iv;
      struct cbor_pair* pairs = cbor_map_handle(coseArray[1]);
      size_t map_size = cbor_map_size(coseArray[1]);
      
      for (size_t i = 0; i < map_size; i++) {
        if (cbor_isa_uint(pairs[i].key) && cbor_get_uint8(pairs[i].key) == 5) { // IV label
          if (cbor_isa_bytestring(pairs[i].value)) {
            iv = std::vector<uint8_t>(
              cbor_bytestring_handle(pairs[i].value),
              cbor_bytestring_handle(pairs[i].value) + cbor_bytestring_length(pairs[i].value)
            );
            break;
          }
        }
      }
      
      if (iv.empty()) {
        cbor_decref(&coseItem);
        throw InvalidTokenFormatError();
      }
      
      // Ciphertext (bytestring)
      if (!cbor_isa_bytestring(coseArray[2])) {
        cbor_decref(&coseItem);
        throw InvalidTokenFormatError();
      }
      auto ciphertext = std::vector<uint8_t>(
        cbor_bytestring_handle(coseArray[2]),
        cbor_bytestring_handle(coseArray[2]) + cbor_bytestring_length(coseArray[2])
      );
      
      // Decrypt the payload
      payloadBytes = algorithm.decrypt(ciphertext, iv);
      
    } else if (arraySize == 4) {
      cbor_item_t** coseArray = cbor_array_handle(coseItem);
      
      // Check if this is COSE_Sign1 or COSE_Sign
      // COSE_Sign1: [protected_header, unprotected_header, payload, signature]
      // COSE_Sign:  [protected_header, unprotected_header, payload, signatures_array]
      
      // Get common fields first
      // Protected header (bytestring)
      if (!cbor_isa_bytestring(coseArray[0])) {
        cbor_decref(&coseItem);
        throw InvalidTokenFormatError();
      }
      protectedHeaderBytes = std::vector<uint8_t>(
        cbor_bytestring_handle(coseArray[0]),
        cbor_bytestring_handle(coseArray[0]) + cbor_bytestring_length(coseArray[0])
      );
      
      // Payload (bytestring)  
      if (!cbor_isa_bytestring(coseArray[2])) {
        cbor_decref(&coseItem);
        throw InvalidTokenFormatError();
      }
      payloadBytes = std::vector<uint8_t>(
        cbor_bytestring_handle(coseArray[2]),
        cbor_bytestring_handle(coseArray[2]) + cbor_bytestring_length(coseArray[2])
      );
      
      // Check if the 4th element is an array (COSE_Sign) or bytestring (COSE_Sign1)
      if (cbor_isa_array(coseArray[3])) {
        // COSE_Sign: [protected_header, unprotected_header, payload, signatures_array]
        // RFC 8152 Section 4.1: validateCwt should only handle COSE_Sign1
        cbor_decref(&coseItem);
        throw InvalidTokenFormatError();
      } else if (cbor_isa_bytestring(coseArray[3])) {
        // COSE_Sign1/COSE_Mac0: [protected_header, unprotected_header, payload, signature]
        auto signatureBytes = std::vector<uint8_t>(
          cbor_bytestring_handle(coseArray[3]),
          cbor_bytestring_handle(coseArray[3]) + cbor_bytestring_length(coseArray[3])
        );
        
        // Verify signature using COSE_Sign1 Sig_structure
        auto signingInput = createCoseSign1Input(protectedHeaderBytes, payloadBytes);
        bool isValid = algorithm.verify(signingInput, signatureBytes);
        
        if (!isValid) {
          cbor_decref(&coseItem);
          throw CryptoError("COSE_Sign1 signature verification failed");
        }
      } else {
        cbor_decref(&coseItem);
        throw InvalidTokenFormatError();
      }
    } else {
      cbor_decref(&coseItem);
      throw InvalidTokenFormatError();
    }
    
    cbor_decref(&coseItem);
    
    // Step 4: Decode payload and create CWT
    auto decodedPayload = decodePayload(payloadBytes);
    
    // Parse protected header to get algorithm
    struct cbor_load_result headerResult;
    cbor_item_t* headerItem = cbor_load(protectedHeaderBytes.data(), 
                                       protectedHeaderBytes.size(), &headerResult);
    
    if (headerResult.error.code != CBOR_ERR_NONE || !cbor_isa_map(headerItem)) {
      if (headerItem) cbor_decref(&headerItem);
      throw InvalidCborError("Invalid COSE protected header");
    }
    
    int64_t algId = algorithm.algorithmId();
    // Extract other header fields if needed...
    
    cbor_decref(&headerItem);
    
    Cwt validatedCwt(algId, decodedPayload);
    
    // Store validated signatures for multi-signed CWTs
    if (isMultiSigned) {
      validatedCwt.signatures = std::move(validatedSignatures);
    }
    // Note: For encrypted CWTs, there's no signature to store
    
    CAT_LOG_DEBUG("CWT validation successful");
    return validatedCwt;
    
  } catch (const std::exception& e) {
    CAT_LOG_ERROR("CWT validation failed: {}", e.what());
    throw CryptoError(std::string("CWT validation failed: ") + e.what());
  }
}

Cwt Cwt::validateMultiSignedCwt(const std::string& encodedCwt,
                                const std::map<int64_t, std::reference_wrapper<const CryptographicAlgorithm>>& algorithms) {
  try {
    CAT_LOG_DEBUG("Validating multi-signed CWT token of {} characters", encodedCwt.size());
    
    // Step 1: Base64url decode according to RFC 4648 Section 5
    auto coseBytes = base64UrlDecode(encodedCwt);
    
    // Step 2: Parse COSE structure
    struct cbor_load_result result;
    cbor_item_t* coseItem = cbor_load(coseBytes.data(), coseBytes.size(), &result);
    
    if (result.error.code != CBOR_ERR_NONE) {
      throw InvalidCborError("Failed to parse COSE structure");
    }
    
    // Step 3: Handle COSE_Sign structure (must be 4-element array with signatures array)
    std::vector<uint8_t> protectedHeaderBytes;
    std::vector<uint8_t> payloadBytes;
    std::vector<CoseSignature> validatedSignatures;
    
    size_t arraySize = cbor_array_size(coseItem);
    
    if (arraySize != 4) {
      cbor_decref(&coseItem);
      throw InvalidTokenFormatError();
    }
    
    cbor_item_t** coseArray = cbor_array_handle(coseItem);
    
    // Get common fields
    // Protected header (bytestring)
    if (!cbor_isa_bytestring(coseArray[0])) {
      cbor_decref(&coseItem);
      throw InvalidTokenFormatError();
    }
    protectedHeaderBytes = std::vector<uint8_t>(
      cbor_bytestring_handle(coseArray[0]),
      cbor_bytestring_handle(coseArray[0]) + cbor_bytestring_length(coseArray[0])
    );
    
    // Payload (bytestring)  
    if (!cbor_isa_bytestring(coseArray[2])) {
      cbor_decref(&coseItem);
      throw InvalidTokenFormatError();
    }
    payloadBytes = std::vector<uint8_t>(
      cbor_bytestring_handle(coseArray[2]),
      cbor_bytestring_handle(coseArray[2]) + cbor_bytestring_length(coseArray[2])
    );
    
    // Must be COSE_Sign with signatures array
    if (!cbor_isa_array(coseArray[3])) {
      cbor_decref(&coseItem);
      throw InvalidTokenFormatError();
    }
    
    // Validate all signatures in the array
    cbor_item_t** signaturesArray = cbor_array_handle(coseArray[3]);
    size_t signaturesCount = cbor_array_size(coseArray[3]);
    
    for (size_t i = 0; i < signaturesCount; i++) {
      if (!cbor_isa_array(signaturesArray[i]) || cbor_array_size(signaturesArray[i]) != 3) {
        cbor_decref(&coseItem);
        throw InvalidTokenFormatError();
      }
      
      cbor_item_t** signatureStructure = cbor_array_handle(signaturesArray[i]);
      
      // Extract signature protected header
      if (!cbor_isa_bytestring(signatureStructure[0])) {
        cbor_decref(&coseItem);
        throw InvalidTokenFormatError();
      }
      std::vector<uint8_t> sigProtectedHeader(
        cbor_bytestring_handle(signatureStructure[0]),
        cbor_bytestring_handle(signatureStructure[0]) + cbor_bytestring_length(signatureStructure[0])
      );
      
      // Extract signature bytes
      if (!cbor_isa_bytestring(signatureStructure[2])) {
        cbor_decref(&coseItem);
        throw InvalidTokenFormatError();
      }
      std::vector<uint8_t> signatureBytes(
        cbor_bytestring_handle(signatureStructure[2]),
        cbor_bytestring_handle(signatureStructure[2]) + cbor_bytestring_length(signatureStructure[2])
      );
      
      // Extract algorithm ID from signature header
      int64_t sigAlgId = 0;
      bool algFound = false;
      
      if (!sigProtectedHeader.empty()) {
        struct cbor_load_result sigHeaderResult;
        cbor_item_t* sigHeaderItem = cbor_load(sigProtectedHeader.data(), 
                                              sigProtectedHeader.size(), &sigHeaderResult);
        if (sigHeaderResult.error.code == CBOR_ERR_NONE && cbor_isa_map(sigHeaderItem)) {
          struct cbor_pair* pairs = cbor_map_handle(sigHeaderItem);
          size_t mapSize = cbor_map_size(sigHeaderItem);
          
          for (size_t j = 0; j < mapSize; j++) {
            if (cbor_isa_uint(pairs[j].key) && cbor_get_uint8(pairs[j].key) == 1) { // algorithm label
              if (cbor_isa_uint(pairs[j].value)) {
                sigAlgId = cbor_get_uint64(pairs[j].value);
                algFound = true;
              } else if (cbor_isa_negint(pairs[j].value)) {
                sigAlgId = -static_cast<int64_t>(cbor_get_uint64(pairs[j].value)) - 1;
                algFound = true;
              }
              break;
            }
          }
        }
        if (sigHeaderItem) cbor_decref(&sigHeaderItem);
      }
      
      if (!algFound) {
        cbor_decref(&coseItem);
        throw CryptoError("Algorithm ID not found in signature " + std::to_string(i) + " protected header");
      }
      
      // Find the corresponding algorithm
      auto algIt = algorithms.find(sigAlgId);
      if (algIt == algorithms.end()) {
        cbor_decref(&coseItem);
        throw CryptoError("No algorithm provided for signature " + std::to_string(i) + " with algorithm ID " + std::to_string(sigAlgId));
      }
      
      // Create COSE_Sign Sig_structure and verify with the specific algorithm
      auto signingInput = createCoseSignInput(protectedHeaderBytes, sigProtectedHeader, {}, payloadBytes);
      bool isValid = algIt->second.get().verify(signingInput, signatureBytes);
      
      if (!isValid) {
        cbor_decref(&coseItem);
        throw CryptoError("Multi-signed CWT signature verification failed for signature " + std::to_string(i));
      }
      
      // Store validated signature with algorithm ID
      validatedSignatures.emplace_back(sigProtectedHeader, signatureBytes, sigAlgId);
    }
    
    cbor_decref(&coseItem);
    
    // Step 4: Decode payload and create CWT
    auto decodedPayload = decodePayload(payloadBytes);
    
    // Parse protected header to get primary algorithm (use first signature's algorithm)
    int64_t primaryAlgId = validatedSignatures.empty() ? 0 : validatedSignatures[0].algorithmId;
    
    Cwt validatedCwt(primaryAlgId, decodedPayload);
    validatedCwt.signatures = std::move(validatedSignatures);
    
    CAT_LOG_DEBUG("Multi-signed CWT validation successful with {} signatures", validatedCwt.signatures.size());
    return validatedCwt;
    
  } catch (const std::exception& e) {
    CAT_LOG_ERROR("Multi-signed CWT validation failed: {}", e.what());
    throw CryptoError(std::string("Multi-signed CWT validation failed: ") + e.what());
  }
}

std::vector<uint8_t> Cwt::createDpopSigningInput(
    const AuthorizationContext& actx,
    int64_t iat,
    const std::optional<std::string>& jti,
    const std::optional<std::string>& ath) {
  
  try {
    // Create CBOR map for DPoP payload
    auto payload_map = CborItemPtr(cbor_new_definite_map(5));
    if (!payload_map) {
      throw InvalidCborError("Failed to create DPoP payload map");
    }
    
    // Add actx (Authorization Context) as nested map with all 5 fields
    auto actx_map = CborItemPtr(cbor_new_definite_map(5));
    if (!actx_map) {
      throw InvalidCborError("Failed to create Authorization Context map");
    }
    
    // Add type
    auto type_key = CborItemPtr(cbor_build_string("type"));
    auto type_val = CborItemPtr(cbor_build_string(actx.type.c_str()));
    if (!type_key || !type_val) {
      throw InvalidCborError("Failed to create type CBOR items");
    }
    struct cbor_pair type_pair = {type_key.release(), type_val.release()};
    if (!cbor_map_add(actx_map.get(), type_pair)) {
      cbor_decref(&type_pair.key);
      cbor_decref(&type_pair.value);
      throw InvalidCborError("Failed to add type to actx map");
    }
    
    // Add action
    auto action_key = CborItemPtr(cbor_build_string("action"));
    auto action_val = CborItemPtr(cbor_build_uint64(actx.action));
    if (!action_key || !action_val) {
      throw InvalidCborError("Failed to create action CBOR items");
    }
    struct cbor_pair action_pair = {action_key.release(), action_val.release()};
    if (!cbor_map_add(actx_map.get(), action_pair)) {
      cbor_decref(&action_pair.key);
      cbor_decref(&action_pair.value);
      throw InvalidCborError("Failed to add action to actx map");
    }
    
    // Add tns (track namespace)
    auto tns_key = CborItemPtr(cbor_build_string("tns"));
    auto tns_val = CborItemPtr(cbor_build_string(actx.tns.c_str()));
    if (!tns_key || !tns_val) {
      throw InvalidCborError("Failed to create tns CBOR items");
    }
    struct cbor_pair tns_pair = {tns_key.release(), tns_val.release()};
    if (!cbor_map_add(actx_map.get(), tns_pair)) {
      cbor_decref(&tns_pair.key);
      cbor_decref(&tns_pair.value);
      throw InvalidCborError("Failed to add tns to actx map");
    }
    
    // Add tn (track name)
    auto tn_key = CborItemPtr(cbor_build_string("tn"));
    auto tn_val = CborItemPtr(cbor_build_string(actx.tn.c_str()));
    if (!tn_key || !tn_val) {
      throw InvalidCborError("Failed to create tn CBOR items");
    }
    struct cbor_pair tn_pair = {tn_key.release(), tn_val.release()};
    if (!cbor_map_add(actx_map.get(), tn_pair)) {
      cbor_decref(&tn_pair.key);
      cbor_decref(&tn_pair.value);
      throw InvalidCborError("Failed to add tn to actx map");
    }
    
    // Add resource (optional)
    if (!actx.resource_uri.empty()) {
      auto resource_key = CborItemPtr(cbor_build_string("resource"));
      auto resource_val = CborItemPtr(cbor_build_string(actx.resource_uri.c_str()));
      if (!resource_key || !resource_val) {
        throw InvalidCborError("Failed to create resource CBOR items");
      }
      struct cbor_pair resource_pair = {resource_key.release(), resource_val.release()};
      if (!cbor_map_add(actx_map.get(), resource_pair)) {
        cbor_decref(&resource_pair.key);
        cbor_decref(&resource_pair.value);
        throw InvalidCborError("Failed to add resource to actx map");
      }
    }
    
    // Add actx to main payload
    auto actx_payload_key = CborItemPtr(cbor_build_string("actx"));
    if (!actx_payload_key) {
      throw InvalidCborError("Failed to create actx payload key");
    }
    struct cbor_pair actx_payload_pair = {actx_payload_key.release(), actx_map.release()};
    if (!cbor_map_add(payload_map.get(), actx_payload_pair)) {
      cbor_decref(&actx_payload_pair.key);
      cbor_decref(&actx_payload_pair.value);
      throw InvalidCborError("Failed to add actx to payload map");
    }
    
    // Add iat (issued at)
    auto iat_key = CborItemPtr(cbor_build_string("iat"));
    auto iat_val = CborItemPtr(cbor_build_uint64(iat));
    if (!iat_key || !iat_val) {
      throw InvalidCborError("Failed to create iat CBOR items");
    }
    struct cbor_pair iat_pair = {iat_key.release(), iat_val.release()};
    if (!cbor_map_add(payload_map.get(), iat_pair)) {
      cbor_decref(&iat_pair.key);
      cbor_decref(&iat_pair.value);
      throw InvalidCborError("Failed to add iat to payload map");
    }
    
    // Add jti if present
    if (jti.has_value()) {
      auto jti_key = CborItemPtr(cbor_build_string("jti"));
      auto jti_val = CborItemPtr(cbor_build_string(jti.value().c_str()));
      if (!jti_key || !jti_val) {
        throw InvalidCborError("Failed to create jti CBOR items");
      }
      struct cbor_pair jti_pair = {jti_key.release(), jti_val.release()};
      if (!cbor_map_add(payload_map.get(), jti_pair)) {
        cbor_decref(&jti_pair.key);
        cbor_decref(&jti_pair.value);
        throw InvalidCborError("Failed to add jti to payload map");
      }
    }
    
    // Add ath if present
    if (ath.has_value()) {
      auto ath_key = CborItemPtr(cbor_build_string("ath"));
      auto ath_val = CborItemPtr(cbor_build_string(ath.value().c_str()));
      if (!ath_key || !ath_val) {
        throw InvalidCborError("Failed to create ath CBOR items");
      }
      struct cbor_pair ath_pair = {ath_key.release(), ath_val.release()};
      if (!cbor_map_add(payload_map.get(), ath_pair)) {
        cbor_decref(&ath_pair.key);
        cbor_decref(&ath_pair.value);
        throw InvalidCborError("Failed to add ath to payload map");
      }
    }
    
    // Serialize CBOR to bytes
    unsigned char* raw_buffer;
    size_t buffer_size;
    size_t length = cbor_serialize_alloc(payload_map.get(), &raw_buffer, &buffer_size);
    
    if (length == 0) {
      throw InvalidCborError("Failed to serialize DPoP proof CBOR");
    }
    
    auto buffer = CborBufferPtr(raw_buffer);
    std::vector<uint8_t> result(buffer.get(), buffer.get() + length);
    
    CAT_LOG_DEBUG("Created DPoP signing input of {} bytes", result.size());
    return result;
    
  } catch (const std::exception& e) {
    CAT_LOG_ERROR("DPoP signing input creation failed: {}", e.what());
    throw InvalidCborError(std::string("DPoP signing input creation failed: ") + e.what());
  }
}

}  // namespace catapult