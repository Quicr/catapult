#include "catapult/cwt.hpp"

#include <cbor.h>

#include <algorithm>

#include "catapult/crypto.hpp"
#include "catapult/logging.hpp"

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
  
  // Move-only semantics
  CborMapBuilder(const CborMapBuilder&) = delete;
  CborMapBuilder& operator=(const CborMapBuilder&) = delete;
  CborMapBuilder(CborMapBuilder&&) = default;
  CborMapBuilder& operator=(CborMapBuilder&&) = default;
  
  /**
   * @brief Add a claim
   */
  template<typename T>
  void addClaim(int64_t claim_id, T&& value) requires CborEncodable<T> {
    if (!value.has_value()) {
        CAT_LOG_TRACE("Skipping claim {} - no value provided", claim_id);
        return;
    }
    addClaimImpl(claim_id, std::forward<T>(value).value());
  }
  
  /**
   * @brief Add typed claim (legacy version)
   */
  template<int64_t ClaimId, typename T>
  void addClaimTyped(T&& value) requires CborEncodable<T> {
    static_assert(ClaimId > 0, "Claim ID must be positive");
    static_assert(ClaimId <= 65535, "Claim ID must be within valid range");
    addClaim(ClaimId, std::forward<T>(value));
  }
  
  /**
   * @brief Add claim using ClaimIdentifier type for compile-time safety
   */
  template<typename ClaimType, typename T>
  void addClaim(T&& value) requires CborEncodable<T> {
    static_assert(ClaimType::value > 0, "Claim ID must be positive");
    static_assert(ClaimType::value <= 65535, "Claim ID must be within valid range");
    addClaim(ClaimType::value, std::forward<T>(value));
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
  }
};

Cwt::Cwt(int64_t alg, const CatToken& token) : header(alg), payload(token) {}

Cwt& Cwt::withKeyId(const std::string& kid) {
  header.kid = kid;
  return *this;
}

std::vector<uint8_t> Cwt::encodePayload() const {
  try {
    // Use RAII CBOR builder with compile-time claim processing
    CborMapBuilder builder(20);  // Reserve space for up to 20 claims
    
    // Process all claims using compile-time dispatch
    ClaimProcessor<CatToken>::processAllClaims(builder, payload);
    
    // Get the CBOR root and serialize
    auto root = builder.release();
    
    // Serialize to buffer using RAII
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
    
    // Use RAII for buffer management
    auto buffer = CborBufferPtr(raw_buffer);
    auto result = std::vector<uint8_t>(buffer.get(), buffer.get() + length);
    
    return result;
    
  } catch (const std::exception& e) {
    throw InvalidCborError(std::string("CBOR encoding failed: ") + e.what());
  }
}

CatToken Cwt::decodePayload(const std::vector<uint8_t>& cborData) {
  struct cbor_load_result result;
  cbor_item_t* item = cbor_load(cborData.data(), cborData.size(), &result);

  if (result.error.code != CBOR_ERR_NONE) {
    if (result.error.code == CBOR_ERR_MEMERROR) {
      throwOsError("cbor_load memory allocation");
    } else {
      throw InvalidCborError("Failed to parse CBOR data");
    }
  }

  if (!cbor_isa_map(item)) {
    cbor_decref(&item);
    throw InvalidTokenFormatError();
  }

  CatToken token;
  struct cbor_pair* pairs = cbor_map_handle(item);
  size_t map_size = cbor_map_size(item);

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
          token.core.iss = std::string(
              reinterpret_cast<const char*>(cbor_string_handle(value_item)),
              cbor_string_length(value_item));
        }
        break;

      case CLAIM_AUD:
        if (cbor_isa_array(value_item)) {
          std::vector<std::string> audiences;
          size_t array_size = cbor_array_size(value_item);
          cbor_item_t** array_handle = cbor_array_handle(value_item);

          for (size_t j = 0; j < array_size; j++) {
            if (cbor_isa_string(array_handle[j])) {
              audiences.emplace_back(reinterpret_cast<const char*>(
                                         cbor_string_handle(array_handle[j])),
                                     cbor_string_length(array_handle[j]));
            }
          }
          token.core.aud = audiences;
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
          token.core.cti = std::string(
              reinterpret_cast<const char*>(cbor_bytestring_handle(value_item)),
              cbor_bytestring_length(value_item));
        } else if (cbor_isa_string(value_item)) {
          token.core.cti = std::string(
              reinterpret_cast<const char*>(cbor_string_handle(value_item)),
              cbor_string_length(value_item));
        }
        break;

      case CLAIM_CATREPLAY:
        if (cbor_isa_string(value_item)) {
          token.cat.catreplay = std::string(
              reinterpret_cast<const char*>(cbor_string_handle(value_item)),
              cbor_string_length(value_item));
        }
        break;

      case CLAIM_CATPOR:
        if (cbor_is_bool(value_item)) {
          token.cat.catpor = cbor_get_bool(value_item);
        }
        break;

      case CLAIM_CATV:
        if (cbor_isa_string(value_item)) {
          token.cat.catv = std::string(
              reinterpret_cast<const char*>(cbor_string_handle(value_item)),
              cbor_string_length(value_item));
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
          
          for (size_t k = 0; k < coord_map_size; k++) {
            cbor_item_t* coord_key = coord_pairs[k].key;
            cbor_item_t* coord_value = coord_pairs[k].value;
            
            if (!cbor_isa_string(coord_key)) continue;
            
            std::string key_str(reinterpret_cast<const char*>(cbor_string_handle(coord_key)),
                               cbor_string_length(coord_key));
            
            if (key_str == "lat" && cbor_isa_float_ctrl(coord_value)) {
              coord.lat = cbor_float_get_float8(coord_value);
            } else if (key_str == "lon" && cbor_isa_float_ctrl(coord_value)) {
              coord.lon = cbor_float_get_float8(coord_value);
            } else if (key_str == "accuracy" && cbor_isa_float_ctrl(coord_value)) {
              coord.accuracy = cbor_float_get_float8(coord_value);
            }
          }
          token.cat.catgeocoord = coord;
        }
        break;

      case CLAIM_GEOHASH:
        if (cbor_isa_string(value_item)) {
          token.cat.geohash = std::string(
              reinterpret_cast<const char*>(cbor_string_handle(value_item)),
              cbor_string_length(value_item));
        }
        break;
    }
  }

  cbor_decref(&item);
  return token;
}

}  // namespace catapult