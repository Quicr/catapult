#include "catapult/cwt.hpp"

#include <cbor.h>

#include <algorithm>
#include <limits>

#include "catapult/base64.hpp"
#include "catapult/crypto.hpp"
#include "catapult/dpop.hpp"
#include "catapult/internal/cbor_owned.hpp"
#include "catapult/internal/parse_limits.hpp"
#include "catapult/internal/strict_cbor.hpp"
#include "catapult/logging.hpp"

namespace catapult {

namespace {

// COSE alg IDs are drawn from the IANA COSE Algorithms registry, which uses
// small positive/negative integers. Reject anything outside a conservative
// range so an attacker cannot smuggle a value whose CBOR round-trip would
// overflow int64_t (see RFC 8152 §8, RFC 9053 §2.1). The range easily covers
// every currently-registered algorithm identifier.
constexpr int64_t kMinCoseAlgId = -65536;
constexpr int64_t kMaxCoseAlgId = 65535;

// Build the CBOR alg header value with an overflow-safe negint conversion.
CborItemPtr buildAlgCborValue(int64_t alg) {
  if (alg < kMinCoseAlgId || alg > kMaxCoseAlgId) {
    throw InvalidCborError("COSE algorithm id out of accepted range");
  }
  if (alg >= 0) {
    return CborItemPtr(cbor_build_uint64(static_cast<uint64_t>(alg)));
  }
  // Encode -1 - alg without overflowing when alg == INT64_MIN.
  uint64_t magnitude = static_cast<uint64_t>(-(alg + 1));
  return CborItemPtr(cbor_build_negint64(magnitude));
}

// Decode a COSE alg header value, enforcing the same range and rejecting
// negints whose (-1 - n) representation would exceed int64_t.
bool decodeAlgCborValue(cbor_item_t* value, int64_t& out) {
  if (cbor_isa_uint(value)) {
    uint64_t raw = cbor_get_int(value);
    if (raw > static_cast<uint64_t>(kMaxCoseAlgId)) return false;
    out = static_cast<int64_t>(raw);
    return true;
  }
  if (cbor_isa_negint(value)) {
    uint64_t magnitude = cbor_get_int(value);  // encodes -1 - value
    if (magnitude > static_cast<uint64_t>(-(kMinCoseAlgId + 1))) return false;
    out = -static_cast<int64_t>(magnitude) - 1;
    return true;
  }
  return false;
}

}  // namespace

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
  template <typename TokenType>
  friend class ClaimProcessor;

 public:
  explicit CborMapBuilder(size_t initial_capacity = 20)
      : root_(cbor_new_definite_map(initial_capacity)) {
    if (!root_) {
      CAT_LOG_ERROR("Failed to create CBOR map with capacity {}",
                    initial_capacity);
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
  template <typename ClaimType, typename T>
  void addClaim(T&& value)
    requires CborEncodable<T>
  {
    static_assert(ClaimType::value > 0, "Claim ID must be positive");
    static_assert(ClaimType::value <= 65535,
                  "Claim ID must be within valid range");

    if constexpr (requires { value.has_value(); }) {
      // Handle optional types (std::optional, etc.)
      if (!value.has_value()) {
        CAT_LOG_TRACE("Skipping claim {} - no value provided",
                      ClaimType::value);
        return;
      }
      addClaimImpl(ClaimType::value, std::forward<T>(value).value());
    } else {
      // Handle direct values
      addClaimImpl(ClaimType::value, std::forward<T>(value));
    }
  }

  CborItemPtr release() { return std::move(root_); }

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
      if (!cbor_array_push(array.get(), str_item.get())) {
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

  // CTA-5007-B `catgeocoord`: array `[lat, lon, radius?]`. A missing radius
  // is represented as the two-element form; producers MUST NOT emit a
  // separate `accuracy` map key (that was the pre-1.3 shape).
  void addClaimImpl(int64_t claim_id, const GeoCoordinate& coord) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    const size_t len = coord.radius.has_value() ? 3 : 2;
    auto arr = cbor_new_definite_array_owned(len);
    auto lat_val = CborItemPtr(cbor_build_float8(coord.lat));
    if (!cbor_array_push(arr.get(), lat_val.get())) {
      throw InvalidCborError("Failed to push catgeocoord latitude");
    }
    auto lon_val = CborItemPtr(cbor_build_float8(coord.lon));
    if (!cbor_array_push(arr.get(), lon_val.get())) {
      throw InvalidCborError("Failed to push catgeocoord longitude");
    }
    if (coord.radius.has_value()) {
      auto rad_val = CborItemPtr(cbor_build_float8(*coord.radius));
      if (!cbor_array_push(arr.get(), rad_val.get())) {
        throw InvalidCborError("Failed to push catgeocoord radius");
      }
    }
    addPair(std::move(key), std::move(arr));
  }

  // CTA-5007-B `catgeoalt`: array `[altitude, deviation?]`.
  void addClaimImpl(int64_t claim_id, const GeoAltitude& alt) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    const size_t len = alt.deviation.has_value() ? 2 : 1;
    auto arr = cbor_new_definite_array_owned(len);
    auto alt_val = CborItemPtr(cbor_build_uint64(
        static_cast<uint64_t>(alt.altitude < 0 ? -alt.altitude : alt.altitude)));
    // Negative altitudes encode as negints per RFC 8949; use the alg helper.
    if (alt.altitude < 0) {
      alt_val = CborItemPtr(cbor_build_negint64(
          static_cast<uint64_t>(-(static_cast<int64_t>(alt.altitude) + 1))));
    }
    if (!cbor_array_push(arr.get(), alt_val.get())) {
      throw InvalidCborError("Failed to push catgeoalt altitude");
    }
    if (alt.deviation.has_value()) {
      const int32_t d = *alt.deviation;
      auto dev_val = d >= 0
                         ? CborItemPtr(cbor_build_uint64(static_cast<uint64_t>(d)))
                         : CborItemPtr(cbor_build_negint64(
                               static_cast<uint64_t>(-(static_cast<int64_t>(d) + 1))));
      if (!cbor_array_push(arr.get(), dev_val.get())) {
        throw InvalidCborError("Failed to push catgeoalt deviation");
      }
    }
    addPair(std::move(key), std::move(arr));
  }

  // CTA-5007-B `geohash`: either a text string or an array of strings.
  void addClaimImpl(int64_t claim_id, const GeohashClaimValue& gh) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    if (gh.isString()) {
      auto val = CborItemPtr(cbor_build_string(gh.asString().c_str()));
      addPair(std::move(key), std::move(val));
      return;
    }
    const auto& arr_val = gh.asArray();
    auto arr = cbor_new_definite_array_owned(arr_val.size());
    for (const auto& s : arr_val) {
      auto item = CborItemPtr(cbor_build_string(s.c_str()));
      if (!cbor_array_push(arr.get(), item.get())) {
        throw InvalidCborError("Failed to push geohash entry");
      }
    }
    addPair(std::move(key), std::move(arr));
  }

  // CTA-5007-B `catreplay`: unsigned integer mode (0/1/2/...).
  void addClaimImpl(int64_t claim_id, CatReplayMode mode) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    auto val = CborItemPtr(
        cbor_build_uint64(static_cast<uint64_t>(mode)));
    addPair(std::move(key), std::move(val));
  }

  // CTA-5007-B `catpor`: [probability, identifier, ?expiry].
  void addClaimImpl(int64_t claim_id, const CatProofOfPossession& por) {
    if (!por.is_valid()) {
      throw InvalidClaimValueError(
          "'catpor' probability out of [0,1] or empty identifier");
    }
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    const size_t len = por.expiry.has_value() ? 3 : 2;
    auto arr = cbor_new_definite_array_owned(len);
    auto prob = CborItemPtr(cbor_build_float8(por.probability));
    if (!cbor_array_push(arr.get(), prob.get())) {
      throw InvalidCborError("Failed to push catpor probability");
    }
    auto ident =
        cbor_build_bytestring_owned(por.identifier.data(), por.identifier.size());
    if (!cbor_array_push(arr.get(), ident.get())) {
      throw InvalidCborError("Failed to push catpor identifier");
    }
    if (por.expiry.has_value()) {
      const int64_t e = *por.expiry;
      auto exp_val = e >= 0
                         ? CborItemPtr(cbor_build_uint64(static_cast<uint64_t>(e)))
                         : CborItemPtr(cbor_build_negint64(
                               static_cast<uint64_t>(-(e + 1))));
      if (!cbor_array_push(arr.get(), exp_val.get())) {
        throw InvalidCborError("Failed to push catpor expiry");
      }
    }
    addPair(std::move(key), std::move(arr));
  }

  // CTA-5007-B `catnip`: array of tagged NIP entries.
  void addClaimImpl(int64_t claim_id, const std::vector<CatNipEntry>& nips) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    auto arr = cbor_new_definite_array_owned(nips.size());
    for (const auto& e : nips) {
      auto val =
          cbor_build_bytestring_owned(e.value.data(), e.value.size());
      auto tagged = CborItemPtr(cbor_new_tag(e.tag));
      cbor_tag_set_item(tagged.get(), val.get());
      if (!cbor_array_push(arr.get(), tagged.get())) {
        throw InvalidCborError("Failed to push catnip entry");
      }
    }
    addPair(std::move(key), std::move(arr));
  }

  // CTA-5007-B `catu`: map from component label (int) to [type, value].
  void addClaimImpl(int64_t claim_id, const CatUriMatchMap& catu) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    auto m = cbor_new_definite_map_owned(catu.components.size());
    for (const auto& [label, match] : catu.components) {
      auto lbl_key = label >= 0
                         ? CborItemPtr(cbor_build_uint64(static_cast<uint64_t>(label)))
                         : CborItemPtr(cbor_build_negint64(
                               static_cast<uint64_t>(-(label + 1))));
      auto entry = cbor_new_definite_array_owned(2);
      auto ty = CborItemPtr(
          cbor_build_uint64(static_cast<uint64_t>(match.type)));
      if (!cbor_array_push(entry.get(), ty.get())) {
        throw InvalidCborError("Failed to push catu type");
      }
      auto val_bstr =
          cbor_build_bytestring_owned(match.value.data(), match.value.size());
      if (!cbor_array_push(entry.get(), val_bstr.get())) {
        throw InvalidCborError("Failed to push catu value");
      }
      addPairToMap(m.get(), std::move(lbl_key), std::move(entry));
    }
    addPair(std::move(key), std::move(m));
  }

  // CTA-5007-B `catalpn`: array of ALPN byte strings (exact byte match).
  void addClaimImpl(int64_t claim_id,
                    const std::vector<std::vector<uint8_t>>& alpn) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    auto arr = cbor_new_definite_array_owned(alpn.size());
    for (const auto& proto : alpn) {
      auto val = cbor_build_bytestring_owned(proto.data(), proto.size());
      if (!cbor_array_push(arr.get(), val.get())) {
        throw InvalidCborError("Failed to push catalpn entry");
      }
    }
    addPair(std::move(key), std::move(arr));
  }

  // CTA-5007-B `cath`: array of [header_name, [type, value]] pairs.
  void addClaimImpl(int64_t claim_id, const CatHostHeaderMatchList& cath) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    auto arr = cbor_new_definite_array_owned(cath.entries.size());
    for (const auto& e : cath.entries) {
      auto pair = cbor_new_definite_array_owned(2);
      auto name = CborItemPtr(cbor_build_string(e.name.c_str()));
      if (!cbor_array_push(pair.get(), name.get())) {
        throw InvalidCborError("Failed to push cath header name");
      }
      auto match = cbor_new_definite_array_owned(2);
      auto ty = CborItemPtr(
          cbor_build_uint64(static_cast<uint64_t>(e.match.type)));
      if (!cbor_array_push(match.get(), ty.get())) {
        throw InvalidCborError("Failed to push cath match type");
      }
      auto val_bstr = cbor_build_bytestring_owned(
          e.match.value.data(), e.match.value.size());
      if (!cbor_array_push(match.get(), val_bstr.get())) {
        throw InvalidCborError("Failed to push cath match value");
      }
      if (!cbor_array_push(pair.get(), match.get())) {
        throw InvalidCborError("Failed to push cath match tuple");
      }
      if (!cbor_array_push(arr.get(), pair.get())) {
        throw InvalidCborError("Failed to push cath entry");
      }
    }
    addPair(std::move(key), std::move(arr));
  }

  // RFC 8747 `cnf`: map with `jkt` bytes and/or `kid` string.
  void addClaimImpl(int64_t claim_id, const CatConfirmation& cnf) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    size_t entries = 0;
    if (cnf.jkt.has_value()) ++entries;
    if (cnf.kid.has_value()) ++entries;
    // If we have neither typed field but have raw bytes, emit those verbatim
    // as a bytestring so downstream verifiers see the issuer's original map.
    if (entries == 0 && cnf.raw.has_value()) {
      auto val = cbor_build_bytestring_owned(cnf.raw->data(), cnf.raw->size());
      addPair(std::move(key), std::move(val));
      return;
    }
    auto m = cbor_new_definite_map_owned(entries);
    if (cnf.jkt.has_value()) {
      // RFC 8747 §3.1 assigns label 3 to `kid`; §3.2 uses `jkt` under label
      // "jkt" in the confirmation JWK thumbprint form. We follow RFC 8747
      // and emit `jkt` as an integer label (3) with the SHA-256 bytes.
      auto lbl = CborItemPtr(cbor_build_uint64(3));
      auto val = cbor_build_bytestring_owned(cnf.jkt->data(), cnf.jkt->size());
      addPairToMap(m.get(), std::move(lbl), std::move(val));
    }
    if (cnf.kid.has_value()) {
      auto lbl = CborItemPtr(cbor_build_string("kid"));
      auto val = CborItemPtr(cbor_build_string(cnf.kid->c_str()));
      addPairToMap(m.get(), std::move(lbl), std::move(val));
    }
    addPair(std::move(key), std::move(m));
  }

  // CTA-5007-B `catdpop`: structured settings map (critical, lifetime, jti).
  void addClaimImpl(int64_t claim_id, const CatDpopSettings& d) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    // If we only have raw pass-through bytes, emit them directly as a byte
    // string (issuer opaque form).
    const bool has_typed = d.critical.has_value() ||
                           d.proof_lifetime_seconds.has_value() ||
                           d.jti_challenge.has_value();
    if (!has_typed && d.raw.has_value()) {
      auto val = cbor_build_bytestring_owned(d.raw->data(), d.raw->size());
      addPair(std::move(key), std::move(val));
      return;
    }
    size_t entries = 0;
    if (d.critical.has_value()) ++entries;
    if (d.proof_lifetime_seconds.has_value()) ++entries;
    if (d.jti_challenge.has_value()) ++entries;
    auto m = cbor_new_definite_map_owned(entries);
    // Labels are integer-keyed per the draft; use a small stable mapping
    // until the draft assigns final numbers: 1=critical, 2=lifetime, 3=jti.
    if (d.critical.has_value()) {
      auto lbl = CborItemPtr(cbor_build_uint64(1));
      auto arr = cbor_new_definite_array_owned(d.critical->size());
      for (int64_t v : *d.critical) {
        auto item = v >= 0 ? CborItemPtr(cbor_build_uint64(static_cast<uint64_t>(v)))
                           : CborItemPtr(cbor_build_negint64(
                                 static_cast<uint64_t>(-(v + 1))));
        if (!cbor_array_push(arr.get(), item.get())) {
          throw InvalidCborError("Failed to push catdpop critical entry");
        }
      }
      addPairToMap(m.get(), std::move(lbl), std::move(arr));
    }
    if (d.proof_lifetime_seconds.has_value()) {
      auto lbl = CborItemPtr(cbor_build_uint64(2));
      const int64_t v = *d.proof_lifetime_seconds;
      auto val = v >= 0 ? CborItemPtr(cbor_build_uint64(static_cast<uint64_t>(v)))
                        : CborItemPtr(cbor_build_negint64(
                              static_cast<uint64_t>(-(v + 1))));
      addPairToMap(m.get(), std::move(lbl), std::move(val));
    }
    if (d.jti_challenge.has_value()) {
      auto lbl = CborItemPtr(cbor_build_uint64(3));
      auto val = cbor_build_bytestring_owned(
          d.jti_challenge->data(), d.jti_challenge->size());
      addPairToMap(m.get(), std::move(lbl), std::move(val));
    }
    addPair(std::move(key), std::move(m));
  }

  // CTA-5007-B `catifdata`: string or array-of-strings.
  void addClaimImpl(int64_t claim_id, const CatIfData& v) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    if (v.isString()) {
      auto val = CborItemPtr(cbor_build_string(v.asString().c_str()));
      addPair(std::move(key), std::move(val));
      return;
    }
    const auto& arr_val = v.asArray();
    auto arr = cbor_new_definite_array_owned(arr_val.size());
    for (const auto& s : arr_val) {
      auto item = CborItemPtr(cbor_build_string(s.c_str()));
      if (!cbor_array_push(arr.get(), item.get())) {
        throw InvalidCborError("Failed to push catifdata entry");
      }
    }
    addPair(std::move(key), std::move(arr));
  }

  // `catif` / `catr` — opaque directive bytes today, until the draft
  // finalises typed accessors (tracked as future work).
  void addClaimImpl(int64_t claim_id, const CatRequestDirective& dir) {
    if (dir.empty()) return;
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    auto val = cbor_build_bytestring_owned(dir.raw.data(), dir.raw.size());
    addPair(std::move(key), std::move(val));
  }

  // `cti` (RFC 8392 §3.1.7): CBOR byte string. Also used for `cattpk`,
  // and any other typed byte string claim.
  void addClaimImpl(int64_t claim_id, const std::vector<uint8_t>& data) {
    auto key = CborItemPtr(cbor_build_uint64(claim_id));
    auto val = cbor_build_bytestring_owned(data.data(), data.size());
    addPair(std::move(key), std::move(val));
  }

  void addPair(CborItemPtr key, CborItemPtr value) {
    addPairToMap(root_.get(), std::move(key), std::move(value));
  }

  void addPairToMap(cbor_item_t* map, CborItemPtr key, CborItemPtr value) {
    struct cbor_pair pair = {key.get(), value.get()};
    if (!cbor_map_add(map, pair)) {
      throw InvalidCborError("Failed to add pair to CBOR map");
    }
    // cbor_map_add calls cbor_incref on both key and value.
    // Let CborItemPtr destructors balance the extra increfs.
  }
};

/**
 * @brief Compile-time claim processing
 */
template <typename TokenType>
class ClaimProcessor {
 public:
  static void processAllClaims(CborMapBuilder& builder,
                               const TokenType& token) {
    using namespace claim_validation;

    // Process core claims using ClaimIdentifier types
    builder.addClaim<IssuerClaim>(token.core.iss);
    builder.addClaim<AudienceClaim>(token.core.aud);
    builder.addClaim<ExpirationClaim>(token.core.exp);
    builder.addClaim<NotBeforeClaim>(token.core.nbf);
    builder.addClaim<CwtIdClaim>(token.core.cti);

    // Process informational claims
    builder.addClaim<SubjectClaim>(token.informational.sub);
    builder.addClaim<IssuedAtClaim>(token.informational.iat);
    builder.addClaim<CatInterfaceDataClaim>(token.informational.catifdata);

    // Process DPoP claims
    builder.addClaim<ConfirmationClaim>(token.dpop.cnf);
    builder.addClaim<CatDpopClaim>(token.dpop.catdpop);

    // Process CAT claims using ClaimIdentifier types
    builder.addClaim<CatReplayClaim>(token.cat.catreplay);
    builder.addClaim<CatProofClaim>(token.cat.catpor);
    builder.addClaim<CatVersionClaim>(token.cat.catv);
    builder.addClaim<CatUsageClaim>(token.cat.catu);
    builder.addClaim<CatNetworkInterfacesClaim>(token.cat.catnip);
    builder.addClaim<CatMethodsClaim>(token.cat.catm);
    builder.addClaim<CatAlpnClaim>(token.cat.catalpn);
    builder.addClaim<CatHostsClaim>(token.cat.cath);
    builder.addClaim<CatGeoIsoClaim>(token.cat.catgeoiso3166);
    builder.addClaim<CatGeoCoordClaim>(token.cat.catgeocoord);
    builder.addClaim<GeohashClaim>(token.cat.geohash);
    builder.addClaim<CatGeoAltitudeClaim>(token.cat.catgeoalt);
    builder.addClaim<CatTokenPublicKeyClaim>(token.cat.cattpk);
    builder.addClaim<CatInterfaceClaim>(token.request.catif);
    builder.addClaim<CatRequestClaim>(token.request.catr);

    // Process extended claims (MOQT)
    processExtendedClaims(builder, token.extended);

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

 private:
  static void processExtendedClaims(CborMapBuilder& builder,
                                    const ExtendedCatClaims& extended) {
    // Process MOQT claims if present
    if (extended.hasMoqtClaims()) {
      auto moqt_cbor =
          serializeMoqtClaimsToCbor(*extended.getMoqtClaimsReadOnly());
      addClaimRaw(builder, CLAIM_MOQT, moqt_cbor);
    }
  }

  static void addClaimRaw(CborMapBuilder& builder, int64_t claim_id,
                          const std::vector<uint8_t>& data) {
    if (!data.empty()) {
      auto key = CborItemPtr(cbor_build_uint64(claim_id));
      auto val = cbor_build_bytestring_owned(data.data(), data.size());

      builder.addPairToMap(builder.root_.get(), std::move(key), std::move(val));
    }
  }

  static CborItemPtr serializeBinaryMatch(const MoqtBinaryMatch& match) {
    if (match.is_empty()) {
      return nullptr;
    }
    if (match.match_type == BinaryMatchType::EXACT) {
      return cbor_build_bytestring_owned(match.pattern.data(),
                                         match.pattern.size());
    }
    auto arr = cbor_new_definite_array_owned(2);
    auto type_val =
        cbor_build_uint8_owned(static_cast<uint8_t>(match.match_type));
    if (!cbor_array_push(arr.get(), type_val.get())) {
      throw InvalidCborError("Failed to push match type");
    }

    auto bstr =
        cbor_build_bytestring_owned(match.pattern.data(), match.pattern.size());
    if (!cbor_array_push(arr.get(), bstr.get())) {
      throw InvalidCborError("Failed to push match pattern");
    }

    return arr;
  }

  static std::vector<uint8_t> serializeMoqtClaimsToCbor(
      const MoqtClaims& moqt_claims) {
    const auto& scopes = moqt_claims.getScopes();
    auto revalidation_interval = moqt_claims.getRevalidationInterval();

    auto moqt_array = CborItemPtr(cbor_new_definite_array(scopes.size()));
    if (!moqt_array) {
      throw InvalidCborError("Failed to create MOQT claims array");
    }

    for (const auto& scope : scopes) {
      size_t scope_len = 1;
      bool has_ns = !scope.namespace_match.is_empty();
      bool has_track = !scope.track_match.is_empty();
      if (has_ns || has_track) scope_len = 2;
      if (has_track) scope_len = 3;

      auto scope_array = CborItemPtr(cbor_new_definite_array(scope_len));

      auto actions_array =
          CborItemPtr(cbor_new_definite_array(scope.actions.size()));
      for (int action : scope.actions) {
        auto action_item =
            CborItemPtr(cbor_build_uint8(static_cast<uint8_t>(action)));
        (void)cbor_array_push(actions_array.get(), action_item.get());
      }
      (void)cbor_array_push(scope_array.get(), actions_array.get());

      if (scope_len >= 2) {
        const auto& ns_conditions = scope.namespace_match.conditions();
        auto ns_matches =
            CborItemPtr(cbor_new_definite_array(ns_conditions.size()));
        for (const auto& cond : ns_conditions) {
          auto ns_item = serializeBinaryMatch(cond);
          if (ns_item) {
            (void)cbor_array_push(ns_matches.get(), ns_item.get());
          } else {
            auto null_item = CborItemPtr(cbor_new_null());
            (void)cbor_array_push(ns_matches.get(), null_item.get());
          }
        }
        (void)cbor_array_push(scope_array.get(), ns_matches.get());
      }

      if (scope_len >= 3) {
        const auto& tr_conditions = scope.track_match.conditions();
        if (tr_conditions.size() == 1) {
          auto track_item = serializeBinaryMatch(tr_conditions[0]);
          if (track_item) {
            (void)cbor_array_push(scope_array.get(), track_item.get());
          } else {
            auto null_item = CborItemPtr(cbor_new_null());
            (void)cbor_array_push(scope_array.get(), null_item.get());
          }
        } else {
          auto tr_matches =
              CborItemPtr(cbor_new_definite_array(tr_conditions.size()));
          for (const auto& cond : tr_conditions) {
            auto tr_item = serializeBinaryMatch(cond);
            if (tr_item) {
              (void)cbor_array_push(tr_matches.get(), tr_item.get());
            } else {
              auto null_item = CborItemPtr(cbor_new_null());
              (void)cbor_array_push(tr_matches.get(), null_item.get());
            }
          }
          (void)cbor_array_push(scope_array.get(), tr_matches.get());
        }
      }

      (void)cbor_array_push(moqt_array.get(), scope_array.get());
    }

    std::vector<uint8_t> result;
    unsigned char* raw_buffer;
    size_t buffer_size;
    size_t length =
        cbor_serialize_alloc(moqt_array.get(), &raw_buffer, &buffer_size);
    if (length == 0) {
      throw InvalidCborError("Failed to serialize MOQT claims CBOR");
    }
    result.assign(raw_buffer, raw_buffer + length);
    free(raw_buffer);

    if (revalidation_interval.has_value()) {
      auto reval =
          CborItemPtr(cbor_build_uint64(revalidation_interval->count()));
      unsigned char* reval_buf;
      size_t reval_size;
      size_t reval_len =
          cbor_serialize_alloc(reval.get(), &reval_buf, &reval_size);
      if (reval_len > 0) {
        result.insert(result.end(), reval_buf, reval_buf + reval_len);
        free(reval_buf);
      }
    }

    return result;
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
      auto alg_val = buildAlgCborValue(algorithm.algorithmId());

      struct cbor_pair alg_pair = {alg_key.get(), alg_val.get()};
      if (!cbor_map_add(headerMap.get(), alg_pair)) {
        throw InvalidCborError("Failed to add algorithm to signature header");
      }

      unsigned char* raw_buffer;
      size_t buffer_size;
      size_t length =
          cbor_serialize_alloc(headerMap.get(), &raw_buffer, &buffer_size);
      if (length == 0) {
        throw InvalidCborError("Failed to serialize signature header");
      }

      auto buffer = CborBufferPtr(raw_buffer);
      sigHeader = std::vector<uint8_t>(buffer.get(), buffer.get() + length);
    }

    // Create COSE Sig_structure for COSE_Sign (multi-signature)
    // Use the specialized function for proper COSE_Sign structure
    auto signingInput =
        createCoseSignInput(bodyHeader, sigHeader, {}, payloadBytes);

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
  // Strict load enforces empty/oversize rejection, definite-length forms,
  // no duplicate keys, no unrecognized tags, no trailing bytes, and the
  // per-token size cap. This is the primary CAT payload parse entry
  // point so all downstream extraction runs on a canonical DOM.
  auto item = catapult::internal::loadStrict(
      std::span<const uint8_t>(cborData.data(), cborData.size()));

  if (!cbor_isa_map(item.get())) {
    throw InvalidTokenFormatError();
  }

  // Maximum string length to prevent memory exhaustion
  constexpr size_t MAX_STRING_LENGTH = 65536;  // 64KB

  // Helper lambda for extracting strings with length validation
  auto extract_string = [](cbor_item_t* str_item) -> std::string {
    if (!str_item) return {};
    size_t length = cbor_string_length(str_item);
    if (length > MAX_STRING_LENGTH) {
      throw InvalidClaimValueError("String value exceeds maximum length");
    }
    const unsigned char* data = cbor_string_handle(str_item);
    if (!data && length > 0) {
      throw InvalidClaimValueError("Invalid string data pointer");
    }
    return {reinterpret_cast<const char*>(data), length};
  };

  auto extract_bytestring = [](cbor_item_t* str_item) -> std::string {
    if (!str_item) return {};
    size_t length = cbor_bytestring_length(str_item);
    if (length > MAX_STRING_LENGTH) {
      throw InvalidClaimValueError("Bytestring value exceeds maximum length");
    }
    const unsigned char* data = cbor_bytestring_handle(str_item);
    if (!data && length > 0) {
      throw InvalidClaimValueError("Invalid bytestring data pointer");
    }
    return {reinterpret_cast<const char*>(data), length};
  };

  // Parse into CatToken
  CatToken token;
  struct cbor_pair* pairs = cbor_map_handle(item.get());
  size_t map_size = cbor_map_size(item.get());

  // Bounds check
  if (!pairs || map_size == 0) {
    return token;
  }

  // CTA-5007-B §4.5 / C-05 fix: a security parser MUST NOT silently repair
  // input. Any malformed claim (non-uint key, unexpected value type, out-of-
  // range integer, unknown/experimental claim id) causes the whole token to
  // be rejected. Widening the acceptance set is exactly the class of bug that
  // lets an attacker smuggle scope past authorization checks.
  for (size_t i = 0; i < map_size; i++) {
    cbor_item_t* key_item = pairs[i].key;
    cbor_item_t* value_item = pairs[i].value;

    if (!cbor_isa_uint(key_item)) {
      throw InvalidTokenFormatError();
    }

    uint64_t claim_id = cbor_get_int(key_item);

    switch (claim_id) {
      case CLAIM_ISS:
        if (!cbor_isa_string(value_item)) {
          throw InvalidClaimValueError("'iss' must be a text string");
        }
        token.core.iss = extract_string(value_item);
        break;

      case CLAIM_AUD:
        if (!cbor_isa_array(value_item)) {
          throw InvalidClaimValueError("'aud' must be an array");
        }
        {
          size_t array_size = cbor_array_size(value_item);
          // Limit audience array size to prevent memory exhaustion
          constexpr size_t MAX_AUDIENCE_COUNT = 100;
          if (array_size > MAX_AUDIENCE_COUNT) {
            throw InvalidClaimValueError("Too many audience values");
          }
          cbor_item_t** array_handle = cbor_array_handle(value_item);
          if (!array_handle && array_size > 0) {
            throw InvalidCborError("Invalid 'aud' array handle");
          }

          std::vector<std::string> audiences;
          audiences.reserve(array_size);
          for (size_t j = 0; j < array_size; j++) {
            if (!array_handle[j] || !cbor_isa_string(array_handle[j])) {
              throw InvalidClaimValueError(
                  "'aud' array entries must be text strings");
            }
            audiences.emplace_back(extract_string(array_handle[j]));
          }
          token.core.aud = std::move(audiences);
        }
        break;

      case CLAIM_EXP:
        if (!cbor_isa_uint(value_item)) {
          throw InvalidClaimValueError("'exp' must be an unsigned integer");
        }
        {
          uint64_t exp_val = cbor_get_int(value_item);
          if (exp_val >
              static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
            throw InvalidClaimValueError("'exp' exceeds int64 range");
          }
          token.core.exp = static_cast<int64_t>(exp_val);
        }
        break;

      case CLAIM_NBF:
        if (!cbor_isa_uint(value_item)) {
          throw InvalidClaimValueError("'nbf' must be an unsigned integer");
        }
        {
          uint64_t nbf_val = cbor_get_int(value_item);
          if (nbf_val >
              static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
            throw InvalidClaimValueError("'nbf' exceeds int64 range");
          }
          token.core.nbf = static_cast<int64_t>(nbf_val);
        }
        break;

      case CLAIM_CTI:
        // RFC 8392 §3.1.7: `cti` is a CBOR byte string. Reject the older
        // text-string form; that shape was never spec-compliant and only
        // survived because early producers used std::string internally.
        if (!cbor_isa_bytestring(value_item)) {
          throw InvalidClaimValueError("'cti' must be a byte string");
        }
        {
          size_t len = cbor_bytestring_length(value_item);
          if (len > MAX_STRING_LENGTH) {
            throw InvalidClaimValueError("'cti' exceeds maximum length");
          }
          const unsigned char* data = cbor_bytestring_handle(value_item);
          if (!data && len > 0) {
            throw InvalidClaimValueError("Invalid 'cti' data pointer");
          }
          token.core.cti = std::vector<uint8_t>(data, data + len);
        }
        break;

      case CLAIM_CATREPLAY:
        if (!cbor_isa_uint(value_item)) {
          throw InvalidClaimValueError(
              "'catreplay' must be an unsigned integer mode");
        }
        {
          uint64_t mode = cbor_get_int(value_item);
          if (mode > std::numeric_limits<uint32_t>::max()) {
            throw InvalidClaimValueError("'catreplay' mode exceeds uint32");
          }
          // Reject unknown modes explicitly — the CTA-5007-B enum is closed;
          // any future mode is a new authorization semantics we can't apply.
          switch (mode) {
            case 0:
            case 1:
            case 2:
              token.cat.catreplay = static_cast<CatReplayMode>(mode);
              break;
            default:
              throw InvalidClaimValueError("Unknown 'catreplay' mode");
          }
        }
        break;

      case CLAIM_CATPOR:
        // CTA-5007-B `catpor`: array [probability, identifier, ?expiry].
        if (!cbor_isa_array(value_item)) {
          throw InvalidClaimValueError("'catpor' must be an array");
        }
        {
          size_t n = cbor_array_size(value_item);
          if (n < 2 || n > 3) {
            throw InvalidClaimValueError(
                "'catpor' array must have 2 or 3 elements");
          }
          cbor_item_t** arr = cbor_array_handle(value_item);
          if (!arr) {
            throw InvalidCborError("Invalid 'catpor' array handle");
          }
          CatProofOfPossession por;
          if (!cbor_isa_float_ctrl(arr[0]) || cbor_float_ctrl_is_ctrl(arr[0])) {
            throw InvalidClaimValueError(
                "'catpor' probability must be a float");
          }
          por.probability = cbor_float_get_float(arr[0]);
          if (!cbor_isa_bytestring(arr[1])) {
            throw InvalidClaimValueError(
                "'catpor' identifier must be a byte string");
          }
          {
            size_t idlen = cbor_bytestring_length(arr[1]);
            const unsigned char* iddata = cbor_bytestring_handle(arr[1]);
            por.identifier.assign(iddata, iddata + idlen);
          }
          if (n == 3) {
            if (!cbor_isa_uint(arr[2])) {
              throw InvalidClaimValueError(
                  "'catpor' expiry must be an unsigned integer");
            }
            uint64_t e = cbor_get_int(arr[2]);
            if (e > static_cast<uint64_t>(
                       std::numeric_limits<int64_t>::max())) {
              throw InvalidClaimValueError("'catpor' expiry exceeds int64");
            }
            por.expiry = static_cast<int64_t>(e);
          }
          if (!por.is_valid()) {
            throw InvalidClaimValueError(
                "'catpor' probability out of [0,1] or empty identifier");
          }
          token.cat.catpor = std::move(por);
        }
        break;

      case CLAIM_CATV:
        if (!cbor_isa_uint(value_item)) {
          throw InvalidClaimValueError("'catv' must be an unsigned integer");
        }
        {
          uint64_t v = cbor_get_int(value_item);
          if (v > std::numeric_limits<uint32_t>::max()) {
            throw InvalidClaimValueError("'catv' exceeds uint32 range");
          }
          token.cat.catv = static_cast<uint32_t>(v);
        }
        break;

      case CLAIM_CATU:
        // CTA-5007-B `catu`: map from component label (int) to [type, value].
        if (!cbor_isa_map(value_item)) {
          throw InvalidClaimValueError("'catu' must be a CBOR map");
        }
        {
          CatUriMatchMap catu;
          struct cbor_pair* u_pairs = cbor_map_handle(value_item);
          size_t u_size = cbor_map_size(value_item);
          if (!u_pairs && u_size > 0) {
            throw InvalidCborError("Invalid 'catu' map handle");
          }
          for (size_t k = 0; k < u_size; ++k) {
            cbor_item_t* lbl = u_pairs[k].key;
            cbor_item_t* entry = u_pairs[k].value;
            int64_t label = 0;
            if (cbor_isa_uint(lbl)) {
              uint64_t raw = cbor_get_int(lbl);
              if (raw > static_cast<uint64_t>(
                            std::numeric_limits<int64_t>::max())) {
                throw InvalidClaimValueError(
                    "'catu' component label exceeds int64 range");
              }
              label = static_cast<int64_t>(raw);
            } else if (cbor_isa_negint(lbl)) {
              uint64_t mag = cbor_get_int(lbl);
              if (mag > static_cast<uint64_t>(
                            std::numeric_limits<int64_t>::max())) {
                throw InvalidClaimValueError(
                    "'catu' negative label exceeds int64 range");
              }
              label = -static_cast<int64_t>(mag) - 1;
            } else {
              throw InvalidClaimValueError(
                  "'catu' component label must be an integer");
            }
            if (!cbor_isa_array(entry) || cbor_array_size(entry) != 2) {
              throw InvalidClaimValueError(
                  "'catu' entry must be a 2-tuple [type, value]");
            }
            cbor_item_t** tup = cbor_array_handle(entry);
            if (!cbor_isa_uint(tup[0])) {
              throw InvalidClaimValueError(
                  "'catu' entry type must be an unsigned integer");
            }
            uint64_t type_u = cbor_get_int(tup[0]);
            if (type_u > 6) {
              throw InvalidClaimValueError("'catu' unknown match type");
            }
            if (!cbor_isa_bytestring(tup[1])) {
              throw InvalidClaimValueError(
                  "'catu' entry value must be a byte string");
            }
            UriComponentMatch match;
            match.type = static_cast<UriMatchType>(type_u);
            size_t vlen = cbor_bytestring_length(tup[1]);
            const unsigned char* vdata = cbor_bytestring_handle(tup[1]);
            match.value.assign(vdata, vdata + vlen);
            catu.components.emplace(label, std::move(match));
          }
          token.cat.catu = std::move(catu);
        }
        break;

      case CLAIM_CATM:
        if (!cbor_isa_array(value_item)) {
          throw InvalidClaimValueError("'catm' must be an array");
        }
        {
          size_t n = cbor_array_size(value_item);
          constexpr size_t MAX_METHODS = 32;
          if (n > MAX_METHODS) {
            throw InvalidClaimValueError("Too many 'catm' entries");
          }
          cbor_item_t** arr = cbor_array_handle(value_item);
          std::vector<std::string> methods;
          methods.reserve(n);
          for (size_t j = 0; j < n; ++j) {
            if (!cbor_isa_string(arr[j])) {
              throw InvalidClaimValueError(
                  "'catm' entries must be text strings");
            }
            methods.emplace_back(extract_string(arr[j]));
          }
          token.cat.catm = std::move(methods);
        }
        break;

      case CLAIM_CATALPN:
        if (!cbor_isa_array(value_item)) {
          throw InvalidClaimValueError("'catalpn' must be an array");
        }
        {
          size_t n = cbor_array_size(value_item);
          constexpr size_t MAX_ALPN = 32;
          if (n > MAX_ALPN) {
            throw InvalidClaimValueError("Too many 'catalpn' entries");
          }
          cbor_item_t** arr = cbor_array_handle(value_item);
          std::vector<std::vector<uint8_t>> alpn;
          alpn.reserve(n);
          for (size_t j = 0; j < n; ++j) {
            if (!cbor_isa_bytestring(arr[j])) {
              throw InvalidClaimValueError(
                  "'catalpn' entries must be byte strings");
            }
            size_t alen = cbor_bytestring_length(arr[j]);
            const unsigned char* adata = cbor_bytestring_handle(arr[j]);
            alpn.emplace_back(adata, adata + alen);
          }
          token.cat.catalpn = std::move(alpn);
        }
        break;

      case CLAIM_CATH:
        if (!cbor_isa_array(value_item)) {
          throw InvalidClaimValueError("'cath' must be an array");
        }
        {
          size_t n = cbor_array_size(value_item);
          constexpr size_t MAX_HDRS = 32;
          if (n > MAX_HDRS) {
            throw InvalidClaimValueError("Too many 'cath' entries");
          }
          cbor_item_t** arr = cbor_array_handle(value_item);
          CatHostHeaderMatchList cath;
          cath.entries.reserve(n);
          for (size_t j = 0; j < n; ++j) {
            if (!cbor_isa_array(arr[j]) || cbor_array_size(arr[j]) != 2) {
              throw InvalidClaimValueError(
                  "'cath' entry must be [name, [type, value]]");
            }
            cbor_item_t** pair = cbor_array_handle(arr[j]);
            if (!cbor_isa_string(pair[0])) {
              throw InvalidClaimValueError(
                  "'cath' header name must be a text string");
            }
            if (!cbor_isa_array(pair[1]) || cbor_array_size(pair[1]) != 2) {
              throw InvalidClaimValueError(
                  "'cath' match must be [type, value]");
            }
            cbor_item_t** m = cbor_array_handle(pair[1]);
            if (!cbor_isa_uint(m[0])) {
              throw InvalidClaimValueError(
                  "'cath' match type must be uint");
            }
            uint64_t type_u = cbor_get_int(m[0]);
            if (type_u > 6) {
              throw InvalidClaimValueError("'cath' unknown match type");
            }
            if (!cbor_isa_bytestring(m[1])) {
              throw InvalidClaimValueError(
                  "'cath' match value must be a byte string");
            }
            CatHeaderMatch hm;
            hm.name = extract_string(pair[0]);
            hm.match.type = static_cast<UriMatchType>(type_u);
            size_t mvlen = cbor_bytestring_length(m[1]);
            const unsigned char* mvdata = cbor_bytestring_handle(m[1]);
            hm.match.value.assign(mvdata, mvdata + mvlen);
            cath.entries.push_back(std::move(hm));
          }
          token.cat.cath = std::move(cath);
        }
        break;

      case CLAIM_CATNIP:
        if (!cbor_isa_array(value_item)) {
          throw InvalidClaimValueError("'catnip' must be an array");
        }
        {
          size_t n = cbor_array_size(value_item);
          constexpr size_t MAX_NIPS = 32;
          if (n > MAX_NIPS) {
            throw InvalidClaimValueError("Too many 'catnip' entries");
          }
          cbor_item_t** arr = cbor_array_handle(value_item);
          std::vector<CatNipEntry> nips;
          nips.reserve(n);
          for (size_t j = 0; j < n; ++j) {
            if (!cbor_isa_tag(arr[j])) {
              throw InvalidClaimValueError(
                  "'catnip' entry must be a tagged byte string");
            }
            CatNipEntry e;
            e.tag = cbor_tag_value(arr[j]);
            cbor_item_t* tagged = cbor_tag_item(arr[j]);
            if (!tagged || !cbor_isa_bytestring(tagged)) {
              cbor_decref(&tagged);
              throw InvalidClaimValueError(
                  "'catnip' tagged item must be a byte string");
            }
            size_t elen = cbor_bytestring_length(tagged);
            const unsigned char* edata = cbor_bytestring_handle(tagged);
            e.value.assign(edata, edata + elen);
            cbor_decref(&tagged);
            nips.push_back(std::move(e));
          }
          token.cat.catnip = std::move(nips);
        }
        break;

      case CLAIM_CATGEOISO3166:
        if (!cbor_isa_array(value_item)) {
          throw InvalidClaimValueError("'catgeoiso3166' must be an array");
        }
        {
          size_t n = cbor_array_size(value_item);
          constexpr size_t MAX_ISO = 250;
          if (n > MAX_ISO) {
            throw InvalidClaimValueError("Too many 'catgeoiso3166' entries");
          }
          cbor_item_t** arr = cbor_array_handle(value_item);
          std::vector<std::string> codes;
          codes.reserve(n);
          for (size_t j = 0; j < n; ++j) {
            if (!cbor_isa_string(arr[j])) {
              throw InvalidClaimValueError(
                  "'catgeoiso3166' entries must be text strings");
            }
            codes.emplace_back(extract_string(arr[j]));
          }
          token.cat.catgeoiso3166 = std::move(codes);
        }
        break;

      case CLAIM_CATGEOCOORD:
        // CTA-5007-B §4.6.x: CBOR array `[latitude, longitude, radius?]`.
        if (!cbor_isa_array(value_item)) {
          throw InvalidClaimValueError("'catgeocoord' must be an array");
        }
        {
          size_t n = cbor_array_size(value_item);
          if (n < 2 || n > 3) {
            throw InvalidClaimValueError(
                "'catgeocoord' must have 2 or 3 elements");
          }
          cbor_item_t** arr = cbor_array_handle(value_item);
          auto read_float = [](cbor_item_t* it) -> double {
            if (!cbor_isa_float_ctrl(it) || cbor_float_ctrl_is_ctrl(it)) {
              throw InvalidClaimValueError(
                  "'catgeocoord' element must be a float");
            }
            return cbor_float_get_float(it);
          };
          double lat = read_float(arr[0]);
          double lon = read_float(arr[1]);
          std::optional<double> radius;
          if (n == 3) radius = read_float(arr[2]);
          auto coord = GeoCoordinate::createSafe(lat, lon, radius);
          if (!coord.has_value()) {
            throw InvalidClaimValueError("'catgeocoord' out of range");
          }
          token.cat.catgeocoord = *coord;
        }
        break;

      case CLAIM_GEOHASH:
        // CTA-5007-B `geohash`: text string OR CBOR array of strings.
        if (cbor_isa_string(value_item)) {
          token.cat.geohash = GeohashClaimValue(extract_string(value_item));
        } else if (cbor_isa_array(value_item)) {
          size_t n = cbor_array_size(value_item);
          constexpr size_t MAX_GEOHASH = 32;
          if (n > MAX_GEOHASH) {
            throw InvalidClaimValueError("Too many 'geohash' entries");
          }
          cbor_item_t** arr = cbor_array_handle(value_item);
          std::vector<std::string> hashes;
          hashes.reserve(n);
          for (size_t j = 0; j < n; ++j) {
            if (!cbor_isa_string(arr[j])) {
              throw InvalidClaimValueError(
                  "'geohash' array entries must be text strings");
            }
            hashes.emplace_back(extract_string(arr[j]));
          }
          token.cat.geohash = GeohashClaimValue(std::move(hashes));
        } else {
          throw InvalidClaimValueError(
              "'geohash' must be a text string or array of strings");
        }
        break;

      case CLAIM_CATGEOALT:
        if (!cbor_isa_array(value_item)) {
          throw InvalidClaimValueError("'catgeoalt' must be an array");
        }
        {
          size_t n = cbor_array_size(value_item);
          if (n < 1 || n > 2) {
            throw InvalidClaimValueError(
                "'catgeoalt' must have 1 or 2 elements");
          }
          cbor_item_t** arr = cbor_array_handle(value_item);
          auto read_int32 = [](cbor_item_t* it) -> int32_t {
            if (cbor_isa_uint(it)) {
              uint64_t v = cbor_get_int(it);
              if (v > static_cast<uint64_t>(
                          std::numeric_limits<int32_t>::max())) {
                throw InvalidClaimValueError(
                    "'catgeoalt' int exceeds int32 range");
              }
              return static_cast<int32_t>(v);
            }
            if (cbor_isa_negint(it)) {
              uint64_t mag = cbor_get_int(it);
              if (mag > static_cast<uint64_t>(
                            std::numeric_limits<int32_t>::max())) {
                throw InvalidClaimValueError(
                    "'catgeoalt' negint exceeds int32 range");
              }
              return -static_cast<int32_t>(mag) - 1;
            }
            throw InvalidClaimValueError(
                "'catgeoalt' element must be an integer");
          };
          GeoAltitude alt;
          alt.altitude = read_int32(arr[0]);
          if (n == 2) {
            alt.deviation = read_int32(arr[1]);
          }
          token.cat.catgeoalt = alt;
        }
        break;

      case CLAIM_CATTPK:
        if (!cbor_isa_bytestring(value_item)) {
          throw InvalidClaimValueError("'cattpk' must be a byte string");
        }
        {
          size_t len = cbor_bytestring_length(value_item);
          if (len > MAX_STRING_LENGTH) {
            throw InvalidClaimValueError("'cattpk' exceeds maximum length");
          }
          const unsigned char* data = cbor_bytestring_handle(value_item);
          token.cat.cattpk = std::vector<uint8_t>(data, data + len);
        }
        break;

      case CLAIM_SUB:
        if (!cbor_isa_string(value_item)) {
          throw InvalidClaimValueError("'sub' must be a text string");
        }
        token.informational.sub = extract_string(value_item);
        break;

      case CLAIM_IAT:
        if (!cbor_isa_uint(value_item)) {
          throw InvalidClaimValueError("'iat' must be an unsigned integer");
        }
        token.informational.iat = cbor_get_int(value_item);
        break;

      case CLAIM_CATIFDATA:
        if (cbor_isa_string(value_item)) {
          token.informational.catifdata =
              CatIfData(extract_string(value_item));
        } else if (cbor_isa_array(value_item)) {
          size_t n = cbor_array_size(value_item);
          constexpr size_t MAX_IFDATA = 32;
          if (n > MAX_IFDATA) {
            throw InvalidClaimValueError("Too many 'catifdata' entries");
          }
          cbor_item_t** arr = cbor_array_handle(value_item);
          std::vector<std::string> vals;
          vals.reserve(n);
          for (size_t j = 0; j < n; ++j) {
            if (!cbor_isa_string(arr[j])) {
              throw InvalidClaimValueError(
                  "'catifdata' array entries must be text strings");
            }
            vals.emplace_back(extract_string(arr[j]));
          }
          token.informational.catifdata = CatIfData(std::move(vals));
        } else {
          throw InvalidClaimValueError(
              "'catifdata' must be a text string or array of strings");
        }
        break;

      case CLAIM_CNF:
        // RFC 8747 §3.1: `cnf` is a CBOR map. Legacy producers that emitted
        // a bare text string (JWK thumbprint) are rejected here — the
        // typed model no longer conflates the two, and silently accepting
        // the string form would let a malformed issuer bypass jkt binding.
        if (!cbor_isa_map(value_item)) {
          throw InvalidClaimValueError("'cnf' must be a CBOR map");
        }
        {
          CatConfirmation cnf;
          struct cbor_pair* cnf_pairs = cbor_map_handle(value_item);
          size_t cnf_size = cbor_map_size(value_item);
          for (size_t k = 0; k < cnf_size; ++k) {
            cbor_item_t* lbl = cnf_pairs[k].key;
            cbor_item_t* val = cnf_pairs[k].value;
            // Integer label 3 is `jkt` (RFC 8747 §3.2).
            if (cbor_isa_uint(lbl) && cbor_get_int(lbl) == 3) {
              if (!cbor_isa_bytestring(val)) {
                throw InvalidClaimValueError(
                    "'cnf' jkt must be a byte string");
              }
              size_t l = cbor_bytestring_length(val);
              const unsigned char* d = cbor_bytestring_handle(val);
              cnf.jkt = std::vector<uint8_t>(d, d + l);
            } else if (cbor_isa_string(lbl)) {
              std::string key = extract_string(lbl);
              if (key == "kid" && cbor_isa_string(val)) {
                cnf.kid = extract_string(val);
              }
              // Unknown text labels: ignore — the typed model preserves
              // strict handling for jkt/kid; other forms round-trip via
              // future [[cnf-jwk-decoding]].
            }
          }
          token.dpop.cnf = std::move(cnf);
        }
        break;

      case CLAIM_CATDPOP:
        // CTA-5007-B `catdpop`: CBOR map with labeled fields.
        if (!cbor_isa_map(value_item)) {
          throw InvalidClaimValueError("'catdpop' must be a CBOR map");
        }
        {
          CatDpopSettings settings;
          struct cbor_pair* dp_pairs = cbor_map_handle(value_item);
          size_t dp_size = cbor_map_size(value_item);
          for (size_t k = 0; k < dp_size; ++k) {
            cbor_item_t* lbl = dp_pairs[k].key;
            cbor_item_t* val = dp_pairs[k].value;
            if (!cbor_isa_uint(lbl)) continue;
            uint64_t label = cbor_get_int(lbl);
            switch (label) {
              case 1:  // critical
                if (cbor_isa_array(val)) {
                  size_t cn = cbor_array_size(val);
                  cbor_item_t** carr = cbor_array_handle(val);
                  std::vector<int64_t> crit;
                  crit.reserve(cn);
                  for (size_t j = 0; j < cn; ++j) {
                    if (cbor_isa_uint(carr[j])) {
                      crit.push_back(
                          static_cast<int64_t>(cbor_get_int(carr[j])));
                    } else if (cbor_isa_negint(carr[j])) {
                      uint64_t mag = cbor_get_int(carr[j]);
                      crit.push_back(-static_cast<int64_t>(mag) - 1);
                    } else {
                      throw InvalidClaimValueError(
                          "'catdpop' critical entries must be integers");
                    }
                  }
                  settings.critical = std::move(crit);
                }
                break;
              case 2:  // proof_lifetime_seconds
                if (cbor_isa_uint(val)) {
                  settings.proof_lifetime_seconds =
                      static_cast<int64_t>(cbor_get_int(val));
                }
                break;
              case 3:  // jti_challenge (byte string)
                if (cbor_isa_bytestring(val)) {
                  size_t l = cbor_bytestring_length(val);
                  const unsigned char* d = cbor_bytestring_handle(val);
                  settings.jti_challenge =
                      std::vector<uint8_t>(d, d + l);
                }
                break;
              default:
                // Ignore unknown labels — they carry no authorization value.
                break;
            }
          }
          token.dpop.catdpop = std::move(settings);
        }
        break;

      case CLAIM_CATIF:
      case CLAIM_CATR:
        // `catif`/`catr` — until the draft finalises typed fields, preserve
        // the wire bytes so downstream inspectors can look at them.
        if (!cbor_isa_map(value_item) && !cbor_isa_bytestring(value_item)) {
          throw InvalidClaimValueError(
              "'catif'/'catr' must be a CBOR map or byte string");
        }
        {
          unsigned char* buf = nullptr;
          size_t buf_size = 0;
          size_t len = cbor_serialize_alloc(value_item, &buf, &buf_size);
          if (len == 0) {
            if (buf) free(buf);
            throw InvalidCborError("Failed to serialize catif/catr");
          }
          CatRequestDirective dir;
          dir.raw.assign(buf, buf + len);
          free(buf);
          if (claim_id == CLAIM_CATIF) {
            token.request.catif = std::move(dir);
          } else {
            token.request.catr = std::move(dir);
          }
        }
        break;

      case CLAIM_MOQT:
        if (!cbor_isa_bytestring(value_item)) {
          throw InvalidClaimValueError("'moqt' must be a byte string");
        }
        {
          auto moqt_data = extract_bytestring(value_item);
          cbor_load_result moqt_result;
          auto moqt_array = cbor_load_owned(
              reinterpret_cast<const uint8_t*>(moqt_data.data()),
              moqt_data.size(), moqt_result);
          if (!moqt_array || moqt_result.error.code != CBOR_ERR_NONE ||
              !cbor_isa_array(moqt_array.get())) {
            throw InvalidClaimValueError(
                "'moqt' payload must decode to a CBOR array");
          }

          constexpr size_t MAX_MOQT_SCOPES = 100;
          size_t moqt_scope_count = cbor_array_size(moqt_array.get());
          if (moqt_scope_count > MAX_MOQT_SCOPES) {
            throw InvalidClaimValueError("Too many MOQT scopes");
          }
          auto moqt_claims = MoqtClaims::create(moqt_scope_count);
          for (size_t si = 0; si < moqt_scope_count; ++si) {
            auto scope_arr = cbor_array_get_owned(moqt_array.get(), si);
            if (!scope_arr || !cbor_isa_array(scope_arr.get())) {
              throw InvalidClaimValueError("MOQT scope must be an array");
            }
            size_t scope_len = cbor_array_size(scope_arr.get());
            if (scope_len < 1) {
              throw InvalidClaimValueError(
                  "MOQT scope missing action list");
            }

            std::vector<int> actions;
            auto actions_arr = cbor_array_get_owned(scope_arr.get(), 0);
            if (!actions_arr || !cbor_isa_array(actions_arr.get())) {
              throw InvalidClaimValueError(
                  "MOQT scope action list must be an array");
            }
            constexpr size_t MAX_ACTIONS = 50;
            size_t action_count = cbor_array_size(actions_arr.get());
            if (action_count > MAX_ACTIONS) {
              throw InvalidClaimValueError(
                  "MOQT scope has too many actions");
            }
            for (size_t ai = 0; ai < action_count; ++ai) {
              auto act = cbor_array_get_owned(actions_arr.get(), ai);
              if (!act || !cbor_isa_uint(act.get())) {
                throw InvalidClaimValueError(
                    "MOQT action must be an unsigned integer");
              }
              uint64_t action_u64 = cbor_get_int(act.get());
              if (action_u64 > static_cast<uint64_t>(
                                   std::numeric_limits<int>::max())) {
                throw InvalidClaimValueError(
                    "MOQT action exceeds int range");
              }
              int action_val = static_cast<int>(action_u64);
              if (!moqt_actions::is_valid_action(action_val)) {
                throw InvalidClaimValueError(
                    "MOQT action id is not recognized");
              }
              actions.push_back(action_val);
            }

            auto parse_bin_match = [](cbor_item_t* item) -> MoqtBinaryMatch {
              if (!item || cbor_is_null(item)) return MoqtBinaryMatch::any();
              if (cbor_isa_bytestring(item)) {
                std::string_view sv(reinterpret_cast<const char*>(
                                        cbor_bytestring_handle(item)),
                                    cbor_bytestring_length(item));
                return MoqtBinaryMatch::exact(sv);
              }
              if (cbor_isa_array(item) && cbor_array_size(item) == 2) {
                auto type_item = cbor_array_get_owned(item, 0);
                auto val_item = cbor_array_get_owned(item, 1);
                if (!type_item || !cbor_isa_uint(type_item.get()) ||
                    !val_item || !cbor_isa_bytestring(val_item.get())) {
                  throw InvalidClaimValueError(
                      "MOQT match tuple must be (uint, bytestring)");
                }
                int type = static_cast<int>(cbor_get_int(type_item.get()));
                std::string_view sv(
                    reinterpret_cast<const char*>(
                        cbor_bytestring_handle(val_item.get())),
                    cbor_bytestring_length(val_item.get()));
                switch (type) {
                  case 1:
                    return MoqtBinaryMatch::prefix(sv);
                  case 2:
                    return MoqtBinaryMatch::suffix(sv);
                  case 3:
                    return MoqtBinaryMatch::contains(sv);
                  case 0:
                    return MoqtBinaryMatch::exact(sv);
                  default:
                    throw InvalidClaimValueError(
                        "MOQT match tuple has unknown type");
                }
              }
              throw InvalidClaimValueError(
                  "MOQT match element must be a bytestring, null, or (uint, "
                  "bytestring) tuple");
            };

            MoqtCompoundMatch ns_match = MoqtCompoundMatch::any();
            MoqtCompoundMatch track_match = MoqtCompoundMatch::any();

            if (scope_len >= 2) {
              auto ns_arr = cbor_array_get_owned(scope_arr.get(), 1);
              if (!ns_arr || !cbor_isa_array(ns_arr.get())) {
                throw InvalidClaimValueError(
                    "MOQT scope namespace element must be an array");
              }
              size_t ns_count = cbor_array_size(ns_arr.get());
              if (ns_count > 0) {
                std::vector<MoqtBinaryMatch> ns_conditions;
                for (size_t ni = 0; ni < ns_count; ++ni) {
                  auto ns_elem = cbor_array_get_owned(ns_arr.get(), ni);
                  auto m = parse_bin_match(ns_elem.get());
                  if (!m.is_empty()) {
                    ns_conditions.push_back(std::move(m));
                  }
                }
                ns_match = MoqtCompoundMatch::all(std::move(ns_conditions));
              }
            }
            if (scope_len >= 3) {
              auto track_item = cbor_array_get_owned(scope_arr.get(), 2);
              if (track_item && cbor_isa_array(track_item.get()) &&
                  cbor_array_size(track_item.get()) > 0) {
                auto first = cbor_array_get_owned(track_item.get(), 0);
                if (first && cbor_isa_array(first.get())) {
                  std::vector<MoqtBinaryMatch> tr_conditions;
                  for (size_t ti = 0; ti < cbor_array_size(track_item.get());
                       ++ti) {
                    auto tr_elem = cbor_array_get_owned(track_item.get(), ti);
                    auto m = parse_bin_match(tr_elem.get());
                    if (!m.is_empty()) {
                      tr_conditions.push_back(std::move(m));
                    }
                  }
                  track_match =
                      MoqtCompoundMatch::all(std::move(tr_conditions));
                } else {
                  auto m = parse_bin_match(track_item.get());
                  if (!m.is_empty()) {
                    track_match = MoqtCompoundMatch::single(std::move(m));
                  }
                }
              } else if (track_item &&
                         cbor_isa_bytestring(track_item.get())) {
                auto m = parse_bin_match(track_item.get());
                if (!m.is_empty()) {
                  track_match = MoqtCompoundMatch::single(std::move(m));
                }
              } else if (track_item && !cbor_is_null(track_item.get())) {
                throw InvalidClaimValueError(
                    "MOQT scope track element must be null, bytestring, or "
                    "array");
              }
            }

            if (actions.empty()) {
              throw InvalidClaimValueError(
                  "MOQT scope must contain at least one action");
            }
            moqt_claims.addScope(actions, std::move(ns_match),
                                 std::move(track_match));
          }
          token.extended.setMoqtClaims(std::move(moqt_claims));
        }
        break;

      default:
        // Unknown / unregistered claim ids are ignored (CTA-5007-B §4.5 —
        // "unrecognized claims MUST NOT be processed"). This is *not* silent
        // repair: unknown ids simply don't grant any authorization by
        // themselves. Known-claim malformation is still rejected above. When
        // typed representations land (task #13), add the registered CAT
        // claims (CATNIP, CATM, CATALPN, CATH, CATGEOISO3166, CATIF, CATR)
        // to this switch so their type is checked strictly.
        CAT_LOG_DEBUG("Ignoring unregistered CAT claim id: {}", claim_id);
        break;
    }
  }

  return token;
}

std::vector<uint8_t> Cwt::createCoseHeader() const {
  try {
    // Create COSE header map manually
    size_t header_fields = 1;  // alg is required
    if (header.kid.has_value()) header_fields++;
    if (header.typ.has_value()) header_fields++;

    auto headerMap = CborItemPtr(cbor_new_definite_map(header_fields));

    // Add algorithm (label 1, required)
    auto alg_key = CborItemPtr(cbor_build_uint8(1));
    auto alg_val = buildAlgCborValue(header.alg);

    struct cbor_pair alg_pair = {alg_key.get(), alg_val.get()};
    if (!cbor_map_add(headerMap.get(), alg_pair)) {
      throw InvalidCborError("Failed to add algorithm to COSE header");
    }

    // Add key ID if present (label 4)
    if (header.kid.has_value()) {
      auto kid_key = CborItemPtr(cbor_build_uint8(4));
      auto kid_val = CborItemPtr(cbor_build_string(header.kid->c_str()));

      struct cbor_pair kid_pair = {kid_key.get(), kid_val.get()};
      if (!cbor_map_add(headerMap.get(), kid_pair)) {
        throw InvalidCborError("Failed to add key ID to COSE header");
      }
    }

    // Add content type if present (label 16)
    if (header.typ.has_value()) {
      auto typ_key = CborItemPtr(cbor_build_uint8(16));
      auto typ_val = CborItemPtr(cbor_build_string(header.typ->c_str()));

      struct cbor_pair typ_pair = {typ_key.get(), typ_val.get()};
      if (!cbor_map_add(headerMap.get(), typ_pair)) {
        throw InvalidCborError("Failed to add content type to COSE header");
      }
    }

    // Serialize to buffer
    unsigned char* raw_buffer;
    size_t buffer_size;
    size_t length =
        cbor_serialize_alloc(headerMap.get(), &raw_buffer, &buffer_size);

    if (length == 0) {
      CAT_LOG_ERROR("COSE header serialization failed");
      throw InvalidCborError("Failed to serialize COSE header");
    }

    auto buffer = CborBufferPtr(raw_buffer);
    return std::vector<uint8_t>(buffer.get(), buffer.get() + length);

  } catch (const std::exception& e) {
    throw InvalidCborError(std::string("COSE header creation failed: ") +
                           e.what());
  }
}

std::vector<uint8_t> Cwt::createCwt(
    CwtMode mode, const CryptographicAlgorithm& algorithm) const {
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
      case CwtMode::Signed: {
        // Use COSE_Sign1 Sig_structure (RFC 8152 §4.4).
        auto signingInput = createCoseSign1Input(coseHeader, payload);
        signature = algorithm.sign(signingInput);
        break;
      }
      case CwtMode::MACed: {
        // Use COSE_Mac0 MAC_structure (RFC 8152 §6.3). Previously this path
        // reused the "Signature1" context, which is non-conformant and
        // opens the door to cross-context tag confusion.
        auto macInput = createCoseMac0Input(coseHeader, payload);
        signature = algorithm.sign(macInput);
        break;
      }
      case CwtMode::MultiSigned:
        // For COSE_Sign, signatures should already be added via addSignature()
        if (signatures.empty()) {
          throw CryptoError(
              "No signatures available for COSE_Sign mode. Use addSignature() "
              "first.");
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

        {
          // Bind the protected header to the ciphertext via the Enc_structure
          // AAD (RFC 8152 §5.3). Without this, an attacker can substitute the
          // alg/kid in the protected header without invalidating the tag.
          auto encAad = createCoseEncrypt0Aad(coseHeader);
          encryptedPayload = algorithm.encrypt(payload, iv, encAad);
        }
        break;
    }

    // Step 5: Create COSE structure based on mode
    CborItemPtr coseStructure;

    if (mode == CwtMode::MultiSigned) {
      // For COSE_Sign: [protected_header, unprotected_header, payload,
      // signatures_array]
      coseStructure = CborItemPtr(cbor_new_definite_array(4));

      // Add protected header (encoded as bstr)
      auto protectedHeader = CborItemPtr(
          cbor_build_bytestring(coseHeader.data(), coseHeader.size()));
      if (!cbor_array_push(coseStructure.get(), protectedHeader.get())) {
        throw InvalidCborError(
            "Failed to add protected header to COSE_Sign structure");
      }

      // Add empty unprotected header (map)
      auto unprotectedHeader = CborItemPtr(cbor_new_definite_map(0));
      if (!cbor_array_push(coseStructure.get(), unprotectedHeader.get())) {
        throw InvalidCborError(
            "Failed to add unprotected header to COSE_Sign structure");
      }

      // Add payload (encoded as bstr)
      auto payloadBstr =
          CborItemPtr(cbor_build_bytestring(payload.data(), payload.size()));
      if (!cbor_array_push(coseStructure.get(), payloadBstr.get())) {
        throw InvalidCborError("Failed to add payload to COSE_Sign structure");
      }

      // Add signatures array
      auto signaturesArray =
          CborItemPtr(cbor_new_definite_array(signatures.size()));
      for (const auto& sig : signatures) {
        // Each signature is: [protected_header, unprotected_header, signature]
        auto sigStructure = CborItemPtr(cbor_new_definite_array(3));

        // Add signature protected header
        auto sigProtectedHeader = CborItemPtr(cbor_build_bytestring(
            sig.protectedHeader.data(), sig.protectedHeader.size()));
        if (!cbor_array_push(sigStructure.get(), sigProtectedHeader.get())) {
          throw InvalidCborError("Failed to add signature protected header");
        }

        // Add empty signature unprotected header
        auto sigUnprotectedHeader = CborItemPtr(cbor_new_definite_map(0));
        if (!cbor_array_push(sigStructure.get(), sigUnprotectedHeader.get())) {
          throw InvalidCborError("Failed to add signature unprotected header");
        }

        // Add signature bytes
        auto sigBytes = CborItemPtr(
            cbor_build_bytestring(sig.signature.data(), sig.signature.size()));
        if (!cbor_array_push(sigStructure.get(), sigBytes.get())) {
          throw InvalidCborError("Failed to add signature bytes");
        }

        // Add this signature to the signatures array
        if (!cbor_array_push(signaturesArray.get(), sigStructure.get())) {
          throw InvalidCborError("Failed to add signature to signatures array");
        }
      }

      // Add signatures array to main structure
      if (!cbor_array_push(coseStructure.get(), signaturesArray.get())) {
        throw InvalidCborError(
            "Failed to add signatures array to COSE_Sign structure");
      }
    } else if (mode == CwtMode::Encrypted) {
      // For COSE_Encrypt0: [protected_header, unprotected_header, ciphertext]
      coseStructure = CborItemPtr(cbor_new_definite_array(3));

      // Add protected header (encoded as bstr)
      auto protectedHeader = CborItemPtr(
          cbor_build_bytestring(coseHeader.data(), coseHeader.size()));
      if (!cbor_array_push(coseStructure.get(), protectedHeader.get())) {
        throw InvalidCborError(
            "Failed to add protected header to COSE_Encrypt0 structure");
      }

      // Add unprotected header with IV (map)
      auto unprotectedHeader = CborItemPtr(cbor_new_definite_map(1));
      auto ivKey =
          CborItemPtr(cbor_build_uint8(5));  // COSE header label for IV
      auto ivVal = CborItemPtr(cbor_build_bytestring(iv.data(), iv.size()));
      struct cbor_pair iv_pair = {ivKey.get(), ivVal.get()};
      if (!cbor_map_add(unprotectedHeader.get(), iv_pair)) {
        throw InvalidCborError("Failed to add IV to unprotected header");
      }

      if (!cbor_array_push(coseStructure.get(), unprotectedHeader.get())) {
        throw InvalidCborError(
            "Failed to add unprotected header to COSE_Encrypt0 structure");
      }

      // Add encrypted payload (encoded as bstr)
      auto ciphertextBstr = CborItemPtr(cbor_build_bytestring(
          encryptedPayload.data(), encryptedPayload.size()));
      if (!cbor_array_push(coseStructure.get(), ciphertextBstr.get())) {
        throw InvalidCborError(
            "Failed to add ciphertext to COSE_Encrypt0 structure");
      }
    } else {
      // For COSE_Sign1/COSE_Mac0: [protected_header, unprotected_header,
      // payload, signature]
      coseStructure = CborItemPtr(cbor_new_definite_array(4));

      // Add protected header (encoded as bstr)
      auto protectedHeader = CborItemPtr(
          cbor_build_bytestring(coseHeader.data(), coseHeader.size()));
      if (!cbor_array_push(coseStructure.get(), protectedHeader.get())) {
        throw InvalidCborError(
            "Failed to add protected header to COSE structure");
      }

      // Add empty unprotected header (map)
      auto unprotectedHeader = CborItemPtr(cbor_new_definite_map(0));
      if (!cbor_array_push(coseStructure.get(), unprotectedHeader.get())) {
        throw InvalidCborError(
            "Failed to add unprotected header to COSE structure");
      }

      // Add payload (encoded as bstr)
      auto payloadBstr =
          CborItemPtr(cbor_build_bytestring(payload.data(), payload.size()));
      if (!cbor_array_push(coseStructure.get(), payloadBstr.get())) {
        throw InvalidCborError("Failed to add payload to COSE structure");
      }

      // Add signature (encoded as bstr)
      auto signatureBstr = CborItemPtr(
          cbor_build_bytestring(signature.data(), signature.size()));
      if (!cbor_array_push(coseStructure.get(), signatureBstr.get())) {
        throw InvalidCborError("Failed to add signature to COSE structure");
      }
    }

    // Step 6: Serialize COSE structure to raw CBOR bytes (RFC 8392 Section 9.2)
    unsigned char* raw_buffer;
    size_t buffer_size;
    size_t length =
        cbor_serialize_alloc(coseStructure.get(), &raw_buffer, &buffer_size);

    if (length == 0) {
      throw InvalidCborError("Failed to serialize COSE structure");
    }

    auto buffer = CborBufferPtr(raw_buffer);
    std::vector<uint8_t> coseBytes(buffer.get(), buffer.get() + length);

    CAT_LOG_DEBUG("Created CWT token of {} bytes", coseBytes.size());

    return coseBytes;

  } catch (const std::exception& e) {
    CAT_LOG_ERROR("CWT creation failed: {}", e.what());
    throw CryptoError(std::string("CWT creation failed: ") + e.what());
  }
}

std::string Cwt::createCwtBase64(
    CwtMode mode, const CryptographicAlgorithm& algorithm) const {
  auto cwtBytes = createCwt(mode, algorithm);
  return base64UrlEncode(cwtBytes);
}

CwtHeader Cwt::decodeHeader(std::span<const uint8_t> cwtBytes) {
  struct cbor_load_result result;
  auto coseItem = cbor_load_owned(cwtBytes, result);

  if (result.error.code != CBOR_ERR_NONE || !coseItem) {
    throw InvalidCborError("Failed to parse COSE structure");
  }

  if (!cbor_isa_array(coseItem.get())) {
    throw InvalidTokenFormatError();
  }

  size_t arraySize = cbor_array_size(coseItem.get());
  if (arraySize < 3 || arraySize > 4) {
    throw InvalidTokenFormatError();
  }

  cbor_item_t** coseArray = cbor_array_handle(coseItem.get());
  if (!coseArray || !cbor_isa_bytestring(coseArray[0])) {
    throw InvalidTokenFormatError();
  }

  auto protectedHeaderBytes =
      std::vector<uint8_t>(cbor_bytestring_handle(coseArray[0]),
                           cbor_bytestring_handle(coseArray[0]) +
                               cbor_bytestring_length(coseArray[0]));

  coseItem.reset();

  // Decode the protected header map
  struct cbor_load_result headerResult;
  auto headerItem = cbor_load_owned(protectedHeaderBytes.data(),
                                    protectedHeaderBytes.size(), headerResult);

  if (headerResult.error.code != CBOR_ERR_NONE || !headerItem ||
      !cbor_isa_map(headerItem.get())) {
    throw InvalidTokenFormatError();
  }

  int64_t algId = 0;
  std::optional<std::string> kid;
  std::optional<std::string> typ;

  struct cbor_pair* pairs = cbor_map_handle(headerItem.get());
  size_t mapSize = cbor_map_size(headerItem.get());

  for (size_t i = 0; i < mapSize; i++) {
    if (!cbor_isa_uint(pairs[i].key)) continue;
    uint64_t label = cbor_get_int(pairs[i].key);

    if (label == 1) {  // alg
      if (!decodeAlgCborValue(pairs[i].value, algId)) {
        throw InvalidTokenFormatError();
      }
    } else if (label == 4) {  // kid
      if (cbor_isa_string(pairs[i].value)) {
        kid = std::string(
            reinterpret_cast<const char*>(cbor_string_handle(pairs[i].value)),
            cbor_string_length(pairs[i].value));
      }
    } else if (label == 16) {  // content type / typ
      if (cbor_isa_string(pairs[i].value)) {
        typ = std::string(
            reinterpret_cast<const char*>(cbor_string_handle(pairs[i].value)),
            cbor_string_length(pairs[i].value));
      }
    }
  }

  CwtHeader header(algId);
  header.kid = std::move(kid);
  header.typ = std::move(typ);
  return header;
}

Cwt Cwt::validateCwt(std::span<const uint8_t> cwtBytes,
                     const CryptographicAlgorithm& algorithm) {
  try {
    CAT_LOG_DEBUG("Validating CWT token of {} bytes", cwtBytes.size());

    // Parse COSE structure from raw CBOR bytes (RFC 8392 Section 9.2)
    struct cbor_load_result result;
    auto coseItem = cbor_load_owned(cwtBytes, result);

    if (result.error.code != CBOR_ERR_NONE || !coseItem) {
      throw InvalidCborError("Failed to parse COSE structure");
    }

    if (!cbor_isa_array(coseItem.get())) {
      throw InvalidTokenFormatError();
    }

    // Step 3: Handle different COSE structures
    std::vector<uint8_t> protectedHeaderBytes;
    std::vector<uint8_t> payloadBytes;
    bool isEncrypted = false;
    bool isMultiSigned = false;
    std::vector<CoseSignature> validatedSignatures;

    size_t arraySize = cbor_array_size(coseItem.get());

    if (arraySize == 3) {
      // COSE_Encrypt0: [protected_header, unprotected_header, ciphertext]
      if (!algorithm.supportsEncryption()) {
        throw CryptoError(
            "Algorithm does not support decryption for COSE_Encrypt0");
      }
      isEncrypted = true;

      cbor_item_t** coseArray = cbor_array_handle(coseItem.get());
      if (!coseArray) {
        throw InvalidTokenFormatError();
      }

      // Protected header (bytestring)
      if (!cbor_isa_bytestring(coseArray[0])) {
        throw InvalidTokenFormatError();
      }
      protectedHeaderBytes =
          std::vector<uint8_t>(cbor_bytestring_handle(coseArray[0]),
                               cbor_bytestring_handle(coseArray[0]) +
                                   cbor_bytestring_length(coseArray[0]));

      // Extract IV from unprotected header (map)
      if (!cbor_isa_map(coseArray[1])) {
        throw InvalidTokenFormatError();
      }

      std::vector<uint8_t> iv;
      struct cbor_pair* pairs = cbor_map_handle(coseArray[1]);
      size_t map_size = cbor_map_size(coseArray[1]);

      for (size_t i = 0; i < map_size; i++) {
        if (cbor_isa_uint(pairs[i].key) &&
            cbor_get_int(pairs[i].key) == 5) {  // IV label
          if (cbor_isa_bytestring(pairs[i].value)) {
            iv = std::vector<uint8_t>(
                cbor_bytestring_handle(pairs[i].value),
                cbor_bytestring_handle(pairs[i].value) +
                    cbor_bytestring_length(pairs[i].value));
            break;
          }
        }
      }

      if (iv.empty()) {
        throw InvalidTokenFormatError();
      }

      // Ciphertext (bytestring)
      if (!cbor_isa_bytestring(coseArray[2])) {
        throw InvalidTokenFormatError();
      }
      auto ciphertext =
          std::vector<uint8_t>(cbor_bytestring_handle(coseArray[2]),
                               cbor_bytestring_handle(coseArray[2]) +
                                   cbor_bytestring_length(coseArray[2]));

      // Decrypt with Enc_structure as AAD to authenticate the protected
      // header (RFC 8152 §5.3). Producers built after this change will
      // include the AAD; producers that did not will fail this tag check,
      // which is the intended outcome — accepting them would silently
      // drop protected-header authentication.
      auto encAad = createCoseEncrypt0Aad(protectedHeaderBytes);
      payloadBytes = algorithm.decrypt(ciphertext, iv, encAad);

    } else if (arraySize == 4) {
      cbor_item_t** coseArray = cbor_array_handle(coseItem.get());
      if (!coseArray) {
        throw InvalidTokenFormatError();
      }

      // Protected header (bytestring)
      if (!cbor_isa_bytestring(coseArray[0])) {
        throw InvalidTokenFormatError();
      }
      protectedHeaderBytes =
          std::vector<uint8_t>(cbor_bytestring_handle(coseArray[0]),
                               cbor_bytestring_handle(coseArray[0]) +
                                   cbor_bytestring_length(coseArray[0]));

      // Payload (bytestring)
      if (!cbor_isa_bytestring(coseArray[2])) {
        throw InvalidTokenFormatError();
      }
      payloadBytes =
          std::vector<uint8_t>(cbor_bytestring_handle(coseArray[2]),
                               cbor_bytestring_handle(coseArray[2]) +
                                   cbor_bytestring_length(coseArray[2]));

      // Check if the 4th element is an array (COSE_Sign) or bytestring
      // (COSE_Sign1)
      if (cbor_isa_array(coseArray[3])) {
        // COSE_Sign format — validateCwt only handles COSE_Sign1
        throw InvalidTokenFormatError();
      } else if (cbor_isa_bytestring(coseArray[3])) {
        // COSE_Sign1/COSE_Mac0
        auto signatureBytes =
            std::vector<uint8_t>(cbor_bytestring_handle(coseArray[3]),
                                 cbor_bytestring_handle(coseArray[3]) +
                                     cbor_bytestring_length(coseArray[3]));

        // Route to the correct RFC 8152 structure for the supplied
        // algorithm: MAC0 for symmetric MAC algs, Sign1 for signatures.
        // Using the wrong context lets a token authenticated in one mode
        // pass verification in the other, so this dispatch must match the
        // encoder's choice exactly.
        const bool isMac = algorithm.algorithmId() == ALG_HMAC256_256;
        auto verifyInput =
            isMac ? createCoseMac0Input(protectedHeaderBytes, payloadBytes)
                  : createCoseSign1Input(protectedHeaderBytes, payloadBytes);
        bool isValid = algorithm.verify(verifyInput, signatureBytes);

        if (!isValid) {
          throw CryptoError(isMac ? "COSE_Mac0 tag verification failed"
                                  : "COSE_Sign1 signature verification failed");
        }
      } else {
        throw InvalidTokenFormatError();
      }
    } else {
      throw InvalidTokenFormatError();
    }

    coseItem.reset();

    // Step 4: Decode payload and create CWT
    auto decodedPayload = decodePayload(payloadBytes);

    // Parse protected header to get algorithm
    struct cbor_load_result headerResult;
    auto headerItem = cbor_load_owned(
        protectedHeaderBytes.data(), protectedHeaderBytes.size(), headerResult);

    if (headerResult.error.code != CBOR_ERR_NONE || !headerItem ||
        !cbor_isa_map(headerItem.get())) {
      throw InvalidCborError("Invalid COSE protected header");
    }

    // Extract algorithm from header and verify it matches
    int64_t headerAlgId = 0;
    struct cbor_pair* headerPairs = cbor_map_handle(headerItem.get());
    size_t headerMapSize = cbor_map_size(headerItem.get());

    if (headerPairs) {
      for (size_t i = 0; i < headerMapSize; i++) {
        if (cbor_isa_uint(headerPairs[i].key) &&
            cbor_get_int(headerPairs[i].key) == 1) {  // algorithm label
          if (!decodeAlgCborValue(headerPairs[i].value, headerAlgId)) {
            throw InvalidTokenFormatError();
          }
          break;
        }
      }
    }

    headerItem.reset();

    // Verify algorithm matches to prevent algorithm confusion attacks
    int64_t algId = algorithm.algorithmId();

    if (headerAlgId == 0) {
      throw CryptoError("Token missing required algorithm header");
    }

    if (headerAlgId != algId) {
      throw CryptoError(
          "Token algorithm does not match provided verification algorithm");
    }

    auto isKnownAlgorithm = [](int64_t alg) {
      return alg == ALG_ES256 || alg == ALG_PS256 || alg == ALG_HMAC256_256 ||
             alg == ALG_A128GCM || alg == ALG_A192GCM || alg == ALG_A256GCM ||
             alg == ALG_ChaCha20_Poly1305;
    };
    if (!isKnownAlgorithm(headerAlgId)) {
      throw CryptoError("Unknown algorithm ID in token header");
    }

    Cwt validatedCwt(algId, decodedPayload);

    if (isMultiSigned) {
      validatedCwt.signatures = std::move(validatedSignatures);
    }

    CAT_LOG_DEBUG("CWT validation successful");
    return validatedCwt;

  } catch (const std::exception& e) {
    CAT_LOG_ERROR("CWT validation failed: {}", e.what());
    throw CryptoError(std::string("CWT validation failed: ") + e.what());
  }
}

Cwt Cwt::validateCwtBase64(const std::string& encodedCwt,
                           const CryptographicAlgorithm& algorithm) {
  // CTA-5007-B §4.3.1: reject oversized encoded CATs before spending any
  // base64 or CBOR allocation on attacker-controlled input.
  if (encodedCwt.size() > internal::kMaxEncodedTokenBytes) {
    CAT_LOG_ERROR("Encoded CWT exceeds CTA-5007-B recommended maximum ({} > {})",
                  encodedCwt.size(), internal::kMaxEncodedTokenBytes);
    throw InvalidTokenFormatError();
  }
  auto cwtBytes = base64UrlDecode(encodedCwt);
  if (cwtBytes.size() > internal::kMaxDecodedCborBytes) {
    CAT_LOG_ERROR("Decoded CWT exceeds internal ceiling ({} > {} bytes)",
                  cwtBytes.size(), internal::kMaxDecodedCborBytes);
    throw InvalidTokenFormatError();
  }
  return validateCwt(cwtBytes, algorithm);
}

Cwt Cwt::validateMultiSignedCwt(
    std::span<const uint8_t> cwtBytes,
    const std::map<int64_t,
                   std::reference_wrapper<const CryptographicAlgorithm>>&
        algorithms) {
  try {
    CAT_LOG_DEBUG("Validating multi-signed CWT token of {} bytes",
                  cwtBytes.size());

    // Parse COSE structure from raw CBOR bytes
    struct cbor_load_result result;
    auto coseItem = cbor_load_owned(cwtBytes, result);

    if (result.error.code != CBOR_ERR_NONE || !coseItem) {
      throw InvalidCborError("Failed to parse COSE structure");
    }

    if (!cbor_isa_array(coseItem.get())) {
      throw InvalidTokenFormatError();
    }

    std::vector<uint8_t> protectedHeaderBytes;
    std::vector<uint8_t> payloadBytes;
    std::vector<CoseSignature> validatedSignatures;

    size_t arraySize = cbor_array_size(coseItem.get());

    if (arraySize != 4) {
      throw InvalidTokenFormatError();
    }

    cbor_item_t** coseArray = cbor_array_handle(coseItem.get());
    if (!coseArray) {
      throw InvalidTokenFormatError();
    }

    if (!cbor_isa_bytestring(coseArray[0])) {
      throw InvalidTokenFormatError();
    }
    protectedHeaderBytes =
        std::vector<uint8_t>(cbor_bytestring_handle(coseArray[0]),
                             cbor_bytestring_handle(coseArray[0]) +
                                 cbor_bytestring_length(coseArray[0]));

    if (!cbor_isa_bytestring(coseArray[2])) {
      throw InvalidTokenFormatError();
    }
    payloadBytes =
        std::vector<uint8_t>(cbor_bytestring_handle(coseArray[2]),
                             cbor_bytestring_handle(coseArray[2]) +
                                 cbor_bytestring_length(coseArray[2]));

    if (!cbor_isa_array(coseArray[3])) {
      throw InvalidTokenFormatError();
    }

    cbor_item_t** signaturesArray = cbor_array_handle(coseArray[3]);
    size_t signaturesCount = cbor_array_size(coseArray[3]);

    if (!signaturesArray) {
      throw InvalidTokenFormatError();
    }

    constexpr size_t MAX_SIGNATURES = 100;
    if (signaturesCount > MAX_SIGNATURES) {
      throw InvalidClaimValueError("Too many signatures");
    }

    for (size_t i = 0; i < signaturesCount; i++) {
      if (!cbor_isa_array(signaturesArray[i]) ||
          cbor_array_size(signaturesArray[i]) != 3) {
        throw InvalidTokenFormatError();
      }

      cbor_item_t** signatureStructure = cbor_array_handle(signaturesArray[i]);
      if (!signatureStructure) {
        throw InvalidTokenFormatError();
      }

      if (!cbor_isa_bytestring(signatureStructure[0])) {
        throw InvalidTokenFormatError();
      }
      std::vector<uint8_t> sigProtectedHeader(
          cbor_bytestring_handle(signatureStructure[0]),
          cbor_bytestring_handle(signatureStructure[0]) +
              cbor_bytestring_length(signatureStructure[0]));

      if (!cbor_isa_bytestring(signatureStructure[2])) {
        throw InvalidTokenFormatError();
      }
      std::vector<uint8_t> signatureBytes(
          cbor_bytestring_handle(signatureStructure[2]),
          cbor_bytestring_handle(signatureStructure[2]) +
              cbor_bytestring_length(signatureStructure[2]));

      int64_t sigAlgId = 0;
      bool algFound = false;

      if (!sigProtectedHeader.empty()) {
        struct cbor_load_result sigHeaderResult;
        auto sigHeaderItem =
            cbor_load_owned(sigProtectedHeader.data(),
                            sigProtectedHeader.size(), sigHeaderResult);
        if (sigHeaderResult.error.code == CBOR_ERR_NONE && sigHeaderItem &&
            cbor_isa_map(sigHeaderItem.get())) {
          struct cbor_pair* pairs = cbor_map_handle(sigHeaderItem.get());
          size_t mapSize = cbor_map_size(sigHeaderItem.get());

          if (!pairs) {
            throw InvalidTokenFormatError();
          }

          for (size_t j = 0; j < mapSize; j++) {
            if (cbor_isa_uint(pairs[j].key) &&
                cbor_get_int(pairs[j].key) == 1) {
              if (!decodeAlgCborValue(pairs[j].value, sigAlgId)) {
                throw InvalidTokenFormatError();
              }
              algFound = true;
              break;
            }
          }
        }
      }

      if (!algFound) {
        throw CryptoError("Algorithm ID not found in signature " +
                          std::to_string(i) + " protected header");
      }

      auto algIt = algorithms.find(sigAlgId);
      if (algIt == algorithms.end()) {
        throw CryptoError("No algorithm provided for signature " +
                          std::to_string(i) + " with algorithm ID " +
                          std::to_string(sigAlgId));
      }

      auto signingInput = createCoseSignInput(
          protectedHeaderBytes, sigProtectedHeader, {}, payloadBytes);
      bool isValid = algIt->second.get().verify(signingInput, signatureBytes);

      if (!isValid) {
        throw CryptoError(
            "Multi-signed CWT signature verification failed for signature " +
            std::to_string(i));
      }

      validatedSignatures.emplace_back(sigProtectedHeader, signatureBytes,
                                       sigAlgId);
    }

    coseItem.reset();

    // Step 4: Decode payload and create CWT
    auto decodedPayload = decodePayload(payloadBytes);

    int64_t primaryAlgId =
        validatedSignatures.empty() ? 0 : validatedSignatures[0].algorithmId;

    Cwt validatedCwt(primaryAlgId, decodedPayload);
    validatedCwt.signatures = std::move(validatedSignatures);

    CAT_LOG_DEBUG("Multi-signed CWT validation successful with {} signatures",
                  validatedCwt.signatures.size());
    return validatedCwt;

  } catch (const std::exception& e) {
    CAT_LOG_ERROR("Multi-signed CWT validation failed: {}", e.what());
    throw CryptoError(std::string("Multi-signed CWT validation failed: ") +
                      e.what());
  }
}

Cwt Cwt::validateMultiSignedCwtBase64(
    const std::string& encodedCwt,
    const std::map<int64_t,
                   std::reference_wrapper<const CryptographicAlgorithm>>&
        algorithms) {
  auto cwtBytes = base64UrlDecode(encodedCwt);
  return validateMultiSignedCwt(cwtBytes, algorithms);
}

std::vector<uint8_t> Cwt::createDpopSigningInput(
    const AuthorizationContext& actx, int64_t iat,
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

    auto addToMap = [](cbor_item_t* map, CborItemPtr key, CborItemPtr val) {
      struct cbor_pair pair = {key.get(), val.get()};
      if (!cbor_map_add(map, pair)) {
        throw InvalidCborError("Failed to add pair to CBOR map");
      }
    };

    // Add type
    addToMap(actx_map.get(), CborItemPtr(cbor_build_string("type")),
             CborItemPtr(cbor_build_string(actx.type.c_str())));

    // Add action
    addToMap(actx_map.get(), CborItemPtr(cbor_build_string("action")),
             CborItemPtr(cbor_build_uint64(actx.action)));

    // Add tns (track namespace)
    addToMap(actx_map.get(), CborItemPtr(cbor_build_string("tns")),
             CborItemPtr(cbor_build_string(actx.tns.c_str())));

    // Add tn (track name)
    addToMap(actx_map.get(), CborItemPtr(cbor_build_string("tn")),
             CborItemPtr(cbor_build_string(actx.tn.c_str())));

    // Add resource (optional)
    if (!actx.resource_uri.empty()) {
      addToMap(actx_map.get(), CborItemPtr(cbor_build_string("resource")),
               CborItemPtr(cbor_build_string(actx.resource_uri.c_str())));
    }

    // Add actx to main payload
    addToMap(payload_map.get(), CborItemPtr(cbor_build_string("actx")),
             std::move(actx_map));

    // Add iat (issued at)
    addToMap(payload_map.get(), CborItemPtr(cbor_build_string("iat")),
             CborItemPtr(cbor_build_uint64(iat)));

    // Add jti if present
    if (jti.has_value()) {
      addToMap(payload_map.get(), CborItemPtr(cbor_build_string("jti")),
               CborItemPtr(cbor_build_string(jti.value().c_str())));
    }

    // Add ath if present
    if (ath.has_value()) {
      addToMap(payload_map.get(), CborItemPtr(cbor_build_string("ath")),
               CborItemPtr(cbor_build_string(ath.value().c_str())));
    }

    // Serialize CBOR to bytes
    unsigned char* raw_buffer;
    size_t buffer_size;
    size_t length =
        cbor_serialize_alloc(payload_map.get(), &raw_buffer, &buffer_size);

    if (length == 0) {
      throw InvalidCborError("Failed to serialize DPoP proof CBOR");
    }

    auto buffer = CborBufferPtr(raw_buffer);
    std::vector<uint8_t> result(buffer.get(), buffer.get() + length);

    CAT_LOG_DEBUG("Created DPoP signing input of {} bytes", result.size());
    return result;

  } catch (const std::exception& e) {
    CAT_LOG_ERROR("DPoP signing input creation failed: {}", e.what());
    throw InvalidCborError(std::string("DPoP signing input creation failed: ") +
                           e.what());
  }
}

}  // namespace catapult