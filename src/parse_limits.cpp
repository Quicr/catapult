#include "catapult/parse_limits.hpp"

#include <sstream>

namespace catapult {

namespace {

void requireNonZero(const char* field, std::size_t value) {
  if (value == 0) {
    std::ostringstream os;
    os << "ParseLimits::" << field
       << " must be positive (zero would disable the check)";
    throw InvalidParseLimitsError(os.str());
  }
}

void requireAtMost(const char* field, std::size_t value, std::size_t ceiling) {
  if (value > ceiling) {
    std::ostringstream os;
    os << "ParseLimits::" << field << " (" << value
       << ") exceeds the compiled-in absolute ceiling (" << ceiling
       << "). Loosening beyond the default is a configuration error; "
          "tighten below the default instead.";
    throw InvalidParseLimitsError(os.str());
  }
}

}  // namespace

void validateParseLimits(const ParseLimits& limits) {
  requireNonZero("max_encoded_token_bytes", limits.max_encoded_token_bytes);
  requireNonZero("max_decoded_cbor_bytes", limits.max_decoded_cbor_bytes);
  requireNonZero("max_cbor_depth", limits.max_cbor_depth);
  requireNonZero("max_uri_length", limits.max_uri_length);
  requireNonZero("max_regex_pattern_length", limits.max_regex_pattern_length);
  requireNonZero("max_regex_patterns", limits.max_regex_patterns);

  requireAtMost("max_encoded_token_bytes", limits.max_encoded_token_bytes,
                kAbsoluteMaxEncodedTokenBytes);
  requireAtMost("max_decoded_cbor_bytes", limits.max_decoded_cbor_bytes,
                kAbsoluteMaxDecodedCborBytes);
  requireAtMost("max_cbor_depth", limits.max_cbor_depth, kAbsoluteMaxCborDepth);
  requireAtMost("max_uri_length", limits.max_uri_length, kAbsoluteMaxUriLength);
  requireAtMost("max_regex_pattern_length", limits.max_regex_pattern_length,
                kAbsoluteMaxRegexPatternLength);
  requireAtMost("max_regex_patterns", limits.max_regex_patterns,
                kAbsoluteMaxRegexPatterns);
}

}  // namespace catapult
