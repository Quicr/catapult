// Fuzz target: base64url decoder. Every token surface (CWT bytes, DPoP JWT
// segments, HTTP headers) hits this decoder before anything else. The
// implementation MUST NOT crash on padding-vs-no-padding permutations,
// non-alphabet characters, or lengths that fall on and off the 4-byte grid.

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string_view>

#include "catapult/base64.hpp"
#include "catapult/error.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const std::string_view input(reinterpret_cast<const char*>(data), size);
  try {
    (void)catapult::base64UrlDecode(input);
  } catch (const catapult::CatError&) {
    // Expected on invalid base64url.
  } catch (const std::exception&) {
  }
  return 0;
}
