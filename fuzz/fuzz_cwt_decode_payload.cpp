// Fuzz target: CWT payload decode. Exercises the CBOR-to-CatToken
// conversion path without touching COSE crypto — the boundary that turns
// bytes into semantic claims (issuer/audience/cti/nbf/exp, catgeocoord,
// moqt-scope, composite claims, etc.).
//
// A crash here is a decoder bug; a rejection is expected.

#include <cstddef>
#include <cstdint>
#include <exception>
#include <span>

#include "catapult/cwt.hpp"
#include "catapult/error.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  try {
    (void)catapult::Cwt::decodePayload(std::span<const uint8_t>(data, size));
  } catch (const catapult::CatError&) {
    // Expected — every semantic failure surfaces as a CatError subclass.
  } catch (const std::exception&) {
    // Bad-alloc / logic errors from downstream libraries: not a decoder bug.
  }
  return 0;
}
