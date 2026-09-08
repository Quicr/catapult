// Fuzz target: CWT header extraction. `decodeHeader` is what runs before
// the KeyResolver dispatch, so it sees attacker bytes with zero crypto
// gating — a crash here means an unauthenticated caller can DoS the
// admission path. Header parsing MUST reject cleanly on any input.

#include <cstddef>
#include <cstdint>
#include <exception>
#include <span>

#include "catapult/cwt.hpp"
#include "catapult/error.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  try {
    (void)catapult::Cwt::decodeHeader(std::span<const uint8_t>(data, size));
  } catch (const catapult::CatError&) {
    // Expected on malformed / truncated / out-of-schema headers.
  } catch (const std::exception&) {
  }
  return 0;
}
