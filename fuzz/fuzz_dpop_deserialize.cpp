// Fuzz target: DPoP proof deserialization. `DpopProof::deserialize` accepts
// arbitrary caller-provided strings (JWT- or CWT-shaped) and must handle
// malformed input without corruption. This is the pre-crypto stage; the
// crypto verification path is not exercised here so that failures bisect
// cleanly to parser bugs.

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string_view>

#include "catapult/dpop.hpp"
#include "catapult/error.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const std::string_view input(reinterpret_cast<const char*>(data), size);
  try {
    (void)catapult::DpopProof::deserialize(input);
  } catch (const catapult::CatError&) {
    // Expected on malformed proofs.
  } catch (const std::exception&) {
  }
  return 0;
}
