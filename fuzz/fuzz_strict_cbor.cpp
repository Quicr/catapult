// Fuzz target: the strict CBOR loader. Every claim parser passes attacker-
// controlled bytes through `loadStrict` before touching them, so this harness
// is the widest net for CBOR decoder bugs (indefinite lengths, nesting
// depth, integer canonicality, dangling continuations).
//
// Contract: `loadStrict` MUST NOT crash, hang, or leak on any input. It is
// free to throw — we catch `catapult::CatError` and any `std::exception`
// because "rejected" is the expected fast path for random bytes.

#include <cstddef>
#include <cstdint>
#include <exception>
#include <span>

#include "catapult/error.hpp"
#include "catapult/internal/strict_cbor.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  try {
    (void)catapult::internal::loadStrict(std::span<const uint8_t>(data, size));
  } catch (const catapult::CatError&) {
    // Expected: strict loader rejected the input.
  } catch (const std::exception&) {
    // libcbor may surface allocation / bad-alloc / logic errors as std
    // exceptions on pathological inputs. Still "handled" — not a bug.
  }
  return 0;
}
