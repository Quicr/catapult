# Catapult fuzz harnesses

This directory ships libFuzzer harnesses for every parser catapult exposes to
untrusted input. Each harness is a single translation unit that defines
`LLVMFuzzerTestOneInput` and calls exactly one entry point, so a crash bisects
directly to the parser under test rather than to a composition of them.

## What is fuzzed

| Harness | Target | Notes |
|---|---|---|
| `fuzz_strict_cbor` | `internal::loadStrict` | The post-parse validator that gates every CBOR-carrying claim path — must not crash on any byte string. |
| `fuzz_cwt_decode_payload` | `Cwt::decodePayload` | Payload-only decode; exercises the CBOR-to-CatToken conversion without triggering crypto. |
| `fuzz_cwt_header` | `Cwt::decodeHeader` | Header extraction the KeyResolver dispatch depends on. |
| `fuzz_base64url` | `base64UrlDecode` | Input surface for every base64url-encoded token. |
| `fuzz_dpop_deserialize` | `DpopProof::deserialize` | JOSE + JWT parser accepting attacker-controlled proofs. |

Every harness catches `catapult::CatError` (and any expected `std::exception`)
and returns `0`. Uncaught exceptions, timeouts, and sanitizer traps are all
treated as failures by the driver — a harness is intentionally silent on
"parser rejected the input" outcomes because that is the desired behaviour.

## Build

Fuzzing is off by default. Enable with:

```sh
cmake -S . -B build-fuzz \
  -DCATAPULT_ENABLE_FUZZERS=ON \
  -DCATAPULT_ENABLE_SANITIZERS=ON \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug
cmake --build build-fuzz --target catapult_fuzz_all
```

`CATAPULT_ENABLE_FUZZERS` is gated on Clang because libFuzzer's
`-fsanitize=fuzzer` is Clang-only.

> **Apple Clang note.** Xcode ships Clang without the libFuzzer runtime
> archive (`libclang_rt.fuzzer_osx.a`); compilation succeeds but the link
> step fails with "library not found". Use an LLVM Clang toolchain from
> Homebrew (`brew install llvm && export
> CC=$(brew --prefix llvm)/bin/clang CXX=$(brew --prefix llvm)/bin/clang++`)
> or run the harnesses on Linux, which is what CI does.

## Run

```sh
# 30-second smoke, one harness:
./build-fuzz/fuzz/fuzz_strict_cbor -max_total_time=30 fuzz/corpus/strict_cbor

# All harnesses, CI-style short soak:
for h in fuzz_strict_cbor fuzz_cwt_decode_payload fuzz_cwt_header \
         fuzz_base64url fuzz_dpop_deserialize; do
  ./build-fuzz/fuzz/$h -max_total_time=60 fuzz/corpus/$h || exit 1
done
```

## Corpus

Seed corpora live under `fuzz/corpus/<harness>`. The CI job runs each harness
for a bounded time so the seeded corpus is loaded on every run; crashes are
reported as artefacts. Long-running (48-hour) soaks are the responsibility of
the embedder's dedicated fuzzing infrastructure — this tree only guarantees
that a checked-in corpus never crashes and that the harnesses build clean
under ASan/UBSan.

## Adding new inputs

Drop the raw bytes into `corpus/<harness>/<descriptive-name>.bin`. libFuzzer
loads every file in the seed directory on startup. Prefer inputs that come
from real captures over synthetic ones.
