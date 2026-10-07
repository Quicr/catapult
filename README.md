# Catapult

![Catapult Icon](catapult-icon.svg)

[![CI](https://github.com/Quicr/catapult/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Quicr/catapult/actions/workflows/ci.yml)
[![Sanitizers](https://github.com/Quicr/catapult/actions/workflows/sanitizers.yml/badge.svg?branch=main)](https://github.com/Quicr/catapult/actions/workflows/sanitizers.yml)
[![Fuzz](https://github.com/Quicr/catapult/actions/workflows/fuzz.yml/badge.svg?branch=main)](https://github.com/Quicr/catapult/actions/workflows/fuzz.yml)
[![Benchmarks](https://github.com/Quicr/catapult/actions/workflows/benchmarks.yml/badge.svg?branch=main)](https://github.com/Quicr/catapult/actions/workflows/benchmarks.yml)
[![Code Formatting](https://github.com/Quicr/catapult/actions/workflows/format.yml/badge.svg?branch=main)](https://github.com/Quicr/catapult/actions/workflows/format.yml)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](BSD-2-Clause.txt)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)

CI covers Linux x86_64, Linux ARM64, macOS ARM64 (Apple Silicon), and Windows x86_64 (MSVC v143 on Server 2022).

Catapult is a modern C++ library that provides secure, high-performance implementation
for Common Access Token. One of the primary application goals for Catapult is 
supporting authorization for Media Over QUIC applications. However, the 
library is designed to be flexible and can be used in various other contexts
where secure token-based access control is required.

## Build Process

### Prerequisites

- C++ Compiler: GCC-12+ or Clang-17+ with full C++20 support
- CMake: 3.16 or later
- Git: For cloning and submodule management
- Just: `cargo install just` or `brew install just` (optional, for justfile support)
- Dependencies: OpenSSL, libcbor, nlohmann-json, spdlog

### Clone and Setup

```bash
# Clone the repository
git clone <repository-url>
cd catapult

# Initialize and update submodules
git submodule update --init --recursive
```

### Local Build

#### Using Just (Recommended)

```bash
# Build the project (using make internally)
just build

# Build using cmake directly
just build-cmake

# Run tests
just test

# Run specific test suites (doctest filters use wildcards)
./build/catapult_tests --test-suite="*MOQT*"   # MOQT-related suites
./build/catapult_tests --test-suite="*DPoP*"   # DPoP-related suites
./build/catapult_tests --list-test-suites      # See all suites

# Clean build directory
just clean

# Show all available commands
just help
```

#### Using Make (Traditional)

```bash
# Build the project
make

# Run tests  
make test

# Show all available commands
make help
```

#### Using CMake Directly

```bash
# Create build directory
mkdir build && cd build

# Configure with CMake
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_LOGGING=ON

# Build the project
make -j$(nproc)

# Run tests
./catapult_tests

# Run a specific test suite (doctest filters use wildcards)
./catapult_tests --test-suite="*MOQT*"

# List all suites, or query the doctest options
./catapult_tests --list-test-suites
./catapult_tests --help
```

## Docker Build and Test

### Quick Start with Docker Scripts

Build the project:
```bash
# Build for Alpine 
./docker-build.sh

# Build for Alpine x86_64 (explicit)
./docker-build.sh alpine

# Build for Raspberry Pi ARM64
./docker-build.sh raspberrypi

# Clean build
CLEAN=true ./docker-build.sh alpine
```

Run tests:
```bash

# Run basic tests on specific platform
./docker-test.sh alpine
./docker-test.sh raspberrypi

# Run all test types (basic, memory, performance, analysis)
./docker-test.sh alpine all
./docker-test.sh raspberrypi all

```

## Build Options

| Option | Default | Purpose |
|--------|---------|---------|
| `ENABLE_LOGGING` | ON | Compile in spdlog-based logging |
| `CATAPULT_ENABLE_JSON` | ON | JSON serialization (requires nlohmann_json) |
| `CATAPULT_ENABLE_SANITIZERS` | OFF | ASan + UBSan |
| `CATAPULT_ENABLE_TSAN` | OFF | ThreadSanitizer (mutually exclusive with ASan) |
| `CATAPULT_ENABLE_WERROR` | OFF | Treat compiler warnings as errors |
| `CATAPULT_ENABLE_LTO` | OFF | Link-time optimization for library targets |
| `CATAPULT_ENABLE_FUZZERS` | OFF | Build libFuzzer harnesses (Clang only) |

## Sanitizer Testing (ASan/UBSan)

```bash
cmake -S . -B build-san \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCATAPULT_ENABLE_SANITIZERS=ON \
  -DENABLE_LOGGING=OFF

cmake --build build-san -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)

# Run tests under sanitizers
ASAN_OPTIONS="detect_leaks=1:halt_on_error=1" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
ctest --test-dir build-san --output-on-failure --timeout 600
```

On macOS, remove `detect_leaks=1` as it is not supported.

## Fuzzing (Clang + libFuzzer)

```bash
CC=clang CXX=clang++ cmake -S . -B build-fuzz \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCATAPULT_ENABLE_FUZZERS=ON

cmake --build build-fuzz -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)

# Fuzz targets live under build-fuzz/fuzz/. Corpora are under fuzz/corpus/.
./build-fuzz/fuzz/fuzz_base64url fuzz/corpus/fuzz_base64url -runs=100000
```

## Observability

Applications inject a `MetricsSink` implementation via
`catapult::metrics::setMetricsSink(...)` (from `include/catapult/metrics.hpp`)
to receive counter, observation, and gauge samples for parser decisions,
policy accept/reject events, DPoP proof outcomes, and cache hits. When no
sink is installed the observability path is zero-cost.

## Benchmarks

### Local Benchmarks

```bash
# Google Benchmark executable (if available)
./build/catapult_benchmarks
```


