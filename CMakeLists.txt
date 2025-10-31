cmake_minimum_required(VERSION 3.16)
project(catapult VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ENABLE_LOGGING "Enable logging with spdlog" ON)

# Dependency management
find_package(OpenSSL REQUIRED)

# Add submodules
add_subdirectory(external/libcbor)
add_subdirectory(external/nlohmann_json)

# Include directories
include_directories(include)

# Create library
add_library(catapult STATIC
    src/base64.cpp
    src/claims.cpp
    src/composite.cpp
    src/crypto.cpp
    src/cwt.cpp
    src/jwk.cpp
    src/dpop.cpp
    src/error.cpp
    src/json_serialization.cpp
    src/moqt_claims.cpp
    src/token.cpp
    src/trie.cpp
    src/uri.cpp
    src/validator.cpp
)

# Link libraries
target_link_libraries(catapult 
    cbor
    ${OPENSSL_LIBRARIES}
    nlohmann_json::nlohmann_json
)

# Include OpenSSL headers
target_include_directories(catapult PRIVATE ${OPENSSL_INCLUDE_DIR})

# Add spdlog if logging is enabled
if(ENABLE_LOGGING)
    target_link_libraries(catapult spdlog::spdlog)
endif()
# Set compiler flags with enhanced security and warnings
target_compile_options(catapult PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic>
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wconversion -Wsign-conversion>
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wformat=2 -Wformat-security>
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wnull-dereference -Wdouble-promotion>
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wshadow -Wcast-align -Wcast-qual>
    # Security hardening flags
    $<$<CXX_COMPILER_ID:GNU,Clang>:-fstack-protector-strong>
    $<$<CXX_COMPILER_ID:GNU,Clang>:-D_FORTIFY_SOURCE=2>
    # MSVC specific flags
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive- /analyze>
    $<$<CXX_COMPILER_ID:MSVC>:/GS /guard:cf>
)


if(ENABLE_LOGGING)
    target_compile_definitions(catapult PRIVATE ENABLE_LOGGING)
endif()

# Enable testing
enable_testing()

# Add Doctest
add_subdirectory(external/doctest)

# Add spdlog if logging is enabled
if(ENABLE_LOGGING)
    add_subdirectory(external/spdlog)
endif()

# Find Google Benchmark
find_package(benchmark QUIET)
if(NOT benchmark_FOUND)
    message(STATUS "Google Benchmark not found, benchmark targets will be disabled")
endif()

# Create test executable
add_executable(catapult_tests
    tests/main.cpp
    tests/base64.cpp
    tests/claims.cpp
    tests/composite_claims.cpp
    tests/crypto.cpp
    tests/cwt.cpp
    tests/cwt_crypto.cpp
    tests/cwt_encode_decode.cpp
    tests/cwt_signing.cpp
    tests/rfc8152_compliance.cpp
    tests/integration.cpp
    tests/memory_pool.cpp
    tests/moqt_claims.cpp
    tests/secure_vector.cpp
    tests/token.cpp
    tests/token_factory.cpp
    tests/trie.cpp
    tests/validator.cpp
)

target_link_libraries(catapult_tests 
    catapult
    ${OPENSSL_LIBRARIES}
    cbor
    doctest::doctest
)

# Apply same security flags to tests
target_compile_options(catapult_tests PRIVATE 
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic>
    $<$<CXX_COMPILER_ID:GNU,Clang>:-fstack-protector-strong>
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /GS>
)

# Add test
add_test(NAME catapult_unit_tests COMMAND catapult_tests)

# Create benchmark executable (if Google Benchmark is available)
if(benchmark_FOUND)
    add_executable(catapult_benchmarks
        benchmarks/base64_bench.cpp
        benchmarks/trie_bench.cpp
        benchmarks/memory_pool_bench.cpp
        benchmarks/secure_vector_bench.cpp
        benchmarks/cbor_bench.cpp
    )
    
    target_link_libraries(catapult_benchmarks
        catapult
        benchmark::benchmark
        benchmark::benchmark_main
    )
    
    # Optionally add benchmark as a test (though it's primarily for performance measurement)
    # add_test(NAME catapult_benchmarks COMMAND catapult_benchmarks)
endif()


# Example executables
add_executable(cat_token_json_example
        examples/cat_token_json_example.cpp
)

target_link_libraries(cat_token_json_example catapult)


add_executable(cat_cwt_per_signature_example
        examples/cat_cwt_per_signature_example.cpp
)

target_link_libraries(cat_cwt_per_signature_example catapult)

if(ENABLE_LOGGING)
    target_compile_definitions(cat_cwt_per_signature_example PRIVATE ENABLE_LOGGING)
endif()

add_executable(cat_cwt_crypto
        examples/cat_cwt_crypto.cpp
)

target_link_libraries(cat_cwt_crypto catapult)
