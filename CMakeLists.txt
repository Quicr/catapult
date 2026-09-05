cmake_minimum_required(VERSION 3.16)
project(catapult VERSION 1.3.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ENABLE_LOGGING "Enable logging with spdlog" ON)
option(CATAPULT_ENABLE_JSON "Enable JSON serialization support (requires nlohmann_json)" ON)
option(CATAPULT_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(CATAPULT_ENABLE_TSAN "Enable ThreadSanitizer (mutually exclusive with ASan/UBSan)" OFF)
option(CATAPULT_ENABLE_WERROR "Treat compiler warnings as errors in library and test builds" OFF)
option(CATAPULT_ENABLE_LTO "Enable interprocedural optimization (LTO) for library targets" OFF)
# Dependency management
find_package(OpenSSL REQUIRED)

# Add submodules
# Align libcbor's sanitizer option with ours
set(SANITIZE ${CATAPULT_ENABLE_SANITIZERS} CACHE BOOL "" FORCE)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)

# libcbor: only the static `cbor` target is linked into catapult. Its
# defaults would build ~10 example binaries and emit install rules for
# headers and pkg-config; force them off so an in-tree rebuild does not
# spend time on artefacts we never ship.
set(WITH_EXAMPLES OFF CACHE BOOL "" FORCE)
set(WITH_TESTS OFF CACHE BOOL "" FORCE)
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY ON CACHE BOOL "" FORCE)
add_subdirectory(external/libcbor)

if(CATAPULT_ENABLE_JSON)
    if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR AND NOT TARGET nlohmann_json::nlohmann_json)
        # nlohmann_json is header-only (INTERFACE) so the compiled bloat is
        # already zero, but its own CMake exposes JSON_BuildTests /
        # JSON_Install knobs whose defaults track MAIN_PROJECT. Pin them off
        # so a parent build that flips MAIN_PROJECT (or a future upstream
        # default change) cannot silently pull tests or install rules in.
        set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
        set(JSON_Install OFF CACHE BOOL "" FORCE)
        add_subdirectory(external/nlohmann_json)
    endif()
endif()

# Create library
set(CATAPULT_SOURCES
    src/base64.cpp
    src/claims.cpp
    src/composite.cpp
    src/crypto.cpp
    src/cwt.cpp
    src/dpop.cpp
    src/error.cpp
    src/key_resolver.cpp
    src/moqt_claims.cpp
    src/policy_cache.cpp
    src/replay_store.cpp
    src/strict_cbor.cpp
    src/token.cpp
    src/trie.cpp
    src/uri.cpp
)

# Add JSON-dependent sources only when JSON is enabled
if(CATAPULT_ENABLE_JSON)
    list(APPEND CATAPULT_SOURCES
        src/json_serialization.cpp
        src/jwk.cpp
    )
endif()

add_library(catapult STATIC ${CATAPULT_SOURCES})

# Link libraries
target_link_libraries(catapult
    cbor
    ${OPENSSL_LIBRARIES}
)

# Link nlohmann_json if JSON support is enabled
if(CATAPULT_ENABLE_JSON AND TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(catapult nlohmann_json::nlohmann_json)
    target_compile_definitions(catapult PUBLIC CATAPULT_ENABLE_JSON)
endif()

# Set up include directories for the library
target_include_directories(catapult
    PUBLIC include
    PUBLIC ${OPENSSL_INCLUDE_DIR}
)

# Add spdlog if logging is enabled
if(ENABLE_LOGGING)
    # Add spdlog as submodule if not already added. Its defaults for
    # tests/bench/example/install/shared already resolve to OFF via
    # SPDLOG_MASTER_PROJECT, but pin them explicitly so a parent build or
    # a future upstream default cannot silently reintroduce those targets.
    if(NOT TARGET spdlog::spdlog)
        set(SPDLOG_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(SPDLOG_BUILD_BENCH OFF CACHE BOOL "" FORCE)
        set(SPDLOG_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
        set(SPDLOG_BUILD_SHARED OFF CACHE BOOL "" FORCE)
        set(SPDLOG_INSTALL OFF CACHE BOOL "" FORCE)
        add_subdirectory(external/spdlog)
    endif()
    target_link_libraries(catapult spdlog::spdlog)
endif()

# Set compiler flags with enhanced security and warnings
target_compile_options(catapult PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -Wpedantic>
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wconversion -Wsign-conversion>
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wformat=2 -Wformat-security>
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wnull-dereference -Wdouble-promotion>
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wshadow -Wcast-align -Wcast-qual>
    # Security hardening flags
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fstack-protector-strong>
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-D_FORTIFY_SOURCE=2>
    # MSVC specific flags
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive- /analyze>
    $<$<CXX_COMPILER_ID:MSVC>:/GS /guard:cf>
)

if(CATAPULT_ENABLE_WERROR)
    # A narrow allowlist of warnings-as-errors. Blanket -Werror would trip on
    # signed/unsigned churn at OpenSSL/libcbor boundaries that is well
    # understood; the classes below correspond to real correctness hazards
    # (dropped return values from warn_unused_result / nodiscard functions,
    # missing return statements, uninitialised reads, unhandled fallthroughs,
    # and undefined behaviour).
    set(CATAPULT_WERROR_FLAGS
        -Werror=unused-result
        -Werror=return-type
        -Werror=uninitialized
        -Werror=implicit-fallthrough
        -Werror=undef
        # Real hazards flagged by the C-08 audit: dropping a value that only
        # exists as a side effect, mismatched delete[]/delete, comparing an
        # array pointer to zero as if it were a scalar, and switching over
        # an enum with a missing case.
        -Werror=unused-value
        -Werror=delete-non-virtual-dtor
        -Werror=switch
        -Werror=address
        -Werror=parentheses
    )
    target_compile_options(catapult PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:${CATAPULT_WERROR_FLAGS}>
        $<$<CXX_COMPILER_ID:MSVC>:/WX>
    )
endif()

if(CATAPULT_ENABLE_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT catapult_ipo_supported OUTPUT catapult_ipo_error)
    if(catapult_ipo_supported)
        set_property(TARGET catapult PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    else()
        message(WARNING "CATAPULT_ENABLE_LTO requested but not supported: ${catapult_ipo_error}")
    endif()
endif()

if(CATAPULT_ENABLE_SANITIZERS AND CATAPULT_ENABLE_TSAN)
    message(FATAL_ERROR
        "CATAPULT_ENABLE_SANITIZERS and CATAPULT_ENABLE_TSAN are mutually exclusive.")
endif()

if(CATAPULT_ENABLE_SANITIZERS)
    set(CATAPULT_SANITIZER_FLAGS
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
        -fno-sanitize-recover=all
        -fno-sanitize=nonnull-attribute
    )
    target_compile_options(catapult PUBLIC ${CATAPULT_SANITIZER_FLAGS})
    target_link_options(catapult PUBLIC ${CATAPULT_SANITIZER_FLAGS})
endif()

if(CATAPULT_ENABLE_TSAN)
    set(CATAPULT_TSAN_FLAGS
        -fsanitize=thread
        -fno-omit-frame-pointer
    )
    target_compile_options(catapult PUBLIC ${CATAPULT_TSAN_FLAGS})
    target_link_options(catapult PUBLIC ${CATAPULT_TSAN_FLAGS})
endif()

if(ENABLE_LOGGING)
    target_compile_definitions(catapult PRIVATE ENABLE_LOGGING)
endif()

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    # Enable testing
    enable_testing()

    # Add Doctest. Its own examples/tests default off when it is a
    # submodule (via MAIN_PROJECT), but DOCTEST_NO_INSTALL defaults OFF —
    # skip its install() rules so `cmake --install` reflects catapult only.
    if(NOT TARGET doctest::doctest)
        set(DOCTEST_WITH_TESTS OFF CACHE BOOL "" FORCE)
        set(DOCTEST_NO_INSTALL ON CACHE BOOL "" FORCE)
        add_subdirectory(external/doctest)
    endif()

    # Add spdlog if logging is enabled and not already added. Guards match
    # the earlier block; both may run depending on how catapult is embedded.
    if(ENABLE_LOGGING AND NOT TARGET spdlog::spdlog)
        set(SPDLOG_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(SPDLOG_BUILD_BENCH OFF CACHE BOOL "" FORCE)
        set(SPDLOG_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
        set(SPDLOG_BUILD_SHARED OFF CACHE BOOL "" FORCE)
        set(SPDLOG_INSTALL OFF CACHE BOOL "" FORCE)
        add_subdirectory(external/spdlog)
    endif()

    # Find Google Benchmark
    find_package(benchmark QUIET)
    if(NOT benchmark_FOUND)
        message(STATUS "Google Benchmark not found, benchmark targets will be disabled")
    endif()

    # Create test executable
    set(CATAPULT_TEST_SOURCES
        tests/main.cpp
        tests/base64.cpp
        tests/claims.cpp
        tests/composite_claims.cpp
        tests/crypto.cpp
        tests/cwt.cpp
        tests/cwt_crypto.cpp
        tests/cwt_encode_decode.cpp
        tests/cwt_signing.cpp
        tests/dpop.cpp
        tests/key_resolver.cpp
        tests/rfc8152_compliance.cpp
        tests/memory_pool.cpp
        tests/moqt_claims.cpp
        tests/parse_limits.cpp
        tests/policy_cache.cpp
        tests/replay_store.cpp
        tests/revalidation_callback.cpp
        tests/uri_catu.cpp
        tests/secure_vector.cpp
        tests/strict_cbor.cpp
        tests/token.cpp
        tests/token_factory.cpp
        tests/trie.cpp
        tests/validator.cpp
    )

    if(CATAPULT_ENABLE_JSON)
        list(APPEND CATAPULT_TEST_SOURCES tests/test_vectors.cpp)
        list(APPEND CATAPULT_TEST_SOURCES tests/test_vectors_c4m.cpp)
    endif()

    add_executable(catapult_tests ${CATAPULT_TEST_SOURCES})

    target_link_libraries(catapult_tests
        catapult
        ${OPENSSL_LIBRARIES}
        cbor
        doctest::doctest
    )

    target_include_directories(catapult_tests PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_compile_definitions(catapult_tests PRIVATE
        TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/test_data")

    if(CATAPULT_ENABLE_JSON AND TARGET nlohmann_json::nlohmann_json)
        target_link_libraries(catapult_tests nlohmann_json::nlohmann_json)
    endif()

    # Apply same security flags to tests
    target_compile_options(catapult_tests PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -Wpedantic>
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fstack-protector-strong>
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /GS>
    )

    if(CATAPULT_ENABLE_WERROR)
        target_compile_options(catapult_tests PRIVATE
            $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:${CATAPULT_WERROR_FLAGS}>
            $<$<CXX_COMPILER_ID:MSVC>:/WX>
        )
    endif()

    # Add test
    add_test(NAME catapult_unit_tests COMMAND catapult_tests)

    # Create benchmark executable (if Google Benchmark is available)
    if(benchmark_FOUND)
        add_executable(catapult_benchmarks
            benchmarks/benchmark_main.cpp
            benchmarks/base64_bench.cpp
            benchmarks/trie_bench.cpp
            benchmarks/memory_pool_bench.cpp
            benchmarks/secure_vector_bench.cpp
            benchmarks/cbor_bench.cpp
            benchmarks/crypto_bench.cpp
            benchmarks/token_bench.cpp
            benchmarks/cwt_validation_bench.cpp
        )
        
        target_link_libraries(catapult_benchmarks
            catapult
            benchmark::benchmark
        )
    
        # Optionally add benchmark as a test (though it's primarily for performance measurement)
        # add_test(NAME catapult_benchmarks COMMAND catapult_benchmarks)
    endif()

    # Example executables
    if(CATAPULT_ENABLE_JSON)
        add_executable(cat_token_json_example
                examples/cat_token_json_example.cpp
        )
        target_link_libraries(cat_token_json_example catapult)
    endif()


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

    add_executable(moqt_dpop_example
            examples/moqt_dpop_example.cpp
    )

    target_link_libraries(moqt_dpop_example catapult)

    # Focused scenario examples
    add_executable(server_token_issuance examples/server_token_issuance.cpp)
    target_link_libraries(server_token_issuance catapult)

    add_executable(client_token_usage examples/client_token_usage.cpp)
    target_link_libraries(client_token_usage catapult)

    add_executable(relay_token_validation examples/relay_token_validation.cpp)
    target_link_libraries(relay_token_validation catapult)

    # Performance tests (using Catch2)
    find_package(Catch2 3 QUIET)
    if(Catch2_FOUND)
        add_executable(catapult_perf_tests tests/performance.cpp)
        target_link_libraries(catapult_perf_tests catapult Catch2::Catch2WithMain)
        add_test(NAME catapult_performance_tests COMMAND catapult_perf_tests)
    endif()
endif()
