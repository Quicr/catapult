cmake_minimum_required(VERSION 3.16)
project(catapult VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ENABLE_LOGGING "Enable logging with spdlog" ON)
option(ENABLE_METRICS "Emit CAT_METRIC_* calls at hot-path instrumentation points" ON)
option(CATAPULT_ENABLE_JSON "Enable JSON serialization support (requires nlohmann_json)" ON)
option(CATAPULT_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(CATAPULT_ENABLE_TSAN "Enable ThreadSanitizer (mutually exclusive with ASan/UBSan)" OFF)
option(CATAPULT_ENABLE_WERROR "Treat compiler warnings as errors in library and test builds" OFF)
option(CATAPULT_ENABLE_LTO "Enable interprocedural optimization (LTO) for library targets" OFF)
option(CATAPULT_ENABLE_FUZZERS "Build libFuzzer harnesses (requires Clang and -fsanitize=fuzzer)" OFF)
option(CATAPULT_INSTALL "Generate install and package-config targets" ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# Dependency management
find_package(OpenSSL REQUIRED)

# Add submodules
# Align libcbor's sanitizer option with ours
set(SANITIZE ${CATAPULT_ENABLE_SANITIZERS} CACHE BOOL "" FORCE)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)

# libcbor: only the static `cbor` target is linked into catapult. Its
# defaults would build ~10 example binaries and emit install rules for
# headers and pkg-config; force them off so an in-tree rebuild does not
# spend time on artefacts we never ship. `EXCLUDE_FROM_ALL` also blocks the
# `install()` calls in the vendored subdirectory from firing when we run
# `cmake --install` on the parent — the whole libcbor artefact set stays
# in the build tree only, and its object files reach the consumer through
# the `$<TARGET_OBJECTS:cbor>` bundling below.
set(WITH_EXAMPLES OFF CACHE BOOL "" FORCE)
set(WITH_TESTS OFF CACHE BOOL "" FORCE)
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY ON CACHE BOOL "" FORCE)
add_subdirectory(external/libcbor EXCLUDE_FROM_ALL)

if(CATAPULT_ENABLE_JSON)
    if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR AND NOT TARGET nlohmann_json::nlohmann_json)
        # Prefer a system-installed nlohmann_json when available so the
        # target we link against is IMPORTED. install(EXPORT) validates
        # that INTERFACE_LINK_LIBRARIES entries are either IMPORTED
        # targets, imported ALIASes, or members of the same export set —
        # an in-tree add_subdirectory() would fail that check because
        # the vendored `nlohmann_json` target is neither imported nor
        # part of catapultTargets. Only fall back to the vendored
        # submodule when no system copy is on CMAKE_PREFIX_PATH.
        find_package(nlohmann_json CONFIG QUIET)
    endif()
    if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR AND NOT TARGET nlohmann_json::nlohmann_json)
        # nlohmann_json is header-only (INTERFACE) so the compiled bloat is
        # already zero, but its own CMake exposes JSON_BuildTests /
        # JSON_Install knobs whose defaults track MAIN_PROJECT. Pin them off
        # so a parent build that flips MAIN_PROJECT (or a future upstream
        # default change) cannot silently pull tests or install rules in.
        set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
        set(JSON_Install OFF CACHE BOOL "" FORCE)
        add_subdirectory(external/nlohmann_json EXCLUDE_FROM_ALL)
        # Record that we resolved JSON from the vendored submodule so the
        # install path can refuse to emit a mangled export set (see
        # CATAPULT_JSON_FROM_VENDORED handling near install(EXPORT)).
        set(CATAPULT_JSON_FROM_VENDORED ON)
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
    src/logging.cpp
    src/metrics.cpp
    src/moqt_claims.cpp
    src/parse_limits.cpp
    src/policy_cache.cpp
    src/reference_policies.cpp
    src/replay_store.cpp
    src/strict_cbor.cpp
    src/token.cpp
    src/trie.cpp
    src/uri.cpp
    src/usage_state.cpp
)

# Add JSON-dependent sources only when JSON is enabled
if(CATAPULT_ENABLE_JSON)
    list(APPEND CATAPULT_SOURCES
        src/json_serialization.cpp
        src/jwk.cpp
    )
endif()

# Bundle cbor's compiled object files directly into libcatapult so the
# installed static archive is self-contained. Without this, catapultTargets
# would carry a link-time reference to `libcbor::libcbor` — a target that
# does not exist in the consumer's build tree because cbor is vendored, not
# installed — and `find_package(catapult)` would fail.
add_library(catapult STATIC ${CATAPULT_SOURCES} $<TARGET_OBJECTS:cbor>)

# Link libraries.
#
# OpenSSL is a genuine PUBLIC dependency — CryptographicAlgorithm and the
# COSE verification paths pull EVP types through the compiled surface, so
# consumers linking against the installed catapult must also link OpenSSL.
# Use the imported targets so the exported catapultTargets.cmake references
# names that `find_dependency(OpenSSL)` will re-materialise on the consumer.
target_link_libraries(catapult
    PUBLIC  OpenSSL::Crypto OpenSSL::SSL
)

# On Windows, inet_pton (used by src/reference_policies.cpp) lives in
# Winsock 2. The symbol is in ws2_32.lib; link it so the catapult target
# resolves. PRIVATE because the dependency is purely an implementation
# detail — the public catapult headers do not re-export Winsock types.
if(WIN32)
    target_link_libraries(catapult PRIVATE ws2_32)
endif()

# libcbor's public headers are consumed by catapult's .cpp files and by
# `internal/cbor_owned.hpp` in the private include path. Ensure the
# compiler can find them during the catapult build without exporting the
# cbor target itself into the install set.
target_include_directories(catapult PRIVATE
    $<BUILD_INTERFACE:$<TARGET_PROPERTY:cbor,INCLUDE_DIRECTORIES>>
)

# nlohmann_json is header-only and appears in catapult's public headers
# (json_serialization.hpp, jwk.hpp) when JSON is enabled, so it must
# propagate through the INTERFACE for both build-tree and installed
# consumers.
#
# Split the reference between BUILD_INTERFACE and INSTALL_INTERFACE:
#
#   - BUILD_INTERFACE picks up the vendored `nlohmann_json::nlohmann_json`
#     target defined by external/nlohmann_json/CMakeLists.txt.
#   - INSTALL_INTERFACE emits the bare target name into the exported
#     catapultTargets.cmake. The corresponding `find_dependency(nlohmann_json)`
#     block in catapultConfig.cmake.in re-imports that target on the
#     consumer side before catapultTargets.cmake is loaded, so the
#     reference resolves cleanly on a fresh toolchain.
#
# The BUILD_INTERFACE / INSTALL_INTERFACE split also lets install(EXPORT)
# succeed — a straight `target_link_libraries(... PUBLIC nlohmann_json::nlohmann_json)`
# fails because the vendored target is not itself part of the export set.
if(CATAPULT_ENABLE_JSON AND TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(catapult
        PUBLIC
            $<BUILD_INTERFACE:nlohmann_json::nlohmann_json>
            $<INSTALL_INTERFACE:nlohmann_json::nlohmann_json>
    )
    target_compile_definitions(catapult PUBLIC CATAPULT_ENABLE_JSON)
endif()

# Set up include directories for the library.
# BUILD_INTERFACE points at the in-tree headers; INSTALL_INTERFACE points at
# the installed layout so consumers using `find_package(catapult)` pick up
# `<prefix>/include` rather than the build tree.
#
# ${OPENSSL_INCLUDE_DIR} is deliberately wrapped in $<BUILD_INTERFACE:...>.
# Without that wrapper, `install(EXPORT)` bakes the build-machine's absolute
# OpenSSL path (e.g. `/opt/homebrew/Cellar/openssl@3/3.6.3/include`) into
# the installed `catapultTargets.cmake`. A consumer on another machine
# would then inherit a nonexistent include path. On the consumer side,
# `find_dependency(OpenSSL)` in `catapultConfig.cmake.in` re-imports
# `OpenSSL::Crypto` and `OpenSSL::SSL`, whose own INTERFACE properties
# carry the correct include directories for the consumer's environment.
target_include_directories(catapult
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        $<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIR}>
)

# Version metadata so ABI-breaking releases can rev SOVERSION independently
# of the marketing version. Static libraries do not honour SOVERSION at link
# time, but tooling (packagers, SBOM producers) reads the property to record
# the ABI generation.
set_target_properties(catapult PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Logging.
#
# The library owns only the log-sink seam (LogSink + CAT_LOG_* macros).
# Embedders wire their own logger by installing a sink at startup. The
# core catapult archive therefore does not depend on spdlog — that
# dependency is now optional and only pulled in when a build asks for
# the spdlog adapter. Rationale is in include/catapult/logging.hpp.
if(ENABLE_LOGGING)
    target_compile_definitions(catapult PUBLIC ENABLE_LOGGING)
endif()

# Metrics.
#
# Same shape as ENABLE_LOGGING: the library owns the sink seam and the
# CAT_METRIC_* macros. Embedders wire their own metric backend by
# installing a MetricsSink at startup. When OFF the macros expand to
# no-ops and the hot-path instrumentation is a hard zero.
if(ENABLE_METRICS)
    target_compile_definitions(catapult PUBLIC ENABLE_METRICS)
endif()

# Windows / MSVC hygiene. These are PUBLIC so downstream consumers that
# transitively include our headers (which pull in <windows.h>) also get
# the hygiene. Without them, the Windows SDK leaks a long tail of macros
# that break portable C++ identifiers used throughout catapult:
#   NOMINMAX              - keeps min/max macros out of std::numeric_limits
#                           and std::min/std::max call sites.
#   NOGDI                 - keeps wingdi.h out, which otherwise defines
#                           ERROR, DELETE, IN, OUT, OPTIONAL as macros
#                           and breaks every scoped-enum member or local
#                           named with the same identifier (e.g.
#                           LogLevel::ERROR).
#   WIN32_LEAN_AND_MEAN   - trims the system-header fan-in to the subset
#                           catapult actually depends on.
if(WIN32)
    target_compile_definitions(catapult PUBLIC
        NOMINMAX
        NOGDI
        WIN32_LEAN_AND_MEAN
    )
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

# ENABLE_LOGGING propagation moved into the LogSink block above and made
# PUBLIC so consumers including <catapult/logging.hpp> see the macros
# expand.

# ---------------------------------------------------------------------------
# Install & package-config
# ---------------------------------------------------------------------------
#
# `CATAPULT_INSTALL` gates the install() calls so a parent build embedding
# catapult via add_subdirectory() can opt out and avoid dragging our
# artefacts into its own `cmake --install` output.
#
# Vendored submodules (cbor, nlohmann_json) are pinned upstream to NOT
# emit install rules (see the CACHE FORCE lines above), so the install
# set covers only catapult's own headers and the archive built here — a
# consumer is expected to bring their own OpenSSL / cbor via
# `find_package` if needed. The generated package config declares
# `find_dependency(OpenSSL REQUIRED)` explicitly for that reason.
if(CATAPULT_INSTALL AND CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    # install(EXPORT) requires every INTERFACE_LINK_LIBRARIES entry to be
    # either an IMPORTED target or a member of the same export set. If
    # nlohmann_json was resolved from the vendored submodule (no system
    # find_package hit and JSON is on), the resulting target is neither,
    # and CMake would refuse to generate catapultTargets.cmake. That would
    # produce a mangled install that silently omits the JSON dependency
    # contract — refuse the install with a targeted error instead so the
    # operator picks a supported path.
    if(CATAPULT_ENABLE_JSON AND CATAPULT_JSON_FROM_VENDORED)
        message(FATAL_ERROR
            "CATAPULT_ENABLE_JSON=ON was resolved via the vendored "
            "external/nlohmann_json submodule, which cannot appear in "
            "catapult's install export set. Install a system copy of "
            "nlohmann_json (find_package must succeed) or reconfigure "
            "with -DCATAPULT_ENABLE_JSON=OFF before running "
            "`cmake --install`.")
    endif()

    install(TARGETS catapult
        EXPORT catapultTargets
        ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    install(DIRECTORY include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING
            PATTERN "*.hpp"
    )

    set(CATAPULT_CMAKE_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/catapult)

    install(EXPORT catapultTargets
        FILE catapultTargets.cmake
        NAMESPACE catapult::
        DESTINATION ${CATAPULT_CMAKE_INSTALL_DIR}
    )

    configure_package_config_file(
        cmake/catapultConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/catapultConfig.cmake
        INSTALL_DESTINATION ${CATAPULT_CMAKE_INSTALL_DIR}
    )

    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/catapultConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        # SameMajorVersion: within a major, later minors are drop-in compatible;
        # major bumps are the ABI break signal (mirrors SOVERSION above).
        COMPATIBILITY SameMajorVersion
    )

    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/catapultConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/catapultConfigVersion.cmake
        DESTINATION ${CATAPULT_CMAKE_INSTALL_DIR}
    )
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
        add_subdirectory(external/doctest EXCLUDE_FROM_ALL)
    endif()

    # spdlog is no longer a build dependency of tests. Tests use the
    # LogSink seam directly; there is nothing to bring in here.

    # Find Google Benchmark
    find_package(benchmark QUIET)
    if(NOT benchmark_FOUND)
        message(STATUS "Google Benchmark not found, benchmark targets will be disabled")
    endif()

    # Create test executable
    set(CATAPULT_TEST_SOURCES
        tests/main.cpp
        tests/authorization_policy.cpp
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
        tests/reference_policies.cpp
        tests/replay_store.cpp
        tests/revalidation_callback.cpp
        tests/uri_catu.cpp
        tests/secure_vector.cpp
        tests/strict_cbor.cpp
        tests/token.cpp
        tests/token_factory.cpp
        tests/trie.cpp
        tests/usage_state.cpp
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
            benchmarks/hot_path_bench.cpp
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

    # Examples link against catapult only. `ENABLE_LOGGING` propagates
    # as a PUBLIC compile definition from libcatapult, so the CAT_LOG_*
    # macros expand correctly here without any per-target wiring.
    target_link_libraries(cat_cwt_per_signature_example catapult)

    add_executable(cat_cwt_crypto
            examples/cat_cwt_crypto.cpp
    )

    target_link_libraries(cat_cwt_crypto catapult)

    add_executable(moqt_dpop_example
            examples/moqt_dpop_example.cpp
    )

    target_link_libraries(moqt_dpop_example catapult)

    # PS256 is demonstrated by the existing examples:
    #   * cat_cwt_crypto --sign  — signs the same CAT token with ES256 and PS256
    #   * moqt_dpop_example      — accepts --alg=ES256|PS256 and
    #                              --encoding=cwt|jwt (or --all for every combo)
    # No PS256-specific example targets.

    # Focused scenario examples
    add_executable(server_token_issuance examples/server_token_issuance.cpp)
    target_link_libraries(server_token_issuance catapult)

    add_executable(client_token_usage examples/client_token_usage.cpp)
    target_link_libraries(client_token_usage catapult)

    add_executable(relay_token_validation examples/relay_token_validation.cpp)
    target_link_libraries(relay_token_validation catapult)

    # Fleet-adapter integration example. Demonstrates the ReplayStore /
    # UsageStateHook / PolicyCache seam a multi-relay production
    # deployment must fill in; not a production adapter itself.
    add_executable(fleet_adapter_integration
            examples/fleet_adapter_integration.cpp)
    target_link_libraries(fleet_adapter_integration catapult)

    # CDN-scale load harness. Runs the full CAT+DPoP admission hot path
    # under an N-worker workload and emits p50/p95/p99 latency + throughput
    # + a rejection taxonomy. See Gate 8 in the production-readiness plan.
    #
    # The harness computes JWK thumbprints via `jwk::calculateJWKThumbprint`
    # and `DpopKeyPair::get_public_key_jwk`, which are only available when
    # `CATAPULT_ENABLE_JSON` is on. Gate the executable accordingly so
    # sanitizer / fuzz builds (which disable JSON to keep the crypto
    # surface small) still configure cleanly.
    if(CATAPULT_ENABLE_JSON)
        add_executable(catapult_load_harness perf/load_harness.cpp)
        target_link_libraries(catapult_load_harness catapult)
    endif()

    # Performance tests (using Catch2)
    find_package(Catch2 3 QUIET)
    if(Catch2_FOUND)
        add_executable(catapult_perf_tests tests/performance.cpp)
        target_link_libraries(catapult_perf_tests catapult Catch2::Catch2WithMain)
        add_test(NAME catapult_performance_tests COMMAND catapult_perf_tests)
    endif()

    # libFuzzer harnesses. Gated on Clang since -fsanitize=fuzzer is a
    # Clang/LLVM feature; other toolchains would silently link a stub.
    #
    # Apple's system clang (Xcode / AppleClang) does not ship the libFuzzer
    # runtime (libclang_rt.fuzzer_osx.a). Detect that up front and emit an
    # actionable error pointing the user at a Homebrew LLVM toolchain, whose
    # compiler-rt package does include the fuzzer runtime. Homebrew LLVM
    # reports CMAKE_CXX_COMPILER_ID = "Clang" (not "AppleClang"), so this
    # check only fires on the system compiler.
    if(CATAPULT_ENABLE_FUZZERS)
        if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
            message(FATAL_ERROR
                "CATAPULT_ENABLE_FUZZERS requires Clang "
                "(current: ${CMAKE_CXX_COMPILER_ID}).")
        endif()
        if(APPLE AND CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
            message(FATAL_ERROR
                "CATAPULT_ENABLE_FUZZERS on macOS requires Homebrew LLVM.\n"
                "Apple's system clang does not ship the libFuzzer runtime "
                "(libclang_rt.fuzzer_osx.a). Install LLVM via Homebrew and "
                "point CMake at it, e.g.:\n"
                "  brew install llvm\n"
                "  cmake -S . -B build-fuzz \\\n"
                "    -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang \\\n"
                "    -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++ \\\n"
                "    -DCATAPULT_ENABLE_FUZZERS=ON")
        endif()
        add_subdirectory(fuzz)
    endif()
endif()
