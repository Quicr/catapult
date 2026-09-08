# libFuzzer harnesses. Enabled by CATAPULT_ENABLE_FUZZERS; Clang-only because
# -fsanitize=fuzzer is a Clang/LLVM feature. The parent CMakeLists enforces
# that gate before add_subdirectory'ing us.
#
# ASan/UBSan flags are not duplicated here — enable them via
# CATAPULT_ENABLE_SANITIZERS, which propagates -fsanitize=address,undefined
# through the catapult target's PUBLIC options. This harness layer only
# adds the libFuzzer driver flag, which is exe-local.

set(CATAPULT_FUZZ_FLAGS
    -fsanitize=fuzzer
    -fno-omit-frame-pointer
)

set(CATAPULT_FUZZ_TARGETS
    fuzz_strict_cbor
    fuzz_cwt_decode_payload
    fuzz_cwt_header
    fuzz_base64url
    fuzz_dpop_deserialize
)

# Meta-target so CI can build all harnesses with one call.
add_custom_target(catapult_fuzz_all)

foreach(fuzz_target ${CATAPULT_FUZZ_TARGETS})
    add_executable(${fuzz_target} ${fuzz_target}.cpp)
    target_link_libraries(${fuzz_target} PRIVATE catapult)
    target_include_directories(${fuzz_target}
        PRIVATE ${CMAKE_SOURCE_DIR}/include
    )
    target_compile_options(${fuzz_target} PRIVATE ${CATAPULT_FUZZ_FLAGS})
    target_link_options(${fuzz_target} PRIVATE ${CATAPULT_FUZZ_FLAGS})
    add_dependencies(catapult_fuzz_all ${fuzz_target})
endforeach()
