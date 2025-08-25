cmake_minimum_required(VERSION 3.16)
project(catapult VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ENABLE_LOGGING "Enable logging with spdlog" ON)

# Dependency management
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)
# Check for libcbor
pkg_check_modules(CBOR REQUIRED libcbor)
link_directories(${CBOR_LIBRARY_DIRS})

# Include directories
include_directories(include)
include_directories(${CBOR_INCLUDE_DIRS})

# Create library
add_library(catapult STATIC
    src/cat_base64.cpp
)

# Link libraries
target_link_libraries(catapult 
    ${CBOR_LIBRARIES}
    OpenSSL::SSL 
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

# Add spdlog if logging is enabled
if(ENABLE_LOGGING)
    target_link_libraries(catapult spdlog::spdlog)
endif()
target_link_directories(catapult PRIVATE ${CBOR_LIBRARY_DIRS})

# Set compiler flags with enhanced security and warnings
target_compile_options(catapult PRIVATE 
    ${CBOR_CFLAGS_OTHER}
    # Enhanced warning flags for better code quality
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
    tests/test_base64.cpp
)

target_link_libraries(catapult_tests 
    catapult
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
    )
    
    target_link_libraries(catapult_benchmarks
        catapult
        benchmark::benchmark
        benchmark::benchmark_main
    )
    
    # Optionally add benchmark as a test (though it's primarily for performance measurement)
    # add_test(NAME catapult_benchmarks COMMAND catapult_benchmarks)
endif()

