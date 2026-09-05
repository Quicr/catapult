#!/bin/bash
set -euo pipefail

# CAT MOQT Build Script
# Builds the project using CMake with optimized configuration

PROJECT_ROOT="/workspace"
BUILD_DIR="${PROJECT_ROOT}/build"
PARALLEL_JOBS="${PARALLEL_JOBS:-4}"
if command -v nproc >/dev/null 2>&1; then
    PARALLEL_JOBS="$(nproc)"
fi
CMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-Release}"
COMPILER="${COMPILER:-gcc}"

echo "=== CAT MOQT Build Script ==="
echo "Build Type: ${CMAKE_BUILD_TYPE}"
echo "Compiler: ${COMPILER}"
echo "Parallel Jobs: ${PARALLEL_JOBS}"
echo "Build Directory: ${BUILD_DIR}"

# Clean previous build if requested
if [[ "${CLEAN_BUILD:-false}" == "true" ]]; then
    echo "Cleaning previous build..."
    rm -rf "${BUILD_DIR}"
fi

# Create build directory
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Configure build. Options here must match those declared in the top-level
# CMakeLists; stale flags (ENABLE_TRIE_MEMORY_POOL, BUILD_TESTING,
# BUILD_BENCHMARKS) were silently ignored by CMake and hid the fact that
# this script had drifted from the source tree.
echo "Configuring build with CMake..."
cmake \
    -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}" \
    -DCMAKE_CXX_STANDARD=20 \
    -DENABLE_LOGGING="${ENABLE_LOGGING:-ON}" \
    -DCATAPULT_ENABLE_JSON="${CATAPULT_ENABLE_JSON:-ON}" \
    -DCATAPULT_ENABLE_WERROR="${CATAPULT_ENABLE_WERROR:-OFF}" \
    -DCATAPULT_ENABLE_LTO="${CATAPULT_ENABLE_LTO:-OFF}" \
    -DCATAPULT_ENABLE_SANITIZERS="${CATAPULT_ENABLE_SANITIZERS:-OFF}" \
    -DCATAPULT_ENABLE_TSAN="${CATAPULT_ENABLE_TSAN:-OFF}" \
    "${PROJECT_ROOT}"

# Build project
echo "Building project..."
make -j"${PARALLEL_JOBS}"

echo "=== Build completed successfully ==="