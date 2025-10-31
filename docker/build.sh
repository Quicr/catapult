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

# Configure build
echo "Configuring build with CMake..."
cmake \
    -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}" \
    -DCMAKE_CXX_STANDARD=20 \
    -DENABLE_TRIE_MEMORY_POOL="${ENABLE_TRIE_MEMORY_POOL:-ON}" \
    -DENABLE_LOGGING="${ENABLE_LOGGING:-ON}" \
    -DBUILD_TESTING=ON \
    -DBUILD_BENCHMARKS=ON \
    "${PROJECT_ROOT}"

# Build project
echo "Building project..."
make -j"${PARALLEL_JOBS}"

echo "=== Build completed successfully ==="