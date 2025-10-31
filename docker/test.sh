#!/bin/bash
set -euo pipefail

# CAT MOQT Test Script
# Runs all tests with various configurations

PROJECT_ROOT="/workspace"
BUILD_DIR="${PROJECT_ROOT}/build"
TEST_REPORTS_DIR="${PROJECT_ROOT}/test-reports"
VERBOSE="${VERBOSE:-false}"
TEST_TIMEOUT="${TEST_TIMEOUT:-300}"
ENABLE_MEMORY_TESTS="${ENABLE_MEMORY_TESTS:-false}"
ENABLE_PERFORMANCE_TESTS="${ENABLE_PERFORMANCE_TESTS:-false}"
GENERATE_REPORT="${GENERATE_REPORT:-false}"

echo "=== CAT MOQT Test Script ==="
echo "Test Timeout: ${TEST_TIMEOUT}s"
echo "Memory Tests: ${ENABLE_MEMORY_TESTS}"
echo "Performance Tests: ${ENABLE_PERFORMANCE_TESTS}"
echo "Generate Report: ${GENERATE_REPORT}"

# Ensure build exists
if [[ ! -d "${BUILD_DIR}" ]]; then
    echo "Build directory not found. Running build first..."
    "${PROJECT_ROOT}/docker/build.sh"
fi

cd "${BUILD_DIR}"

# Create test reports directory
if [[ "${GENERATE_REPORT}" == "true" ]]; then
    mkdir -p "${TEST_REPORTS_DIR}"
fi

# Run basic tests
echo "Running basic tests..."
if [[ "${VERBOSE}" == "true" ]]; then
    CTEST_ARGS="--verbose --output-on-failure"
else
    CTEST_ARGS="--output-on-failure"
fi

if [[ "${GENERATE_REPORT}" == "true" ]]; then
    ctest ${CTEST_ARGS} --timeout "${TEST_TIMEOUT}" --output-junit "${TEST_REPORTS_DIR}/test-results.xml"
else
    ctest ${CTEST_ARGS} --timeout "${TEST_TIMEOUT}"
fi

# Run memory tests if enabled
if [[ "${ENABLE_MEMORY_TESTS}" == "true" ]] && command -v valgrind >/dev/null 2>&1; then
    echo "Running memory tests with Valgrind..."
    for test_binary in cat_tests integration_tests; do
        if [[ -f "${test_binary}" ]]; then
            echo "Memory testing ${test_binary}..."
            if [[ "${GENERATE_REPORT}" == "true" ]]; then
                valgrind --tool=memcheck --leak-check=full --xml=yes \
                    --xml-file="${TEST_REPORTS_DIR}/${test_binary}-memcheck.xml" \
                    "./${test_binary}" || echo "Memory test failed for ${test_binary}"
            else
                valgrind --tool=memcheck --leak-check=full "./${test_binary}" || echo "Memory test failed for ${test_binary}"
            fi
        fi
    done
elif [[ "${ENABLE_MEMORY_TESTS}" == "true" ]]; then
    echo "Warning: Valgrind not available, skipping memory tests"
fi

# Run performance tests if enabled
if [[ "${ENABLE_PERFORMANCE_TESTS}" == "true" ]]; then
    echo "Running performance tests..."
    for bench_binary in catapult_benchmarks composite_claims_bench; do
        if [[ -f "${bench_binary}" ]]; then
            echo "Running ${bench_binary}..."
            if [[ "${GENERATE_REPORT}" == "true" ]]; then
                "./${bench_binary}" --benchmark_format=json --benchmark_out="${TEST_REPORTS_DIR}/${bench_binary}-results.json" || echo "Performance test failed for ${bench_binary}"
            else
                "./${bench_binary}" || echo "Performance test failed for ${bench_binary}"
            fi
        fi
    done
fi

echo "=== Test execution completed ==="