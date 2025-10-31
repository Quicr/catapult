#!/bin/bash
set -euo pipefail

# CAT MOQT Benchmark Script
# Runs performance benchmarks with various configurations

PROJECT_ROOT="/workspace"
BUILD_DIR="${PROJECT_ROOT}/build"
BENCHMARK_REPORTS_DIR="${PROJECT_ROOT}/benchmark-reports"
BENCHMARK_TIMEOUT="${BENCHMARK_TIMEOUT:-600}"
BENCHMARK_RUNS="${BENCHMARK_RUNS:-3}"
GENERATE_REPORT="${GENERATE_REPORT:-false}"
ENABLE_MEMORY_PROFILING="${ENABLE_MEMORY_PROFILING:-false}"

echo "=== CAT MOQT Benchmark Script ==="
echo "Benchmark Timeout: ${BENCHMARK_TIMEOUT}s"
echo "Benchmark Runs: ${BENCHMARK_RUNS}"
echo "Generate Report: ${GENERATE_REPORT}"
echo "Memory Profiling: ${ENABLE_MEMORY_PROFILING}"

# Ensure build exists
if [[ ! -d "${BUILD_DIR}" ]]; then
    echo "Build directory not found. Running build first..."
    "${PROJECT_ROOT}/docker/build.sh"
fi

cd "${BUILD_DIR}"

# Create benchmark reports directory
if [[ "${GENERATE_REPORT}" == "true" ]]; then
    mkdir -p "${BENCHMARK_REPORTS_DIR}"
fi

# Run main benchmark suite
echo "Running main benchmark suite..."
for benchmark_binary in catapult_benchmarks composite_claims_bench; do
    if [[ -f "${benchmark_binary}" ]]; then
        echo "Running ${benchmark_binary}..."
        
        # Basic benchmark run
        if [[ "${GENERATE_REPORT}" == "true" ]]; then
            timeout "${BENCHMARK_TIMEOUT}" "./${benchmark_binary}" \
                --benchmark_repetitions="${BENCHMARK_RUNS}" \
                --benchmark_format=json \
                --benchmark_out="${BENCHMARK_REPORTS_DIR}/${benchmark_binary}-results.json" \
                --benchmark_display_aggregates_only=true || echo "Benchmark failed for ${benchmark_binary}"
        else
            timeout "${BENCHMARK_TIMEOUT}" "./${benchmark_binary}" \
                --benchmark_repetitions="${BENCHMARK_RUNS}" \
                --benchmark_display_aggregates_only=true || echo "Benchmark failed for ${benchmark_binary}"
        fi
        
        # Memory profiling if enabled
        if [[ "${ENABLE_MEMORY_PROFILING}" == "true" ]] && command -v valgrind >/dev/null 2>&1; then
            echo "Running memory profiling for ${benchmark_binary}..."
            if [[ "${GENERATE_REPORT}" == "true" ]]; then
                timeout "${BENCHMARK_TIMEOUT}" valgrind --tool=massif \
                    --massif-out-file="${BENCHMARK_REPORTS_DIR}/${benchmark_binary}-massif.out" \
                    "./${benchmark_binary}" --benchmark_min_time=1 || echo "Memory profiling failed for ${benchmark_binary}"
            else
                timeout "${BENCHMARK_TIMEOUT}" valgrind --tool=massif \
                    "./${benchmark_binary}" --benchmark_min_time=1 || echo "Memory profiling failed for ${benchmark_binary}"
            fi
        fi
    else
        echo "Warning: ${benchmark_binary} not found, skipping..."
    fi
done

# Run custom benchmarks if available
if [[ -f "test_cbor_dpop" ]]; then
    echo "Running CBOR DPoP benchmark..."
    if [[ "${GENERATE_REPORT}" == "true" ]]; then
        timeout "${BENCHMARK_TIMEOUT}" "./test_cbor_dpop" > "${BENCHMARK_REPORTS_DIR}/cbor-dpop-results.txt" || echo "CBOR DPoP benchmark failed"
    else
        timeout "${BENCHMARK_TIMEOUT}" "./test_cbor_dpop" || echo "CBOR DPoP benchmark failed"
    fi
fi

echo "=== Benchmark execution completed ==="