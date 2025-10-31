#!/bin/bash
set -euo pipefail

# Catapult Static Analysis Script
# Runs various static analysis tools on the codebase

PROJECT_ROOT="/workspace"
BUILD_DIR="${PROJECT_ROOT}/build"
ANALYSIS_REPORTS_DIR="${PROJECT_ROOT}/analysis-reports"
GENERATE_REPORT="${GENERATE_REPORT:-false}"
ENABLE_SECURITY_ANALYSIS="${ENABLE_SECURITY_ANALYSIS:-false}"
ENABLE_INCLUDE_ANALYSIS="${ENABLE_INCLUDE_ANALYSIS:-false}"

echo "=== Catapult Static Analysis Script ==="
echo "Generate Report: ${GENERATE_REPORT}"
echo "Security Analysis: ${ENABLE_SECURITY_ANALYSIS}"
echo "Include Analysis: ${ENABLE_INCLUDE_ANALYSIS}"

# Ensure build exists
if [[ ! -d "${BUILD_DIR}" ]]; then
    echo "Build directory not found. Running build first..."
    "${PROJECT_ROOT}/docker/build.sh"
fi

cd "${PROJECT_ROOT}"

# Create analysis reports directory
if [[ "${GENERATE_REPORT}" == "true" ]]; then
    mkdir -p "${ANALYSIS_REPORTS_DIR}"
fi

# Run cppcheck
if command -v cppcheck >/dev/null 2>&1; then
    echo "Running cppcheck static analysis..."
    if [[ "${GENERATE_REPORT}" == "true" ]]; then
        cppcheck --enable=all --std=c++20 --platform=unix64 \
            --xml --xml-version=2 --output-file="${ANALYSIS_REPORTS_DIR}/cppcheck-results.xml" \
            src/ include/ || echo "cppcheck analysis completed with warnings"
    else
        cppcheck --enable=all --std=c++20 --platform=unix64 \
            src/ include/ || echo "cppcheck analysis completed with warnings"
    fi
else
    echo "Warning: cppcheck not available"
fi

# Run clang-tidy
if command -v clang-tidy >/dev/null 2>&1; then
    echo "Running clang-tidy analysis..."
    find src -name "*.cpp" | while read -r file; do
        echo "Analyzing ${file}..."
        if [[ "${GENERATE_REPORT}" == "true" ]]; then
            clang-tidy "${file}" -p="${BUILD_DIR}" \
                --export-fixes="${ANALYSIS_REPORTS_DIR}/$(basename "${file}" .cpp)-fixes.yaml" \
                -- -std=c++20 -Iinclude || echo "clang-tidy completed with warnings for ${file}"
        else
            clang-tidy "${file}" -p="${BUILD_DIR}" \
                -- -std=c++20 -Iinclude || echo "clang-tidy completed with warnings for ${file}"
        fi
    done
else
    echo "Warning: clang-tidy not available"
fi

# Security analysis with additional checks
if [[ "${ENABLE_SECURITY_ANALYSIS}" == "true" ]]; then
    echo "Running security analysis..."
    
    # Check for common security issues
    echo "Checking for potential security issues..."
    if [[ "${GENERATE_REPORT}" == "true" ]]; then
        {
            echo "=== Security Analysis Report ==="
            echo "Generated: $(date)"
            echo ""
            
            echo "--- Potential Buffer Overflows ---"
            grep -rn "strcpy\|strcat\|sprintf\|gets" src/ include/ || echo "None found"
            echo ""
            
            echo "--- Potential Format String Vulnerabilities ---"
            grep -rn "printf.*%.*\"\|fprintf.*%.*\"" src/ include/ || echo "None found"
            echo ""
            
            echo "--- Potential Integer Overflows ---"
            grep -rn "malloc\|calloc\|realloc" src/ include/ || echo "None found"
            echo ""
            
            echo "--- Hardcoded Credentials/Keys ---"
            grep -rn "password\|secret\|key.*=" src/ include/ || echo "None found"
            echo ""
        } > "${ANALYSIS_REPORTS_DIR}/security-analysis.txt"
    else
        echo "Checking for buffer overflows..."
        grep -rn "strcpy\|strcat\|sprintf\|gets" src/ include/ || echo "None found"
        echo "Checking for format string vulnerabilities..."
        grep -rn "printf.*%.*\"\|fprintf.*%.*\"" src/ include/ || echo "None found"
    fi
fi

# Include dependency analysis
if [[ "${ENABLE_INCLUDE_ANALYSIS}" == "true" ]]; then
    echo "Running include dependency analysis..."
    if [[ "${GENERATE_REPORT}" == "true" ]]; then
        {
            echo "=== Include Dependency Analysis ==="
            echo "Generated: $(date)"
            echo ""
            
            echo "--- Header Include Counts ---"
            find include/ -name "*.hpp" | while read -r header; do
                count=$(grep -c "#include" "${header}" 2>/dev/null || echo "0")
                echo "${header}: ${count} includes"
            done | sort -k2 -nr
            echo ""
            
            echo "--- External Dependencies ---"
            grep -rh "#include <" src/ include/ | sort | uniq -c | sort -nr
            echo ""
        } > "${ANALYSIS_REPORTS_DIR}/include-analysis.txt"
    else
        echo "Header include counts:"
        find include/ -name "*.hpp" | while read -r header; do
            count=$(grep -c "#include" "${header}" 2>/dev/null || echo "0")
            echo "${header}: ${count} includes"
        done | sort -k2 -nr | head -10
    fi
fi

echo "=== Static analysis completed ==="
