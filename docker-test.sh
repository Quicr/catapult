#!/bin/bash
set -euo pipefail

# Docker Test Wrapper Script
# Simplifies running tests in Docker containers

PLATFORM="${1:-alpine}"
TEST_TYPE="${2:-basic}"

case "$PLATFORM" in
    alpine|ubuntu|x86_64)
        SERVICE="alpine-build"
        ;;
    raspberrypi|rpi|arm64)
        SERVICE="raspberrypi-build"
        ;;
    *)
        echo "Usage: $0 [alpine|raspberrypi] [basic|memory|performance|all]"
        echo "Platforms:"
        echo "  alpine     - Test on Alpine Linux x86_64 (default)"
        echo "  raspberrypi - Test on Raspberry Pi ARM64"
        echo "Test types:"
        echo "  basic      - Run basic test suite (default)"
        echo "  memory     - Run memory tests with Valgrind"
        echo "  performance - Run performance benchmarks"
        echo "  all        - Run all test types"
        exit 1
        ;;
esac

echo "=== Running CAT MOQT tests for $PLATFORM ($TEST_TYPE) ==="

# Build the Docker image first
echo "Ensuring Docker image is built..."
docker-compose build "$SERVICE"

case "$TEST_TYPE" in
    basic)
        echo "Running basic tests..."
        docker-compose run --rm "$SERVICE" /workspace/docker/test.sh
        ;;
    memory)
        echo "Running memory tests..."
        docker-compose run --rm -e ENABLE_MEMORY_TESTS=true -e GENERATE_REPORT=true "$SERVICE" /workspace/docker/test.sh
        ;;
    performance)
        echo "Running performance tests..."
        docker-compose run --rm -e ENABLE_PERFORMANCE_TESTS=true -e GENERATE_REPORT=true "$SERVICE" /workspace/docker/test.sh
        docker-compose run --rm "$SERVICE" /workspace/docker/benchmark.sh
        ;;
    all)
        echo "Running all tests..."
        docker-compose run --rm -e ENABLE_MEMORY_TESTS=true -e ENABLE_PERFORMANCE_TESTS=true -e GENERATE_REPORT=true "$SERVICE" /workspace/docker/test.sh
        docker-compose run --rm -e GENERATE_REPORT=true "$SERVICE" /workspace/docker/benchmark.sh
        docker-compose run --rm -e GENERATE_REPORT=true -e ENABLE_SECURITY_ANALYSIS=true -e ENABLE_INCLUDE_ANALYSIS=true "$SERVICE" /workspace/docker/analyze.sh
        ;;
    *)
        echo "Unknown test type: $TEST_TYPE"
        echo "Valid types: basic, memory, performance, all"
        exit 1
        ;;
esac

echo "=== Test execution completed for $PLATFORM ==="