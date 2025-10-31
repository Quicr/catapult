#!/bin/bash
set -euo pipefail

# Docker Build Wrapper Script

PLATFORM="${1:-alpine}"
CLEAN="${CLEAN:-false}"

case "$PLATFORM" in
    x86_64|alpine|amd64)
        SERVICE="alpine-build"
        IMAGE="catapult:alpine-latest"
        ;;
    raspberrypi|rpi|arm64)
        SERVICE="raspberrypi-build"
        IMAGE="catapult:raspberrypi-arm64"
        ;;
    *)
        echo "Usage: $0 [alpine|raspberrypi]"
        echo "  alpine/amd64 - Build for Alpine x86_64 (default)"
        echo "  raspberrypi   - Build for Raspberry Pi ARM64"
        exit 1
        ;;
esac

echo "=== Building Catapult for $PLATFORM ==="

# Build the Docker image
echo "Building Docker image..."
docker-compose build "$SERVICE"

# Run the build
echo "Running build in container..."
if [[ "$CLEAN" == "true" ]]; then
    docker-compose run --rm -e CLEAN_BUILD=true "$SERVICE" /workspace/docker/build.sh
else
    docker-compose run --rm "$SERVICE" /workspace/docker/build.sh
fi

echo "=== Build completed for $PLATFORM ==="
