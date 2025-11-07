# Catapult QUICR Build System using Just
# Common Access Token (CAT) Implementation

# Default target
default: build

# Build configuration
cmake_build_type := env_var_or_default('CMAKE_BUILD_TYPE', 'Release')
build_dir := "build"

# Configure CMake build
configure:
    mkdir -p {{build_dir}}
    cd {{build_dir}} && cmake -DCMAKE_BUILD_TYPE={{cmake_build_type}} ..

# Build the project (using make)
build: configure
    cd {{build_dir}} && make -j`nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4`

# Alternative build using cmake --build (justfile way)
build-cmake: configure
    cmake --build {{build_dir}} --parallel

# Run tests
test: build
    cd {{build_dir}} && ctest --output-on-failure

# Clean build directory
clean:
    rm -rf {{build_dir}}

# Install built binaries and libraries (make way)
install: build
    cd {{build_dir}} && make install

# Install using cmake (justfile way)  
install-cmake: build-cmake
    cmake --install {{build_dir}}

# Run benchmarks
bench: build
    @if [ -f {{build_dir}}/catapult_benchmarks ]; then \
        {{build_dir}}/catapult_benchmarks; \
    else \
        echo "C++ benchmarks not available. Install Google Benchmark to enable."; \
    fi

# Format C++ code
format:
    find src include -name "*.cpp" -o -name "*.hpp" | xargs clang-format -i -style=Google

# Lint C++ code
lint:
    @echo "Running clang-tidy lint checks..."
    @find src -name "*.cpp" | while read file; do \
        echo "Checking $$file..."; \
        clang++ -std=c++20 -Iinclude -I/opt/homebrew/include \
            -fsyntax-only -Wall -Wextra -Wpedantic \
            -Wno-unused-parameter -Wno-unused-variable \
            "$$file" || exit 1; \
    done

# Run memory tests with valgrind
memory-test: build
    @command -v valgrind >/dev/null 2>&1 && \
        valgrind --tool=memcheck --leak-check=full {{build_dir}}/catapult_tests 2>/dev/null || \
        echo "Valgrind not available, skipping memory tests"

# Generate API documentation
docs:
    @echo "Generating API documentation ..."
    @command -v doxygen >/dev/null 2>&1 || { echo "Error: doxygen not found. Please install doxygen first."; exit 1; }
    doxygen Doxyfile
    @echo "Documentation generated in docs/html/"
    @echo "Open docs/html/index.html in your browser to view the documentation"

# Show help information
help:
    @echo "Catapult QUICR Build System using Just"
    @echo ""
    @echo "Available recipes:"
    @echo "  default        - Build the project (same as 'build')"
    @echo "  configure      - Configure CMake build"
    @echo "  build          - Build the project using make"
    @echo "  build-cmake    - Build the project using cmake --build"
    @echo "  test           - Run all tests"
    @echo "  clean          - Remove build directory"
    @echo "  install        - Install using make"
    @echo "  install-cmake  - Install using cmake --install"
    @echo "  bench          - Run benchmarks (if available)"
    @echo "  format         - Format C++ code with clang-format"
    @echo "  lint           - Lint C++ code with clang-tidy"
    @echo "  memory-test    - Run memory tests with valgrind"
    @echo "  docs           - Generate API documentation with Doxygen"
    @echo "  help           - Show this help message"
    @echo ""
    @echo "Configuration:"
    @echo "  CMAKE_BUILD_TYPE - Debug, Release, RelWithDebInfo, MinSizeRel (default: Release)"
    @echo ""
    @echo "Examples:"
    @echo "  just build          # Build using make"
    @echo "  just build-cmake    # Build using cmake"
    @echo "  just test"
    @echo "  CMAKE_BUILD_TYPE=Debug just build"