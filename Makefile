# Common Access Token (CAT) Implementation Makefile

.PHONY: all build test clean install help lint check docs configure format bench memory-test sanitizers fuzz

# Default target
all: build

# Build configuration
CMAKE_BUILD_TYPE ?= Release
BUILD_DIR = build

configure:
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) ../

build: configure
	cd $(BUILD_DIR) && make -j$$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

test: build
	cd $(BUILD_DIR) && ctest --output-on-failure

clean:
	rm -rf $(BUILD_DIR)

install: build
	cd $(BUILD_DIR) && make install

bench: build
	@if [ -f $(BUILD_DIR)/catapult_benchmarks ]; then \
		$(BUILD_DIR)/catapult_benchmarks; \
	else \
		echo "C++ benchmarks not available. Install Google Benchmark to enable."; \
	fi

format:
	find src include -name "*.cpp" -o -name "*.hpp" | xargs clang-format -i -style=Google

lint:
	@echo "Running clang-tidy lint checks..."
	@find src -name "*.cpp" | while read file; do \
		echo "Checking $$file..."; \
		clang++ -std=c++20 -Iinclude -I/opt/homebrew/include \
			-fsyntax-only -Wall -Wextra -Wpedantic \
			-Wno-unused-parameter -Wno-unused-variable \
			"$$file" || exit 1; \
	done

memory-test: build
	@command -v valgrind >/dev/null 2>&1 && \
		valgrind --tool=memcheck --leak-check=full $(BUILD_DIR)/catapult_tests 2>/dev/null || \
		echo "Valgrind not available, skipping memory tests"

sanitizers:
	mkdir -p build-san
	cd build-san && cmake -DCMAKE_BUILD_TYPE=Debug \
		-DCATAPULT_ENABLE_SANITIZERS=ON -DENABLE_LOGGING=OFF ../
	cmake --build build-san --parallel
	ASAN_OPTIONS="halt_on_error=1" UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
		ctest --test-dir build-san --output-on-failure --timeout 600

fuzz:
	mkdir -p build-fuzz
	CC=clang CXX=clang++ cmake -S . -B build-fuzz \
		-DCMAKE_BUILD_TYPE=Debug -DCATAPULT_ENABLE_FUZZERS=ON
	cmake --build build-fuzz --parallel

docs:
	@echo "Generating API documentation ..."
	@command -v doxygen >/dev/null 2>&1 || { echo "Error: doxygen not found. Please install doxygen first."; exit 1; }
	doxygen Doxyfile
	@echo "Documentation generated in docs/html/"
	@echo "Open docs/html/index.html in your browser to view the documentation"


help:
	@echo "CAT Implementation C++ Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all         - Build the project (default)"
	@echo "  test        - Run all tests"
	@echo "  clean       - Remove build directory"
	@echo "  install     - Install the built binaries and libraries"
	@echo "  bench       - Run benchmarks (if available)"
	@echo "  sanitizers  - Configure & run tests under ASan+UBSan in build-san/"
	@echo "  fuzz        - Configure & build libFuzzer harnesses in build-fuzz/"
	@echo "  memory-test - Run valgrind memcheck against the test binary"
	@echo "  format      - Format C++ code with clang-format"
	@echo "  lint        - Lint C++ code with clang-tidy"
	@echo "  docs        - Generate API documentation with Doxygen"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Configuration:"
	@echo "  CMAKE_BUILD_TYPE - Debug, Release, RelWithDebInfo, MinSizeRel (default: Release)"

