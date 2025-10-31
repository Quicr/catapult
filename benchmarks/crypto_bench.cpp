#include <benchmark/benchmark.h>
#include "catapult/crypto.hpp"
#include <vector>
#include <string>

using namespace catapult;

// Test data of different sizes
static const std::vector<uint8_t> SMALL_DATA = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21}; // "Hello, World!"
static std::vector<uint8_t> CreateMediumData() {
    std::string data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.";
    return std::vector<uint8_t>(data.begin(), data.end());
}
static const std::vector<uint8_t> LARGE_DATA(1024, 0x42);

// HMAC256 Benchmarks
static void BM_HMAC_KeyGeneration(benchmark::State& state) {
    for (auto _ : state) {
        auto key = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
        benchmark::DoNotOptimize(key);
    }
}
BENCHMARK(BM_HMAC_KeyGeneration);

static void BM_HMAC_Sign_Small(benchmark::State& state) {
    auto key = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    HmacSha256Algorithm hmac(key);
    
    for (auto _ : state) {
        auto signature = hmac.sign(SMALL_DATA);
        benchmark::DoNotOptimize(signature);
    }
}
BENCHMARK(BM_HMAC_Sign_Small);

static void BM_HMAC_Sign_Medium(benchmark::State& state) {
    auto key = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    HmacSha256Algorithm hmac(key);
    auto medium_data = CreateMediumData();
    
    for (auto _ : state) {
        auto signature = hmac.sign(medium_data);
        benchmark::DoNotOptimize(signature);
    }
}
BENCHMARK(BM_HMAC_Sign_Medium);

static void BM_HMAC_Sign_Large(benchmark::State& state) {
    auto key = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    HmacSha256Algorithm hmac(key);
    
    for (auto _ : state) {
        auto signature = hmac.sign(LARGE_DATA);
        benchmark::DoNotOptimize(signature);
    }
}
BENCHMARK(BM_HMAC_Sign_Large);

static void BM_HMAC_Verify_Small(benchmark::State& state) {
    auto key = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    HmacSha256Algorithm hmac(key);
    auto signature = hmac.sign(SMALL_DATA);
    
    for (auto _ : state) {
        bool result = hmac.verify(SMALL_DATA, signature);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_HMAC_Verify_Small);

static void BM_HMAC_Verify_Medium(benchmark::State& state) {
    auto key = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    HmacSha256Algorithm hmac(key);
    auto medium_data = CreateMediumData();
    auto signature = hmac.sign(medium_data);
    
    for (auto _ : state) {
        bool result = hmac.verify(medium_data, signature);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_HMAC_Verify_Medium);

static void BM_HMAC_Verify_Large(benchmark::State& state) {
    auto key = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
    HmacSha256Algorithm hmac(key);
    auto signature = hmac.sign(LARGE_DATA);
    
    for (auto _ : state) {
        bool result = hmac.verify(LARGE_DATA, signature);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_HMAC_Verify_Large);

// ES256 Benchmarks
static void BM_ES256_KeyGeneration(benchmark::State& state) {
    for (auto _ : state) {
        Es256Algorithm es256;
        benchmark::DoNotOptimize(es256);
    }
}
BENCHMARK(BM_ES256_KeyGeneration);

static void BM_ES256_Sign_Small(benchmark::State& state) {
    Es256Algorithm es256;
    
    for (auto _ : state) {
        auto signature = es256.sign(SMALL_DATA);
        benchmark::DoNotOptimize(signature);
    }
}
BENCHMARK(BM_ES256_Sign_Small);

static void BM_ES256_Sign_Medium(benchmark::State& state) {
    Es256Algorithm es256;
    auto medium_data = CreateMediumData();
    
    for (auto _ : state) {
        auto signature = es256.sign(medium_data);
        benchmark::DoNotOptimize(signature);
    }
}
BENCHMARK(BM_ES256_Sign_Medium);

static void BM_ES256_Sign_Large(benchmark::State& state) {
    Es256Algorithm es256;
    
    for (auto _ : state) {
        auto signature = es256.sign(LARGE_DATA);
        benchmark::DoNotOptimize(signature);
    }
}
BENCHMARK(BM_ES256_Sign_Large);

static void BM_ES256_Verify_Small(benchmark::State& state) {
    Es256Algorithm es256;
    auto signature = es256.sign(SMALL_DATA);
    
    for (auto _ : state) {
        bool result = es256.verify(SMALL_DATA, signature);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_ES256_Verify_Small);

static void BM_ES256_Verify_Medium(benchmark::State& state) {
    Es256Algorithm es256;
    auto medium_data = CreateMediumData();
    auto signature = es256.sign(medium_data);
    
    for (auto _ : state) {
        bool result = es256.verify(medium_data, signature);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_ES256_Verify_Medium);

static void BM_ES256_Verify_Large(benchmark::State& state) {
    Es256Algorithm es256;
    auto signature = es256.sign(LARGE_DATA);
    
    for (auto _ : state) {
        bool result = es256.verify(LARGE_DATA, signature);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_ES256_Verify_Large);

// PS256 Benchmarks
static void BM_PS256_KeyGeneration(benchmark::State& state) {
    for (auto _ : state) {
        Ps256Algorithm ps256;
        benchmark::DoNotOptimize(ps256);
    }
}
BENCHMARK(BM_PS256_KeyGeneration);

static void BM_PS256_Sign_Small(benchmark::State& state) {
    Ps256Algorithm ps256;
    
    for (auto _ : state) {
        auto signature = ps256.sign(SMALL_DATA);
        benchmark::DoNotOptimize(signature);
    }
}
BENCHMARK(BM_PS256_Sign_Small);

static void BM_PS256_Sign_Medium(benchmark::State& state) {
    Ps256Algorithm ps256;
    auto medium_data = CreateMediumData();
    
    for (auto _ : state) {
        auto signature = ps256.sign(medium_data);
        benchmark::DoNotOptimize(signature);
    }
}
BENCHMARK(BM_PS256_Sign_Medium);

static void BM_PS256_Sign_Large(benchmark::State& state) {
    Ps256Algorithm ps256;
    
    for (auto _ : state) {
        auto signature = ps256.sign(LARGE_DATA);
        benchmark::DoNotOptimize(signature);
    }
}
BENCHMARK(BM_PS256_Sign_Large);

static void BM_PS256_Verify_Small(benchmark::State& state) {
    Ps256Algorithm ps256;
    auto signature = ps256.sign(SMALL_DATA);
    
    for (auto _ : state) {
        bool result = ps256.verify(SMALL_DATA, signature);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_PS256_Verify_Small);

static void BM_PS256_Verify_Medium(benchmark::State& state) {
    Ps256Algorithm ps256;
    auto medium_data = CreateMediumData();
    auto signature = ps256.sign(medium_data);
    
    for (auto _ : state) {
        bool result = ps256.verify(medium_data, signature);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_PS256_Verify_Medium);

static void BM_PS256_Verify_Large(benchmark::State& state) {
    Ps256Algorithm ps256;
    auto signature = ps256.sign(LARGE_DATA);
    
    for (auto _ : state) {
        bool result = ps256.verify(LARGE_DATA, signature);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_PS256_Verify_Large);

// Algorithm Comparison Benchmarks
static void BM_Crypto_Sign_Comparison(benchmark::State& state) {
    const int algorithm = state.range(0); // 0=HMAC, 1=ES256, 2=PS256
    auto medium_data = CreateMediumData();
    
    std::unique_ptr<CryptographicAlgorithm> crypto;
    switch (algorithm) {
        case 0: {
            auto key = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
            crypto = std::make_unique<HmacSha256Algorithm>(key);
            break;
        }
        case 1: {
            crypto = std::make_unique<Es256Algorithm>();
            break;
        }
        case 2: {
            crypto = std::make_unique<Ps256Algorithm>();
            break;
        }
    }
    
    for (auto _ : state) {
        auto signature = crypto->sign(medium_data);
        benchmark::DoNotOptimize(signature);
    }
}
BENCHMARK(BM_Crypto_Sign_Comparison)->DenseRange(0, 2);

static void BM_Crypto_Verify_Comparison(benchmark::State& state) {
    const int algorithm = state.range(0); // 0=HMAC, 1=ES256, 2=PS256
    auto medium_data = CreateMediumData();
    
    std::unique_ptr<CryptographicAlgorithm> crypto;
    switch (algorithm) {
        case 0: {
            auto key = secure_utils::to_regular_vector(HmacSha256Algorithm::generateSecureKey());
            crypto = std::make_unique<HmacSha256Algorithm>(key);
            break;
        }
        case 1: {
            crypto = std::make_unique<Es256Algorithm>();
            break;
        }
        case 2: {
            crypto = std::make_unique<Ps256Algorithm>();
            break;
        }
    }
    
    auto signature = crypto->sign(medium_data);
    
    for (auto _ : state) {
        bool result = crypto->verify(medium_data, signature);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_Crypto_Verify_Comparison)->DenseRange(0, 2);

