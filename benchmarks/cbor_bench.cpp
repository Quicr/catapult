#include <benchmark/benchmark.h>
#include "catapult/token.hpp"
#include "catapult/cwt.hpp"
#include "catapult/crypto.hpp"
#include <chrono>
#include <vector>

using namespace catapult;

static CatToken CreateSimpleToken() {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    return CatToken()
        .withIssuer("https://auth.example.com")
        .withAudience({"client1"})
        .withExpiration(exp)
        .withCwtId("token-123")
        .withSubject("user@example.com");
}

static CatToken CreateMediumToken() {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    return CatToken()
        .withIssuer("https://auth.example.com")
        .withAudience({"client1", "client2"})
        .withExpiration(exp)
        .withNotBefore(now)
        .withCwtId("token-12345")
        .withVersion("1.0.0")
        .withUsageLimit(100)
        .withReplayProtection("nonce-456")
        .withProofOfPossession(true)
        .withSubject("user@example.com")
        .withIssuedAt(now)
        .withInterfaceData("web-interface");
}

static CatToken CreateComplexToken() {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    auto iat = now - std::chrono::minutes(1);
    
    std::vector<std::string> uriPatterns = {
        "https://api.example.com",
        "https://secure.*",
        "*/api/v1",
        "^https://.*\\.test\\.com$",
        "abcdef123456"
    };
    
    return CatToken()
        .withIssuer("https://auth.example.com")
        .withAudience({"client1", "client2", "mobile-app", "web-app", "api-service"})
        .withExpiration(exp)
        .withNotBefore(now)
        .withCwtId("token-12345-complex")
        .withVersion("1.2.0")
        .withUsageLimit(1000)
        .withReplayProtection("nonce-67890-complex")
        .withProofOfPossession(true)
        .withGeoCoordinate(40.7128, -74.0060, 100.0)
        .withGeohash("dr5regw")
        .withUriPatterns(uriPatterns)
        .withSubject("user@example.com")
        .withIssuedAt(iat)
        .withInterfaceData("mobile-interface-v2")
        .withConfirmation("jwk-thumbprint-xyz")
        .withDpopClaim("dpop-proof-token")
        .withInterfaceClaim("auth-interface")
        .withRequestClaim("login-request-abc")
        .withNetworkInterfaces({"192.168.1.100", "10.0.0.0/8"});
}

// CBOR Encoding Benchmarks
static void BM_CBOR_Encode_Simple(benchmark::State& state) {
    auto token = CreateSimpleToken();
    Cwt cwt(ALG_HMAC256_256, token);
    
    for (auto _ : state) {
        auto encoded = cwt.encodePayload();
        benchmark::DoNotOptimize(encoded);
    }
}
BENCHMARK(BM_CBOR_Encode_Simple);

static void BM_CBOR_Encode_Medium(benchmark::State& state) {
    auto token = CreateMediumToken();
    Cwt cwt(ALG_ES256, token);
    
    for (auto _ : state) {
        auto encoded = cwt.encodePayload();
        benchmark::DoNotOptimize(encoded);
    }
}
BENCHMARK(BM_CBOR_Encode_Medium);

static void BM_CBOR_Encode_Complex(benchmark::State& state) {
    auto token = CreateComplexToken();
    Cwt cwt(ALG_PS256, token);
    
    for (auto _ : state) {
        auto encoded = cwt.encodePayload();
        benchmark::DoNotOptimize(encoded);
    }
}
BENCHMARK(BM_CBOR_Encode_Complex);

// CBOR Decoding Benchmarks
static void BM_CBOR_Decode_Simple(benchmark::State& state) {
    auto token = CreateSimpleToken();
    Cwt cwt(ALG_HMAC256_256, token);
    auto encoded = cwt.encodePayload();
    
    for (auto _ : state) {
        auto decoded = Cwt::decodePayload(encoded);
        benchmark::DoNotOptimize(decoded);
    }
}
BENCHMARK(BM_CBOR_Decode_Simple);

static void BM_CBOR_Decode_Medium(benchmark::State& state) {
    auto token = CreateMediumToken();
    Cwt cwt(ALG_ES256, token);
    auto encoded = cwt.encodePayload();
    
    for (auto _ : state) {
        auto decoded = Cwt::decodePayload(encoded);
        benchmark::DoNotOptimize(decoded);
    }
}
BENCHMARK(BM_CBOR_Decode_Medium);

static void BM_CBOR_Decode_Complex(benchmark::State& state) {
    auto token = CreateComplexToken();
    Cwt cwt(ALG_PS256, token);
    auto encoded = cwt.encodePayload();
    
    for (auto _ : state) {
        auto decoded = Cwt::decodePayload(encoded);
        benchmark::DoNotOptimize(decoded);
    }
}
BENCHMARK(BM_CBOR_Decode_Complex);

// CBOR Roundtrip Benchmarks
static void BM_CBOR_Roundtrip_Simple(benchmark::State& state) {
    auto token = CreateSimpleToken();
    Cwt cwt(ALG_HMAC256_256, token);
    
    for (auto _ : state) {
        auto encoded = cwt.encodePayload();
        auto decoded = Cwt::decodePayload(encoded);
        benchmark::DoNotOptimize(decoded);
    }
}
BENCHMARK(BM_CBOR_Roundtrip_Simple);

static void BM_CBOR_Roundtrip_Medium(benchmark::State& state) {
    auto token = CreateMediumToken();
    Cwt cwt(ALG_ES256, token);
    
    for (auto _ : state) {
        auto encoded = cwt.encodePayload();
        auto decoded = Cwt::decodePayload(encoded);
        benchmark::DoNotOptimize(decoded);
    }
}
BENCHMARK(BM_CBOR_Roundtrip_Medium);

static void BM_CBOR_Roundtrip_Complex(benchmark::State& state) {
    auto token = CreateComplexToken();
    Cwt cwt(ALG_PS256, token);
    
    for (auto _ : state) {
        auto encoded = cwt.encodePayload();
        auto decoded = Cwt::decodePayload(encoded);
        benchmark::DoNotOptimize(decoded);
    }
}
BENCHMARK(BM_CBOR_Roundtrip_Complex);

// Algorithm-specific CBOR Benchmarks
static void BM_CBOR_ByAlgorithm_Encode(benchmark::State& state) {
    const int algorithm = state.range(0); // 0=HMAC, 1=ES256, 2=PS256
    auto token = CreateMediumToken();
    
    int64_t alg_id;
    switch (algorithm) {
        case 0: alg_id = ALG_HMAC256_256; break;
        case 1: alg_id = ALG_ES256; break;
        case 2: alg_id = ALG_PS256; break;
        default: alg_id = ALG_HMAC256_256; break;
    }
    
    Cwt cwt(alg_id, token);
    
    for (auto _ : state) {
        auto encoded = cwt.encodePayload();
        benchmark::DoNotOptimize(encoded);
    }
}
BENCHMARK(BM_CBOR_ByAlgorithm_Encode)->DenseRange(0, 2);

static void BM_CBOR_ByAlgorithm_Decode(benchmark::State& state) {
    const int algorithm = state.range(0); // 0=HMAC, 1=ES256, 2=PS256
    auto token = CreateMediumToken();
    
    int64_t alg_id;
    switch (algorithm) {
        case 0: alg_id = ALG_HMAC256_256; break;
        case 1: alg_id = ALG_ES256; break;
        case 2: alg_id = ALG_PS256; break;
        default: alg_id = ALG_HMAC256_256; break;
    }
    
    Cwt cwt(alg_id, token);
    auto encoded = cwt.encodePayload();
    
    for (auto _ : state) {
        auto decoded = Cwt::decodePayload(encoded);
        benchmark::DoNotOptimize(decoded);
    }
}
BENCHMARK(BM_CBOR_ByAlgorithm_Decode)->DenseRange(0, 2);

// Size Analysis Benchmark
static void BM_CBOR_SizeAnalysis(benchmark::State& state) {
    auto simple_token = CreateSimpleToken();
    auto medium_token = CreateMediumToken();
    auto complex_token = CreateComplexToken();
    
    Cwt simple_cwt(ALG_HMAC256_256, simple_token);
    Cwt medium_cwt(ALG_ES256, medium_token);
    Cwt complex_cwt(ALG_PS256, complex_token);
    
    // Pre-calculate sizes for analysis
    auto simple_size = simple_cwt.encodePayload().size();
    auto medium_size = medium_cwt.encodePayload().size();
    auto complex_size = complex_cwt.encodePayload().size();
    
    // Output size information
    static bool size_logged = false;
    if (!size_logged) {
        printf("CBOR Size Analysis:\n");
        printf("Simple token: %zu bytes\n", simple_size);
        printf("Medium token: %zu bytes\n", medium_size);
        printf("Complex token: %zu bytes\n", complex_size);
        size_logged = true;
    }
    
    // Benchmark encoding with size awareness
    const int token_type = state.range(0); // 0=simple, 1=medium, 2=complex
    
    for (auto _ : state) {
        std::vector<uint8_t> encoded;
        switch (token_type) {
            case 0:
                encoded = simple_cwt.encodePayload();
                break;
            case 1:
                encoded = medium_cwt.encodePayload();
                break;
            case 2:
                encoded = complex_cwt.encodePayload();
                break;
        }
        benchmark::DoNotOptimize(encoded.size());
    }
}
BENCHMARK(BM_CBOR_SizeAnalysis)->DenseRange(0, 2);

