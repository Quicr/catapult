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
        .withCwtIdString("token-123")
        .withSubject("user@example.com");
}

static CatToken CreateMediumToken() {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);

    CatProofOfPossession por;
    por.probability = 1.0;
    por.identifier = {0x01, 0x02, 0x03};

    return CatToken()
        .withIssuer("https://auth.example.com")
        .withAudience({"client1", "client2"})
        .withExpiration(exp)
        .withNotBefore(now)
        .withCwtIdString("token-12345")
        .withVersion(1)
        .withReplayProtection(CatReplayMode::RejectOnReplay)
        .withProofOfPossession(por)
        .withSubject("user@example.com")
        .withIssuedAt(now)
        .withInterfaceData(CatIfData{std::string{"web-interface"}});
}

static CatToken CreateComplexToken() {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    auto iat = now - std::chrono::minutes(1);
    
    CatUriMatchMap catu;
    catu.components[1] = UriComponentMatch{UriMatchType::Prefix,
                                           {'h', 't', 't', 'p', 's', ':', '/', '/'}};
    catu.components[3] = UriComponentMatch{UriMatchType::Exact,
                                           {'/', 'a', 'p', 'i', '/', 'v', '1'}};

    CatProofOfPossession por;
    por.probability = 1.0;
    por.identifier = {0x0A, 0x0B, 0x0C, 0x0D};

    CatConfirmation cnf;
    cnf.jkt = {0xAA, 0xBB, 0xCC, 0xDD};

    CatDpopSettings dpop;
    dpop.critical = std::vector<int64_t>{1, 3};
    dpop.proof_lifetime_seconds = 300;

    CatRequestDirective iface_claim;
    iface_claim.raw = {'i', 'f', 'a', 'c', 'e'};

    CatRequestDirective req_claim;
    req_claim.raw = {'r', 'e', 'q'};

    CatNipEntry nip_a{.tag = 260, .value = {0xC0, 0xA8, 0x01, 0x64}};
    CatNipEntry nip_b{.tag = 260, .value = {0x0A, 0x00, 0x00, 0x00}};

    return CatToken()
        .withIssuer("https://auth.example.com")
        .withAudience({"client1", "client2", "mobile-app", "web-app", "api-service"})
        .withExpiration(exp)
        .withNotBefore(now)
        .withCwtIdString("token-12345-complex")
        .withVersion(1)
        .withUriMatch(catu)
        .withReplayProtection(CatReplayMode::RejectOnReplay)
        .withProofOfPossession(por)
        .withGeoCoordinate(40.7128, -74.0060, 100.0)
        .withGeohash(GeohashClaimValue{std::string{"dr5regw"}})
        .withSubject("user@example.com")
        .withIssuedAt(iat)
        .withInterfaceData(CatIfData{std::string{"mobile-interface-v2"}})
        .withConfirmation(cnf)
        .withDpopClaim(dpop)
        .withInterfaceClaim(iface_claim)
        .withRequestClaim(req_claim)
        .withNetworkInterfaces({nip_a, nip_b});
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

