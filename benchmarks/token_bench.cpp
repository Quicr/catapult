#include <benchmark/benchmark.h>
#include "catapult/claims.hpp"
#include "catapult/validator.hpp"
#include "catapult/uri.hpp"
#include "catapult/crypto.hpp"
#include <chrono>

using namespace catapult;

static CatToken CreateSimpleToken() {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    return CatToken()
        .withIssuer("https://auth.example.com")
        .withAudience({"client1", "client2"})
        .withExpiration(exp)
        .withNotBefore(now)
        .withCwtIdString("token-12345")
        .withVersion(1)
        .withSubject("user@example.com")
        .withIssuedAt(now);
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
        .withAudience({"client1", "client2", "mobile-app"})
        .withExpiration(exp)
        .withNotBefore(now)
        .withCwtIdString("token-12345")
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

static void BM_CreateSimpleToken(benchmark::State& state) {
    for (auto _ : state) {
        auto token = CreateSimpleToken();
        benchmark::DoNotOptimize(token);
    }
}
BENCHMARK(BM_CreateSimpleToken);

static void BM_CreateComplexToken(benchmark::State& state) {
    for (auto _ : state) {
        auto token = CreateComplexToken();
        benchmark::DoNotOptimize(token);
    }
}
BENCHMARK(BM_CreateComplexToken);

static void BM_TokenBuilderChaining(benchmark::State& state) {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(1);
    
    for (auto _ : state) {
        auto token = CatToken()
            .withIssuer("https://auth.example.com")
            .withAudience({"client1"})
            .withExpiration(exp)
            .withVersion(1)
            .withSubject("user@example.com");
        benchmark::DoNotOptimize(token);
    }
}
BENCHMARK(BM_TokenBuilderChaining);

static void BM_ValidateSimpleToken(benchmark::State& state) {
    auto token = CreateSimpleToken();
    auto validator = CatTokenValidator()
        .withExpectedIssuers({"https://auth.example.com"})
        .withExpectedAudiences({"client1", "client2"})
        .withClockSkewTolerance(60);
    
    for (auto _ : state) {
        try {
            validator.validate(token);
            benchmark::DoNotOptimize(token);
        } catch (const CatError& e) {
            // Expected for some validation failures
        }
    }
}
BENCHMARK(BM_ValidateSimpleToken);

static void BM_ValidateComplexToken(benchmark::State& state) {
    auto token = CreateComplexToken();
    auto validator = CatTokenValidator()
        .withExpectedIssuers({"https://auth.example.com"})
        .withExpectedAudiences({"client1", "client2", "mobile-app"})
        .withClockSkewTolerance(60);
    
    for (auto _ : state) {
        try {
            validator.validate(token);
            benchmark::DoNotOptimize(token);
        } catch (const CatError& e) {
            // Expected for some validation failures
        }
    }
}
BENCHMARK(BM_ValidateComplexToken);

static void BM_TokenCopy(benchmark::State& state) {
    auto token = CreateComplexToken();
    
    for (auto _ : state) {
        auto copy = token;
        benchmark::DoNotOptimize(copy);
    }
}
BENCHMARK(BM_TokenCopy);

static void BM_TokenMove(benchmark::State& state) {
    for (auto _ : state) {
        auto token = CreateComplexToken();
        auto moved = std::move(token);
        benchmark::DoNotOptimize(moved);
    }
}
BENCHMARK(BM_TokenMove);

// Benchmark different token sizes
static void BM_TokenCreationSize(benchmark::State& state) {
    const int num_audiences = state.range(0);
    
    for (auto _ : state) {
        auto now = std::chrono::system_clock::now();
        auto exp = now + std::chrono::hours(1);
        
        std::vector<std::string> audiences;
        for (int i = 0; i < num_audiences; ++i) {
            audiences.push_back("client" + std::to_string(i));
        }
        
        auto token = CatToken()
            .withIssuer("https://auth.example.com")
            .withAudience(audiences)
            .withExpiration(exp)
            .withVersion(1);
        benchmark::DoNotOptimize(token);
    }
}
BENCHMARK(BM_TokenCreationSize)->Range(1, 100);

