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
        .withCwtId("token-12345")
        .withVersion("1.0.0")
        .withSubject("user@example.com")
        .withIssuedAt(now);
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
        .withAudience({"client1", "client2", "mobile-app"})
        .withExpiration(exp)
        .withNotBefore(now)
        .withCwtId("token-12345")
        .withVersion("1.2.0")
        .withUsageLimit(500)
        .withReplayProtection("nonce-67890")
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
            .withVersion("1.0")
            .withUsageLimit(100)
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
            .withVersion("1.0");
        benchmark::DoNotOptimize(token);
    }
}
BENCHMARK(BM_TokenCreationSize)->Range(1, 100);

