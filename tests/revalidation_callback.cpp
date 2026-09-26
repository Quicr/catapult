/**
 * @file revalidation_callback.cpp
 * @brief Tests for the RevalidationCallback observability hook.
 */

#include <doctest/doctest.h>

#include <atomic>
#include <chrono>
#include <string>

#include "catapult/moqt_claims.hpp"
#include "catapult/revalidation_callback.hpp"
#include "catapult/token.hpp"
#include "catapult/validator.hpp"

using namespace catapult;
using namespace std::chrono_literals;

namespace {

class RecordingCallback final : public RevalidationCallback {
 public:
  std::atomic<int> fresh_count{0};
  std::atomic<int> expired_count{0};
  std::chrono::seconds last_time_to_reval{0};
  std::string last_token_id;

  void onRevalidationCheck(RevalidationStatus status,
                           std::string_view token_id, int64_t /*iat*/,
                           std::chrono::seconds /*reval_interval*/,
                           std::chrono::seconds
                               time_to_reval) noexcept override {
    if (status == RevalidationStatus::Fresh) {
      fresh_count.fetch_add(1, std::memory_order_relaxed);
    } else {
      expired_count.fetch_add(1, std::memory_order_relaxed);
    }
    last_time_to_reval = time_to_reval;
    last_token_id = std::string(token_id);
  }
};

int64_t nowSeconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

CatToken makeMoqtToken(int64_t iat, std::chrono::seconds reval_interval) {
  CatToken token;
  token.core.iss = "issuer";
  token.core.aud = std::vector<std::string>{"audience"};
  token.core.exp = iat + 3600;
  token.informational.iat = iat;
  auto& moqt = token.extended.getMoqtClaims();
  moqt.setRevalidationInterval(reval_interval);
  moqt.addCompileTimeScope<moqt_actions::SUBSCRIBE>(
      MoqtBinaryMatch::exact("ns"), MoqtBinaryMatch::exact("tr"));
  return token;
}

// A MOQT-scoped token requires the request tuple by default. These reval
// tests are not exercising scope enforcement; the tuple values only need
// to match the exact("ns")/exact("tr") scope above.
PolicyContext moqtScopeContext() {
  static const std::string kNs = "ns";
  static const std::string kTrack = "tr";
  PolicyContext ctx;
  ctx.moqt_action = moqt_actions::SUBSCRIBE;
  ctx.moqt_namespace = kNs;
  ctx.moqt_track = kTrack;
  return ctx;
}

}  // namespace

TEST_SUITE("RevalidationCallback") {
  TEST_CASE("Fresh token fires callback with positive time_to_reval") {
    RecordingCallback cb;
    CatTokenValidator validator;
    validator.withRevalidationCallback(&cb);

    // iat is now; reval interval is 300s — plenty of budget.
    auto token = makeMoqtToken(nowSeconds(), 300s);
    CHECK_NOTHROW(validator.validate(token, moqtScopeContext()));

    CHECK(cb.fresh_count.load() == 1);
    CHECK(cb.expired_count.load() == 0);
    CHECK(cb.last_time_to_reval.count() > 0);
  }

  TEST_CASE("Expired token fires callback with non-positive time_to_reval "
            "AND throws") {
    RecordingCallback cb;
    CatTokenValidator validator;
    validator.withRevalidationCallback(&cb);

    // iat 10 minutes ago, reval interval 60s — well past the deadline.
    auto token = makeMoqtToken(nowSeconds() - 600, 60s);
    CHECK_THROWS_AS(validator.validate(token),
                    TokenRevalidationRequiredError);

    CHECK(cb.fresh_count.load() == 0);
    CHECK(cb.expired_count.load() == 1);
    CHECK(cb.last_time_to_reval.count() <= 0);
  }

  TEST_CASE("Callback is not invoked on tokens without moqt-reval") {
    RecordingCallback cb;
    CatTokenValidator validator;
    validator.withRevalidationCallback(&cb);

    CatToken plain;
    plain.core.iss = "issuer";
    plain.core.aud = std::vector<std::string>{"audience"};
    plain.core.exp = nowSeconds() + 3600;
    CHECK_NOTHROW(validator.validate(plain));

    CHECK(cb.fresh_count.load() == 0);
    CHECK(cb.expired_count.load() == 0);
  }

  TEST_CASE("Nullptr callback leaves validation semantics unchanged") {
    CatTokenValidator validator;
    validator.withRevalidationCallback(nullptr);

    auto fresh = makeMoqtToken(nowSeconds(), 300s);
    CHECK_NOTHROW(validator.validate(fresh, moqtScopeContext()));

    auto expired = makeMoqtToken(nowSeconds() - 600, 60s);
    CHECK_THROWS_AS(validator.validate(expired),
                    TokenRevalidationRequiredError);
  }

  TEST_CASE("NoopRevalidationCallback compiles and runs") {
    // The default in-tree callback: no fields, no state, no crash.
    NoopRevalidationCallback noop;
    CatTokenValidator validator;
    validator.withRevalidationCallback(&noop);

    auto token = makeMoqtToken(nowSeconds(), 300s);
    CHECK_NOTHROW(validator.validate(token, moqtScopeContext()));
  }
}
