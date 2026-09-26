/**
 * @file load_harness.cpp
 * @brief Single-host CDN-scale proof for the CAT admission hot path.
 *
 * Spawns `--threads` worker threads that hammer a single, shared
 * `CatTokenValidator` + `DpopProofValidator` pair with a realistic
 * workload:
 *
 *   - each worker holds its own pool of pre-signed CAT tokens and DPoP
 *     key pairs, sized so the working set collectively spans
 *     `--flows` distinct "client sessions"
 *   - every iteration picks a random flow, generates a fresh DPoP
 *     proof (fresh jti so replay tracking exercises insertion, not the
 *     replay-hit fast path), and runs the full admission sequence:
 *     `Cwt::validateCwt` → `CatTokenValidator::intoValidated` →
 *     `DpopProofValidator::validate_proof`
 *   - a small fraction of iterations (`--replay-pct`) intentionally
 *     replay a previously-used jti to exercise the replay-reject path
 *   - a small fraction of iterations (`--expired-pct`) use an expired
 *     token to exercise the temporal-reject path
 *
 * Reports p50/p95/p99/max end-to-end admission latency, throughput,
 * peak RSS, and an error taxonomy. Output is JSON on stdout by default
 * so downstream tooling can diff runs; `--pretty` switches to a
 * human-readable summary.
 *
 * The harness is deliberately in-process. It does not exercise
 * network, TLS, QUIC, or a distributed replay backend — those are the
 * relay's concern. What it does prove is what the library costs *once
 * bytes are on the CPU*, and how that cost degrades as N workers
 * contend on the shared replay store, usage store, and JWK cache.
 */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <sys/resource.h>

#include "catapult/catapult.hpp"

using namespace catapult;
using namespace std::chrono_literals;

namespace {

struct Config {
  int threads = 4;
  int flows = 1024;
  long iterations_per_thread = 20'000;
  double replay_pct = 0.02;
  double expired_pct = 0.01;
  bool pretty = false;
  unsigned seed = 42;
  // When true, each worker gets its own DpopProofValidator. Diagnostic:
  // the shared validator's parsed-JWK-cache mutex is single-guarded, so
  // running per-worker validators isolates whether that mutex is the
  // bottleneck at high thread counts.
  bool per_worker_dpop = false;
};

void printUsage(const char* argv0) {
  std::fprintf(
      stderr,
      "usage: %s [options]\n"
      "  --threads N            worker threads (default 4)\n"
      "  --flows N              distinct client flows (default 1024)\n"
      "  --iterations N         admissions per thread (default 20000)\n"
      "  --replay-pct F         fraction of iterations that replay jti (0.02)\n"
      "  --expired-pct F        fraction of iterations using expired token "
      "(0.01)\n"
      "  --seed N               RNG seed (default 42)\n"
      "  --pretty               human-readable output instead of JSON\n"
      "  --per-worker-dpop      one DpopProofValidator per worker "
      "(diagnostic)\n"
      "  --help                 this help\n",
      argv0);
}

Config parseArgs(int argc, char** argv) {
  Config c;
  for (int i = 1; i < argc; ++i) {
    std::string_view a = argv[i];
    auto next = [&](const char* name) -> const char* {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "missing value for %s\n", name);
        std::exit(2);
      }
      return argv[++i];
    };
    if (a == "--help" || a == "-h") {
      printUsage(argv[0]);
      std::exit(0);
    } else if (a == "--threads") {
      c.threads = std::atoi(next("--threads"));
    } else if (a == "--flows") {
      c.flows = std::atoi(next("--flows"));
    } else if (a == "--iterations") {
      c.iterations_per_thread = std::atol(next("--iterations"));
    } else if (a == "--replay-pct") {
      c.replay_pct = std::atof(next("--replay-pct"));
    } else if (a == "--expired-pct") {
      c.expired_pct = std::atof(next("--expired-pct"));
    } else if (a == "--seed") {
      c.seed = static_cast<unsigned>(std::atoi(next("--seed")));
    } else if (a == "--pretty") {
      c.pretty = true;
    } else if (a == "--per-worker-dpop") {
      c.per_worker_dpop = true;
    } else {
      std::fprintf(stderr, "unknown arg: %s\n", argv[i]);
      printUsage(argv[0]);
      std::exit(2);
    }
  }
  if (c.threads < 1) c.threads = 1;
  if (c.flows < c.threads) c.flows = c.threads;
  return c;
}

// Per-flow static state: signed CWT bytes (never mutated), an equally
// long-lived DPoP key pair, and the pre-computed jkt for CWT proof
// validation. Everything the worker needs to admit that flow on a
// per-request basis is here.
struct FlowState {
  std::vector<uint8_t> cwt_bytes;
  std::vector<uint8_t> expired_cwt_bytes;
  std::unique_ptr<DpopKeyPair> dpop_key;
  std::string jkt_b64;
};

// Peak observed permission-adjusted allow/reject counts. We keep this
// out of the hot loop; workers accumulate locally and the reducer
// merges at the end.
struct WorkerStats {
  long allow = 0;
  long reject_signature = 0;
  long reject_expired = 0;
  long reject_replay = 0;
  long reject_other = 0;
  std::vector<uint64_t> latencies_ns;  // nanoseconds per admission attempt
};

// Percentile from a sorted vector. `p` in [0, 1].
uint64_t percentile(const std::vector<uint64_t>& sorted, double p) {
  if (sorted.empty()) return 0;
  double idx = p * static_cast<double>(sorted.size() - 1);
  auto lo = static_cast<size_t>(idx);
  auto hi = std::min(lo + 1, sorted.size() - 1);
  double frac = idx - static_cast<double>(lo);
  return static_cast<uint64_t>((1.0 - frac) * static_cast<double>(sorted[lo]) +
                               frac * static_cast<double>(sorted[hi]));
}

long peakRssKb() {
  struct rusage ru {};
  if (getrusage(RUSAGE_SELF, &ru) != 0) return 0;
  // Darwin reports bytes; Linux reports kilobytes.
#ifdef __APPLE__
  return static_cast<long>(ru.ru_maxrss / 1024);
#else
  return static_cast<long>(ru.ru_maxrss);
#endif
}

// A `PermissivePolicy` behind a stable address. `CatTokenValidator`
// holds a non-owning pointer, and every worker shares the same instance.
PermissivePolicy& permissivePolicy() {
  static PermissivePolicy p;
  return p;
}

}  // namespace

int main(int argc, char** argv) {
  Config cfg = parseArgs(argc, argv);

  // --- Setup: issuer key, per-flow CWTs, DPoP key pairs. -------------------
  const std::string relay_endpoint = "relay.moqt-cdn.example.com:4433";
  const std::string issuer_name = "auth.moqt-cdn.example.com";
  const std::string relay_aud = "relay.moqt-cdn.example.com";

  auto [issuer_priv, issuer_pub] = Es256Algorithm::generateSecureKeyPair();
  Es256Algorithm issuer_signer(issuer_priv, issuer_pub);
  auto issuer_verifier =
      std::make_shared<Es256Algorithm>(issuer_pub);  // used by every worker

  std::fprintf(stderr, "load_harness: setting up %d flows...\n", cfg.flows);

  std::vector<FlowState> flows(static_cast<size_t>(cfg.flows));
  {
    // Building flow state is the slowest part — parallelize.
    const int build_threads =
        std::min(cfg.threads, static_cast<int>(std::thread::hardware_concurrency()));
    std::vector<std::thread> builders;
    std::atomic<int> next{0};
    for (int t = 0; t < build_threads; ++t) {
      builders.emplace_back([&]() {
        for (;;) {
          int i = next.fetch_add(1);
          if (i >= cfg.flows) return;
          auto& f = flows[static_cast<size_t>(i)];
          auto alg = std::make_unique<Es256Algorithm>();
          f.dpop_key = std::make_unique<DpopKeyPair>(std::move(alg));
          // JWT proofs are validated against the JWK thumbprint, not the
          // COSE thumbprint. The CAT token's `cnf.jkt` and the relay's
          // expected-thumbprint argument to `validate_proof` must both
          // use the same form.
          f.jkt_b64 = jwk::calculateJWKThumbprint(
              f.dpop_key->get_public_key_jwk());

          auto build_token = [&](std::chrono::seconds exp_from_now) {
            auto token = CatToken::builder()
                             .issuer(issuer_name)
                             .audience(relay_aud)
                             .expiresIn(exp_from_now)
                             .build();
            {
              CatConfirmation cnf;
              cnf.jkt = base64UrlDecode(f.jkt_b64);
              token.dpop.cnf = std::move(cnf);
            }
            MoqtClaims moqt;
            std::vector<int> pub_actions = {moqt_actions::PUBLISH};
            moqt.addScope(pub_actions, MoqtBinaryMatch::exact("live"),
                          MoqtBinaryMatch::any());
            token.extended.setMoqtClaims(std::move(moqt));
            Cwt cwt(ALG_ES256, token);
            return cwt.createCwt(CwtMode::Signed, issuer_signer);
          };

          f.cwt_bytes = build_token(1h);
          f.expired_cwt_bytes = build_token(-1h);  // already expired
        }
      });
    }
    for (auto& b : builders) b.join();
  }
  std::fprintf(stderr, "load_harness: flow setup done.\n");

  // --- Shared validators. Constructed once, shared by every worker. --------
  CatTokenValidator cat_validator;
  cat_validator.withExpectedIssuers({issuer_name})
      .withExpectedAudiences({relay_aud})
      .withAuthorizationPolicy(&permissivePolicy());

  DpopValidationSettings dpop_settings;
  dpop_settings.set_window(300s);
  // A shared replay store, always. Correct replay semantics require
  // it. `--per-worker-dpop` gives each worker its own validator wrapping
  // this same store, isolating the validator's parsed-JWK-cache mutex
  // without losing cross-worker replay detection.
  auto shared_replay_store = std::make_shared<InMemoryReplayStore>(
      dpop_settings.get_max_jti_entries(),
      dpop_settings.get_jti_cleanup_interval());
  DpopProofValidator shared_dpop_validator(dpop_settings, shared_replay_store);

  // --- Worker loop. --------------------------------------------------------
  std::vector<WorkerStats> per_worker(cfg.threads);
  std::atomic<long> total_ops{0};

  auto start = std::chrono::steady_clock::now();

  std::vector<std::thread> workers;
  for (int t = 0; t < cfg.threads; ++t) {
    workers.emplace_back([&, t]() {
      auto& stats = per_worker[t];
      // Local validator when the diagnostic flag is set; otherwise
      // reference the shared one.
      std::optional<DpopProofValidator> local_dpop;
      if (cfg.per_worker_dpop) {
        local_dpop.emplace(dpop_settings, shared_replay_store);
      }
      DpopProofValidator& dpop_validator =
          cfg.per_worker_dpop ? *local_dpop : shared_dpop_validator;
      stats.latencies_ns.reserve(
          static_cast<size_t>(cfg.iterations_per_thread));

      std::mt19937_64 rng(cfg.seed + static_cast<unsigned>(t));
      std::uniform_int_distribution<int> flow_pick(0, cfg.flows - 1);
      std::uniform_real_distribution<double> unit(0.0, 1.0);

      // Cache a single reused jti for replay-hit iterations so the
      // second admission actually collides.
      std::optional<std::string> stashed_jti;
      int stashed_flow = 0;

      for (long i = 0; i < cfg.iterations_per_thread; ++i) {
        int flow_idx = flow_pick(rng);
        auto& flow = flows[static_cast<size_t>(flow_idx)];

        double roll = unit(rng);
        bool do_expired = roll < cfg.expired_pct;
        bool do_replay = !do_expired && stashed_jti.has_value() &&
                         roll < cfg.expired_pct + cfg.replay_pct;

        std::string jti = do_replay ? *stashed_jti : moqt_dpop::generate_jti();
        int use_flow = do_replay ? stashed_flow : flow_idx;
        auto& active = flows[static_cast<size_t>(use_flow)];
        const auto& cwt_bytes =
            do_expired ? active.expired_cwt_bytes : active.cwt_bytes;

        // JWT-encoded so each proof embeds its own JWK. This avoids
        // needing to reconfigure `set_cwt_verifier` on the shared
        // validator per iteration, which would be a data race under
        // concurrent workers.
        auto proof = active.dpop_key->generate_proof(
            moqt_actions::PUBLISH, "live", "video", relay_endpoint, jti,
            DpopEncoding::JWT);

        auto op_start = std::chrono::steady_clock::now();
        bool allowed = false;
        int reject_class = 0;  // 0=other,1=sig,2=expired,3=replay
        try {
          Cwt cwt = Cwt::validateCwt(
              std::span<const uint8_t>(cwt_bytes.data(), cwt_bytes.size()),
              *issuer_verifier);
          PolicyContext pctx;
          int action = moqt_actions::PUBLISH;
          pctx.moqt_action = action;
          std::string_view ns_sv = "live";
          std::string_view tk_sv = "video";
          pctx.moqt_namespace = ns_sv;
          pctx.moqt_track = tk_sv;
          auto validated = cat_validator.intoValidated(
              std::move(cwt.payload), pctx);

          // JWT-encoded proofs carry their JWK — no per-request
          // verifier plumbing needed.
          auto expected_uri = moqt_dpop::construct_moqt_uri(
              relay_endpoint, "live", "video");
          if (dpop_validator.validate_proof(proof, moqt_actions::PUBLISH,
                                            expected_uri, active.jkt_b64)) {
            allowed = true;
          } else {
            // `validate_proof` returns false on both replay-hit and other
            // DPoP-layer rejections. In this harness, the only
            // deterministic false-return path is the intentional replay
            // roll; a false return outside that roll indicates a
            // configuration bug.
            reject_class = 3;
          }
        } catch (const SignatureVerificationError&) {
          reject_class = 1;
        } catch (const TokenExpiredError&) {
          reject_class = 2;
        } catch (const ReplayAttackError&) {
          reject_class = 3;
        } catch (const CatError&) {
          reject_class = 0;
        } catch (const std::exception&) {
          reject_class = 0;
        }
        auto op_end = std::chrono::steady_clock::now();

        stats.latencies_ns.push_back(static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(op_end -
                                                                 op_start)
                .count()));
        if (allowed) {
          ++stats.allow;
          if (!stashed_jti.has_value()) {
            stashed_jti = jti;
            stashed_flow = flow_idx;
          }
        } else {
          switch (reject_class) {
            case 1: ++stats.reject_signature; break;
            case 2: ++stats.reject_expired; break;
            case 3: ++stats.reject_replay; break;
            default: ++stats.reject_other; break;
          }
        }
        ++total_ops;
      }
    });
  }
  for (auto& w : workers) w.join();

  auto end = std::chrono::steady_clock::now();
  double elapsed_s =
      std::chrono::duration<double>(end - start).count();

  // --- Reduce. -------------------------------------------------------------
  long total_allow = 0, total_sig = 0, total_exp = 0, total_replay = 0,
       total_other = 0;
  std::vector<uint64_t> all_latencies;
  all_latencies.reserve(static_cast<size_t>(cfg.iterations_per_thread) *
                        static_cast<size_t>(cfg.threads));
  for (auto& s : per_worker) {
    total_allow += s.allow;
    total_sig += s.reject_signature;
    total_exp += s.reject_expired;
    total_replay += s.reject_replay;
    total_other += s.reject_other;
    all_latencies.insert(all_latencies.end(), s.latencies_ns.begin(),
                         s.latencies_ns.end());
  }
  std::sort(all_latencies.begin(), all_latencies.end());
  uint64_t p50 = percentile(all_latencies, 0.50);
  uint64_t p95 = percentile(all_latencies, 0.95);
  uint64_t p99 = percentile(all_latencies, 0.99);
  uint64_t pmax = all_latencies.empty() ? 0 : all_latencies.back();
  double ops_per_s = static_cast<double>(total_ops.load()) / elapsed_s;
  long rss_kb = peakRssKb();

  // --- Report. -------------------------------------------------------------
  if (cfg.pretty) {
    std::printf("=== catapult load harness ===\n");
    std::printf("threads=%d flows=%d iters/thread=%ld elapsed=%.3fs\n",
                cfg.threads, cfg.flows, cfg.iterations_per_thread, elapsed_s);
    std::printf("total ops       : %ld\n", total_ops.load());
    std::printf("throughput      : %.0f ops/s\n", ops_per_s);
    std::printf("latency p50     : %6.1f us\n",
                static_cast<double>(p50) / 1000.0);
    std::printf("latency p95     : %6.1f us\n",
                static_cast<double>(p95) / 1000.0);
    std::printf("latency p99     : %6.1f us\n",
                static_cast<double>(p99) / 1000.0);
    std::printf("latency max     : %6.1f us\n",
                static_cast<double>(pmax) / 1000.0);
    std::printf("peak RSS        : %ld KB\n", rss_kb);
    std::printf("allow           : %ld\n", total_allow);
    std::printf("reject.expired  : %ld\n", total_exp);
    std::printf("reject.replay   : %ld\n", total_replay);
    std::printf("reject.signature: %ld\n", total_sig);
    std::printf("reject.other    : %ld\n", total_other);
  } else {
    std::printf(
        "{\"threads\":%d,\"flows\":%d,\"iterations_per_thread\":%ld,"
        "\"elapsed_s\":%.6f,\"total_ops\":%ld,\"ops_per_s\":%.2f,"
        "\"latency_ns\":{\"p50\":%llu,\"p95\":%llu,\"p99\":%llu,\"max\":%llu},"
        "\"peak_rss_kb\":%ld,"
        "\"allow\":%ld,\"reject\":{\"expired\":%ld,\"replay\":%ld,"
        "\"signature\":%ld,\"other\":%ld}}\n",
        cfg.threads, cfg.flows, cfg.iterations_per_thread, elapsed_s,
        total_ops.load(), ops_per_s,
        static_cast<unsigned long long>(p50),
        static_cast<unsigned long long>(p95),
        static_cast<unsigned long long>(p99),
        static_cast<unsigned long long>(pmax), rss_kb, total_allow, total_exp,
        total_replay, total_sig, total_other);
  }

  return 0;
}
