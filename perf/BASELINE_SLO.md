# CDN-scale baseline SLOs (Gate 8)

This document reports the single-host baseline for the catapult
admission hot path — the metrics an operator can use to size a real
deployment and to detect regressions.

## What the baseline measures

Each iteration runs the full library admission sequence for one
authorization request:

1. `Cwt::validateCwt` — CBOR parse + issuer signature verify
2. `CatTokenValidator::intoValidated` — temporal/issuer/audience/MOQT
   checks + `PermissivePolicy` authorization hook + `ValidatedCatToken`
   construction
3. `DpopKeyPair::generate_proof` (client side, JWT-encoded) —
   emulates the client's proof each request
4. `DpopProofValidator::validate_proof` — JWK-import (cached),
   signature verify, replay-store admit

Workload mix per iteration (default):

- 97% "steady state": fresh jti, valid token — hits the allow path
- 2%  intentional replay: same jti reused — hits the replay-reject path
- 1%  expired token — hits the temporal-reject path

The DPoP proof is JWT-encoded so each proof self-carries its JWK; this
avoids per-iteration reconfiguration of `set_cwt_verifier` on the
shared validator (which would be a data race under concurrent
workers). Real deployments using CWT-encoded proofs must construct
one validator per client-key, or pin the verifier at connection
establishment.

## Baseline hardware

- Apple M4, 10 cores (10 physical), 24 GB RAM
- macOS Darwin 25.5.0
- Release build (`-O3 -DNDEBUG`), Clang 17
- Single process, in-memory replay + usage stores

CDN-scale production numbers will differ; use the run scripts below
to reproduce on target hardware before publishing operator-facing SLOs.

## Baseline results

### Thread scaling (16k flows, 5k iters/thread)

| Threads | Throughput (ops/s) | p50 (μs) | p95 (μs) | p99 (μs) |
| ------: | -----------------: | -------: | -------: | -------: |
|       1 |              7,315 |    119.5 |    125.7 |    134.7 |
|       2 |             14,034 |    122.7 |    128.1 |    134.3 |
|       4 |             26,887 |    124.9 |    133.0 |    187.9 |
|       8 |             35,269 |    135.7 |    328.1 |    403.1 |

Interpretation: near-linear scaling through 4 threads, then the tail
degrades sharply. **This is Apple Silicon core asymmetry, not a
library bottleneck.** The M4 has 4 performance + 6 efficiency cores;
p95 jumps from ~138 μs at 4 threads to ~309 μs at 5 threads, exactly
when a worker first lands on an E-core.

Two experiments ruled out library-side contention:

1. Every `InMemory*Store` in the library is already 16-way sharded on
   its own mutex (`InMemoryReplayStore::kShardCount`,
   `InMemoryUsageState::kShardCount`, `InMemoryPolicyCache::kShardCount`).
2. Running `--per-worker-dpop` (one `DpopProofValidator` per worker,
   isolating the parsed-JWK-cache mutex) produced identical throughput
   and p99 at every thread count — the JWK cache mutex is not the
   contention point either.

Homogeneous-core production hardware (Xeon, Graviton, EPYC) is not
expected to exhibit the 4→5-thread discontinuity. Re-baseline on
target hardware before drawing scaling conclusions from this table.

### 100k-flow proof (8 threads, 20k iters/thread)

| Metric              | Value          |
| ------------------- | -------------- |
| Total admissions    | 160,000        |
| Elapsed             | 4.38 s         |
| Throughput          | 36,522 ops/s   |
| Latency p50         | 132.8 μs       |
| Latency p95         | 313.8 μs       |
| Latency p99         | 343.6 μs       |
| Latency max         | 1,565.2 μs     |
| Peak RSS            | 513,568 KB (≈ 500 MB) |
| Allow / expected    | 155,183 / 155,183 |
| Replay reject / expected | 3,203 / ≈ 3,200 |
| Expired reject / expected | 1,614 / ≈ 1,600 |
| Other reject        | 0              |

The reject counts match the requested workload mix (2% replay + 1%
expired) within tolerance, confirming the harness exercises the
intended failure paths.

Memory is dominated by per-flow state (each flow retains a valid CWT
byte string, an expired CWT byte string, and an `Es256Algorithm`
key pair). At 100k flows this is ≈ 5 KB per flow amortized — a
real relay would keep only the client's public key and a session
handle, not two full signed CWTs.

## Reproducing

```bash
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --target catapult_load_harness -j

# Human-readable
./build-release/catapult_load_harness --threads 8 --flows 100000 \
  --iterations 20000 --pretty

# JSON (for regression tracking)
./build-release/catapult_load_harness --threads 8 --flows 100000 \
  --iterations 20000 > baseline-$(date +%Y%m%d).json
```

Useful sweeps:

- Scaling sweep: `for t in 1 2 4 8 16; do ./catapult_load_harness --threads $t --flows 16384 --iterations 5000; done`
- Replay churn: vary `--replay-pct` to stress the DPoP replay path
- Expired churn: vary `--expired-pct` to stress the temporal reject
  path (cheaper than allow — `intoValidated` throws before DPoP)

## What this does NOT prove

Gate 8 mentions several axes this single-host harness does not
exercise. Before shipping, each of these needs its own coverage:

- **Real target hardware.** M4 laptop numbers are indicative, not
  authoritative. Run on the actual relay SKU.
- **Multi-instance failover.** The harness uses in-memory stores.
  Race behavior with a distributed replay backend (Redis, DynamoDB)
  needs its own test.
- **Long-duration soak.** These runs are seconds long. A 24h soak
  reveals leaks and drift the microbaseline misses.
- **Reconnect churn.** All flows here live for the whole run. A
  realistic client population reconnects every N minutes; that
  hammers the JWK cache LRU and the connection-establishment path.
- **Network + TLS + QUIC.** The harness measures library work only.
  Add the QUIC + framing cost the relay actually pays.
- **Overload behavior.** Behavior when the replay store rejects
  admissions with `StoreExhausted` is not exercised here.
