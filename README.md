# HTTP adapter benchmarks

Independent benchmark snapshot of wreq-proto at
[`dc1cabe551a63525cd4ed7c8ee39cf1d48ea8f8a`](https://github.com/0x676e67/wreq-proto/commit/dc1cabe551a63525cd4ed7c8ee39cf1d48ea8f8a).
This orphan branch has its own root commit and no development-branch ancestry.
`src/` and `tests/` preserve that product snapshot; the benchmark harnesses come
from the isolated M3 Max comparisons. See `SOURCE.json` for file hashes.
This is an analysis artifact, not a release branch (`publish = false`).

## Build

Use Rust 1.98 or newer. The measured M3 Max environment used Rust 1.98.1.
Dependencies are pinned in Cargo.lock; the two Git patches are pinned to full
commit IDs. Initial setup requires network access to fetch dependencies.

```sh
cargo bench --locked --features http3 --bench http3 --bench http2-adapter --no-run
```

No local path dependency outside this checkout, external proxy process,
certificate file or .agents directory is required. Both servers use localhost
IPv4 and ephemeral ports. HTTP/3 certificates are generated locally and trusted
only by the benchmark client. For formatting use `cargo +nightly fmt --all`.

## Short run

POSIX shell (macOS/Linux):

```sh
CLIENT_BENCH_MODE=single CLIENT_BENCH_CONCURRENCY=1 CLIENT_BENCH_BYTES=4096 \
CLIENT_BENCH_ROUNDS=1 CLIENT_BENCH_SECONDS=1 \
cargo bench --locked --features http3 --bench http3

CLIENT_BENCH_MODE=single CLIENT_BENCH_CONCURRENCY=1 CLIENT_BENCH_BYTES=4096 \
CLIENT_BENCH_ROUNDS=1 CLIENT_BENCH_SECONDS=1 \
cargo bench --locked --features http3 --bench http2-adapter
```

PowerShell (Windows):

```powershell
$env:CLIENT_BENCH_MODE = 'single'
$env:CLIENT_BENCH_CONCURRENCY = '1'
$env:CLIENT_BENCH_BYTES = '4096'
$env:CLIENT_BENCH_ROUNDS = '1'
$env:CLIENT_BENCH_SECONDS = '1'
cargo bench --locked --features http3 --bench http3
cargo bench --locked --features http3 --bench http2-adapter
```

Unset these variables afterwards to restore defaults. Results are CSV on stdout;
Cargo build messages go to stderr. Each round alternates direct/wreq order.
Build and run separately when profiling; Cargo JSON output identifies each bench
executable. Avoid reusing CARGO_TARGET_DIR across modified source copies.

## Parameters and scope

| Variable | Default | Values |
|---|---|---|
| CLIENT_BENCH_MODE | all models | single, shared, sharded |
| CLIENT_BENCH_CONCURRENCY | all configured values | single/shared: 1,4,32,128; sharded: 4,32,128 |
| CLIENT_BENCH_BYTES | 0 | H3: 0,4096,131072; H2: 0,4096 |
| CLIENT_BENCH_ROUNDS | 3 | Positive integer |
| CLIENT_BENCH_SECONDS | 2 | Positive integer; measurement only, plus 1 second warmup |
| CLIENT_BENCH_IMPLEMENTATION | both | http3 or http2 for the direct arm; wreq-proto for the adapter |

single uses one current-thread runtime and one connection. shared uses four
Tokio workers and one connection. sharded uses four OS threads, each with its
own current-thread runtime, connection and (for H3) QUIC endpoint. Concurrency
is the total across connections. The server has a separate four-worker runtime.

H3 compares the http3 library through http3-quic with wreq-proto through its
test QUIC trait adapter. Both use the same client QUIC configuration and an
upstream h3 + Quinn server. H2 compares http2 with wreq-proto against the same
upstream Hyper server. These are per-protocol adapter comparisons, not an
absolute TCP-versus-QUIC contest. No SOCKS5/MASQUE forwarding code is included.

Both request and response have CLIENT_BENCH_BYTES bytes. Runs validate payloads,
request counts and driver/task cleanup. Timing includes content verification.
Use at least three alternating rounds for performance analysis; the one-round
commands above only smoke-test executability. Compare per-round RPS ratios and
report their median/range. P99 is a histogram bucket upper bound, with roughly
3.125% quantization, not exact nanosecond measurement.

The H2 handoff intentionally supports only the completed 0/4 KiB configurations.
128 KiB was not validated through the full matrix and is rejected explicitly.
Do not interpret successful compilation as validation of arbitrary workloads.
Unset H3_BENCH_PROFILE, H3_BENCH_DIRECT_TASKS and H3_BENCH_DIRECT_CLONE: this
normal matrix rejects those diagnostic modes. Existing profiling helper source
is retained to keep the measured harness layout; it is inactive in normal runs.

## Analysis boundaries

The HTTP/3 Incoming implementation deliberately retains chan::Receiver. Request
future cancellation cancels the request; after response handoff, dropping the
response Body only cancels receiving and must preserve a pending upload.
Any proposed optimization must preserve those contracts and existing tests.
Keep library changes small, measure allocation count/bytes separately from RPS,
and avoid assuming channel or lock cost explains the entire adapter gap.

This branch supplies reproducible code, not a claim that production acceptance
is complete. Keep source/lockfile/toolchain/topology and background load visible
when comparing measurements. Existing older measurements used other harness
versions and must not be presented as fresh runs of this branch.

## License

Product and benchmark sources retain the repository's Apache-2.0 license and
existing source notices. See LICENSE.
