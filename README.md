# nghttp3 / ngtcp2 interoperability

## Source and purpose

Independent orphan-branch snapshot of wreq-proto
[dcdf949720dbf334c1eb9376a2d93938cc8bc5b6](https://github.com/0x676e67/wreq-proto/commit/dcdf949720dbf334c1eb9376a2d93938cc8bc5b6),
whose product implementation equals dc1cabe. Product sources and protocol tests
are included; SOURCE.json records LF-normalized file hashes. This is an analysis
artifact, not a release (`publish = false`).

This branch tests interoperability and lifecycle behavior. It is **not** a
direct-library versus wreq-proto throughput comparison. For that matrix use
[bench/task-02-http-adapter](https://github.com/0x676e67/wreq-proto/tree/bench/task-02-http-adapter),
whose H3 server is upstream h3 + Quinn. Do not compare these test durations to
benchmark RPS or attribute different peer behavior to client performance.

## Toolchain and dependencies

Rust 1.98 or newer; the short validation uses Windows x64 Rust 1.98.0 with
RUSTFLAGS=-D warnings. Native dependencies require a C/C++ build toolchain,
CMake and the platform prerequisites of the pinned TLS library. Windows uses
Visual Studio C++ Build Tools, MSVC and the Windows SDK. These are not pure Rust
builds. No separately installed server, container, external certificate or
local .agents checkout is needed; the tests create certificates and trust them
only in their test client. First build needs network access for dependencies.

Run the fixture manifest shown below: it owns an independent workspace and
lockfile. It uses the public wreq-proto API through a path within this checkout.
http3 is pinned to PR #104 e7103dc594a88b8473a1f6af477c5e17266767cb.
The fixture client uses published quic/quic-proto 0.12.1 without PR #50.
The root manifest's dev-only quic patch does not propagate to this workspace.
Keep both lockfiles and all Git patch revisions unchanged for comparisons.

## Client contract

Incoming retains the channel architecture. Dropping an unresolved request
future cancels the request; after response handoff, dropping Body cancels
receiving while a pending upload can continue. Cancellation must reach the
peer and release stream/flow-control resources while the connection is alive.
Do not use connection shutdown to hide leaked stream or send-task state.

## Short validation

```sh
cargo test --locked --manifest-path interop/nghttp3/Cargo.toml --test blocked --test cancel_body -- --nocapture
```

Unset H3_QPACK_CASE to run all four QPACK modes. An optional selector is one of
fixed-control, sensitive-control, blocked-response or partial-request.
QPACK coverage requires observed nonzero Required Insert Counts, ongoing table
turnover, an exact Stream Cancellation instruction for a blocked response, and
request cancellation after eight HEADERS bytes. Each scenario crosses the
server's initial 1,000 stream credit. The Body test verifies 128 requests / 64
cancellations, live connection with zero active streams, then request 129 and
normal process cleanup. The native server binds 127.0.0.1:4433, so keep that UDP
port free and run these test binaries sequentially.

The separate churn test defaults to **300 seconds**. For a short smoke run:

```sh
H3_QPACK_SECONDS=3 cargo test --locked --manifest-path interop/nghttp3/Cargo.toml --test churn -- --nocapture
```

PowerShell: set `$env:H3_QPACK_SECONDS='3'` before the same Cargo command.
Do not run bare `cargo test` on this fixture if a five-minute run is unintended.
For formatting: `cargo +nightly fmt --manifest-path interop/nghttp3/Cargo.toml`.

## Peer and licensing

nghttp3 1.18.0 + ngtcp2 1.25.0 via nghttp3-sys/ngtcp2-sys 0.2.0, AWS-LC 0.43.0.
The native wrapper derives from the fixed
[http3 benchmark 0289b7d5ac4d04ee3db324aba95d20c1e6084a53](https://github.com/0x676e67/http3/tree/0289b7d5ac4d04ee3db324aba95d20c1e6084a53/bench).
It adds bounded x-churn echo, cancellation counters and a read-only live-stream
snapshot. Native files retain MIT notices and fixed-source links; the wrapper
retains LICENSE-APACHE. Root protocol sources retain LICENSE and source notices.
Old failed experiments, log files, proxy code and measured memory claims are
not part of this runnable snapshot.
