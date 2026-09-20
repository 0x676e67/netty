# Cloudflare tokio-quiche interoperability

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
cargo test --locked --manifest-path interop/quiche/Cargo.toml --test client -- --nocapture
```

Two tests cover empty/128 KiB responses with GREASE off/on, then 32 callers / 128
requests / 64 Body cancellations. The client retains the connection until the
server reports zero active streams and zero send tasks, checks cancellation
count and fresh stream credit, and then closes normally. Ports are selected
locally; no fixed external endpoint is contacted.

For formatting: `cargo +nightly fmt --manifest-path interop/quiche/Cargo.toml`.

## Peer and licensing

tokio-quiche 0.19.1 / quiche 0.29.3, from Cloudflare's fixed
[09b125d4cfc16e78d73d8382c93926f3aba063d4](https://github.com/cloudflare/quiche/commit/09b125d4cfc16e78d73d8382c93926f3aba063d4).
The peer uses native BoringSSL. Setup follows the official async HTTP/3 server
example; its BSD-2-Clause notice is retained in client.rs and
interop/quiche/CLOUDFLARE-COPYING. Root sources retain their Apache-2.0 LICENSE.

Dynamic QPACK is disabled: this fixed quiche version does not supply dynamic
table coverage. Use the separate interop/task-02-nghttp3 branch for that purpose.
These tests do not establish performance budgets or long-term resource bounds.
