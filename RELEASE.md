# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## netty [0.3.0](https://github.com/0x676e67/netty/compare/v0.2.5...v0.3.0) - 2026-10-29



### 🚀 Features

- *(http1)* Add max_header_size limit for server and client ([#149](https://github.com/0x676e67/netty/issues/149)) - ([22a2b4a](https://github.com/0x676e67/netty/commit/22a2b4aa4fa8cfa532792ecfa6cc176d891fda10))
- *(http2)* Gate extended CONNECT on peer SETTINGS ([#151](https://github.com/0x676e67/netty/issues/151)) - ([3703f25](https://github.com/0x676e67/netty/commit/3703f250846b832f222dc284e84af771c7e855a2))
- *(http3)* 💥 **breaking:** Configure pseudo-header order through options ([#167](https://github.com/0x676e67/netty/issues/167)) - ([3070e05](https://github.com/0x676e67/netty/commit/3070e0515e28af4177695cb2b2bfcbed6dbb561c))
- *(proxy)* Add SOCKS5 UDP ASSOCIATE with sans-IO datagram framing ([#154](https://github.com/0x676e67/netty/issues/154)) - ([e83ecb4](https://github.com/0x676e67/netty/commit/e83ecb4a23ef6b96ea55f9a410a4955cf1e49683))
- *(proxy)* Add MASQUE CONNECT-UDP over HTTP/2 - ([8da4b0b](https://github.com/0x676e67/netty/commit/8da4b0b1a20678a6961481a3808ba73da47df7b0))
- *(proxy)* Add SOCKS connector backed by tokio-socks ([#161](https://github.com/0x676e67/netty/issues/161)) - ([6c475e7](https://github.com/0x676e67/netty/commit/6c475e73d4ade28d43d0f9530a58262623c2a24a))
- *(proxy)* Add HTTP CONNECT tunnel connector ([#152](https://github.com/0x676e67/netty/issues/152)) - ([6e89ccb](https://github.com/0x676e67/netty/commit/6e89ccbf31331f9b3638e447632bab3a3b72e997))
- *(proxy)* Keep the control peer's scope in SOCKS5 relay_addr - ([2497b75](https://github.com/0x676e67/netty/commit/2497b75119cf53bbd20de97f4adbde7c964abe71))
- *(proxy)* Add MASQUE CONNECT-UDP client - ([ee3b819](https://github.com/0x676e67/netty/commit/ee3b819dccefe42c46f62a603c1d22500a17bab5))
- *(proxy)* Add SOCKS5 UDP ASSOCIATE with sans-IO datagram framing - ([148a469](https://github.com/0x676e67/netty/commit/148a46901a489c7725faaa613e9f353be74dbed8))
- *(proxy)* Add SOCKS connector backed by tokio-socks - ([9c402da](https://github.com/0x676e67/netty/commit/9c402daa2e26a6cdadf8d0ed86c017739d26689a))
- *(proxy)* Add HTTP CONNECT tunnel connector - ([d5257b8](https://github.com/0x676e67/netty/commit/d5257b8d28734e35cdab8ea710daf67f379b885e))

### 🐛 Bug Fixes

- *(http1)* Remove content-length if transfer-encoding is auto-added ([#166](https://github.com/0x676e67/netty/issues/166)) - ([f6dd929](https://github.com/0x676e67/netty/commit/f6dd9291f2823dfe615b1ae41c4f16afa3ae7cb0))
- *(http1)* Always remove content-length if transfer-encoding is sent ([#165](https://github.com/0x676e67/netty/issues/165)) - ([688f481](https://github.com/0x676e67/netty/commit/688f481deeebc3a2d592efd6866ed8636f542da9))
- *(http1)* Let a Connection close token win over a later keep-alive ([#147](https://github.com/0x676e67/netty/issues/147)) - ([a5ec550](https://github.com/0x676e67/netty/commit/a5ec55002583e16c0730247e1a3a406e76d3bd24))
- *(http1)* Close canceled connections without flushing ([#145](https://github.com/0x676e67/netty/issues/145)) - ([f8652dd](https://github.com/0x676e67/netty/commit/f8652ddf5e386d66b7f03cceedbc6b319d849762))
- *(http2)* Ignore content-length on 2xx responses to CONNECT ([#171](https://github.com/0x676e67/netty/issues/171)) - ([b8d0d0d](https://github.com/0x676e67/netty/commit/b8d0d0d345283a1d4fa0a2101c49e473f34abb90))
- *(http2)* Open CONNECT tunnels on any 2xx and share the Hyper proxy test fixture ([#170](https://github.com/0x676e67/netty/issues/170)) - ([49237fd](https://github.com/0x676e67/netty/commit/49237fd7caf833a0e1aa1a52602340d31d62affb))
- *(http2)* Do not reserve capacity for idle Upgraded streams ([#140](https://github.com/0x676e67/netty/issues/140)) - ([f598a3e](https://github.com/0x676e67/netty/commit/f598a3edfcc72c4ad0ca7e1a0aff884ee1cff3d7))
- *(http3)* End only the tunnel send direction when a write reports a peer stop ([#181](https://github.com/0x676e67/netty/issues/181)) - ([fa54e31](https://github.com/0x676e67/netty/commit/fa54e31d018279d009dee362b5d4fb9036edffbd))
- *(http3)* Abort refused CONNECT-UDP and reject capsule-breaking 2xx ([#174](https://github.com/0x676e67/netty/issues/174)) - ([1a2cf19](https://github.com/0x676e67/netty/commit/1a2cf19ad71559ef960176b61c72f5772b55be8a))
- *(http3)* Tighten RFC 9114 compliance ([#172](https://github.com/0x676e67/netty/issues/172)) - ([a0565dc](https://github.com/0x676e67/netty/commit/a0565dc1c0f19e9866ddcabe175361e2eee91a98))
- *(http3)* Reset both directions of a malformed CONNECT response head - ([02c61b4](https://github.com/0x676e67/netty/commit/02c61b4bd92c17433ece97e708495c90cb4ceae4))
- *(masque)* Stop HTTP/2 tunnel receive on drop and close sends on reset ([#188](https://github.com/0x676e67/netty/issues/188)) - ([163c6b4](https://github.com/0x676e67/netty/commit/163c6b45973b8b7acec1a66e24e160349a546374))
- *(masque)* Restore proxy validation and close datagrams before stream resets ([#184](https://github.com/0x676e67/netty/issues/184)) - ([47118e2](https://github.com/0x676e67/netty/commit/47118e240b8d8ddb21e9287b4ec5b8faf2e05c7f))
- *(masque)* Reject templates that do not expand to a URI and correct docs ([#183](https://github.com/0x676e67/netty/issues/183)) - ([95dc6a8](https://github.com/0x676e67/netty/commit/95dc6a8dc4347f588affd6af3daacd28b8baa0c5))
- *(masque)* Split tunnel halves and follow RFC datagram close semantics ([#180](https://github.com/0x676e67/netty/issues/180)) - ([0b86df5](https://github.com/0x676e67/netty/commit/0b86df5a9c7e2a31b31d90b3b52a910ee8918f90))
- *(masque)* Harden HTTP/3 close handling and template validation ([#178](https://github.com/0x676e67/netty/issues/178)) - ([7114888](https://github.com/0x676e67/netty/commit/71148886d26900944d22d59668480746c68c9e75))
- *(masque)* Tighten tunnel limits, receive fairness and test coverage ([#177](https://github.com/0x676e67/netty/issues/177)) - ([7834b9d](https://github.com/0x676e67/netty/commit/7834b9d65939222279fd0ab4bd356b159da38ff5))
- *(masque)* Report unusable datagram limits and drop extra send copies ([#175](https://github.com/0x676e67/netty/issues/175)) - ([f84b764](https://github.com/0x676e67/netty/commit/f84b7646e8a6b5b7492042d9781e8b726d0682ad))
- *(proxy)* Validate MASQUE proxy and target hosts and give flushes their own wakeup - ([6c526c4](https://github.com/0x676e67/netty/commit/6c526c4b76d89b7bab7e5d55f43ba80689f9d0fa))
- *(proxy)* Check CONNECT-UDP capsule framing in every build and tie stream resets to the IO - ([284bb38](https://github.com/0x676e67/netty/commit/284bb38a79e19acc677c51912aecde97d6ce1ec6))
- *(proxy)* Abort unclosed HTTP/2 CONNECT-UDP tunnels on drop and require the client's upgrade - ([78e9150](https://github.com/0x676e67/netty/commit/78e9150ab5a3cfbbcbf22bab04122f936067b1b8))
- *(proxy)* Reset malformed MASQUE responses and wake senders on MTU change ([#163](https://github.com/0x676e67/netty/issues/163)) - ([978e842](https://github.com/0x676e67/netty/commit/978e84217b90641324aa1743bde2e2f66d062319))
- *(proxy)* Reset malformed HTTP/2 CONNECT-UDP streams with PROTOCOL_ERROR - ([c50af25](https://github.com/0x676e67/netty/commit/c50af258d1a85ed36b4094842485f3593b3e1ffd))
- *(proxy)* Reset truncated MASQUE capsules with H3_MESSAGE_ERROR - ([06dc56a](https://github.com/0x676e67/netty/commit/06dc56aef2516212fab371d48ac5cdcb5c56db78))
- *(proxy)* Reset malformed MASQUE responses and wake senders on MTU change - ([4860e91](https://github.com/0x676e67/netty/commit/4860e9118ac8e5a2aa9a8a7ad8c56a38bce5e7fb))
- *(proxy)* Tighten MASQUE validation and Datagram session teardown - ([db6b720](https://github.com/0x676e67/netty/commit/db6b7203eb7a2e3ef4ecaacdc814f901f56dde81))
- *(proxy)* Harden MASQUE close, receive budget and target checks - ([492212b](https://github.com/0x676e67/netty/commit/492212b9ee452c3fe8a0b57049c4801858b5797f))
- *(proxy)* Match link-local SOCKS5 relays by scope - ([494b6dd](https://github.com/0x676e67/netty/commit/494b6dd0532213366a3038e5c499b54c334a586e))
- *(proxy)* Split mixed SOCKS5 UDP batches and read mapped addresses as IPv4 - ([e5f2d80](https://github.com/0x676e67/netty/commit/e5f2d806a87968180774f595cfa6d66f9f2d969c))
- *(proxy)* Check SOCKS destination and credentials before connecting - ([7d40b22](https://github.com/0x676e67/netty/commit/7d40b22b602c510d084320543c7f286877bf9493))
- *(proxy)* Validate CONNECT target and harden tunnel handshake - ([6cd06dd](https://github.com/0x676e67/netty/commit/6cd06dd3f0e3cd9d2454c1bbd9458b92ff6840a8))

### 🚜 Refactor

- *(proxy)* Share lock poison recovery and the CONNECT-UDP test request - ([e805792](https://github.com/0x676e67/netty/commit/e805792d92180b1ac2592f44b7956484088f267e))
- *(proxy)* Open HTTP/2 CONNECT-UDP tunnels synchronously and ungate stream resets - ([fec701d](https://github.com/0x676e67/netty/commit/fec701d1b2aa5f1327ce01efb664fbbd64c8561f))
- *(proxy)* Limit MASQUE CONNECT-UDP to HTTP/3 - ([c9d0c7a](https://github.com/0x676e67/netty/commit/c9d0c7a92270bbc09406660ca9d909cdea9f6c0f))

### 📚 Documentation

- *(http3)* Describe datagram limits and connection close outcomes ([#176](https://github.com/0x676e67/netty/issues/176)) - ([f0ea808](https://github.com/0x676e67/netty/commit/f0ea808dd498b5d44c92d4808658bff5cb8a8ba3))

### ⚡ Performance

- *(body)* Skip waking a closed peer when a channel end drops ([#150](https://github.com/0x676e67/netty/issues/150)) - ([663b094](https://github.com/0x676e67/netty/commit/663b094fe80389c393880d8d5168c73131629336))
- *(http2)* Shrink tasks and defer cancellation channel allocation ([#182](https://github.com/0x676e67/netty/issues/182)) - ([c671f45](https://github.com/0x676e67/netty/commit/c671f45299bff5b6a8bcc4c37dafbc0dba0d0f6f))
- *(http3)* Box connection task to shrink spawned futures ([#189](https://github.com/0x676e67/netty/issues/189)) - ([4197732](https://github.com/0x676e67/netty/commit/41977320273a564e9e26b597e5d91ecdab7d8bb4))

### 🎨 Styling

- *(lib)* Address cast-possible-truncation clippy findings ([#148](https://github.com/0x676e67/netty/issues/148)) - ([3fa9152](https://github.com/0x676e67/netty/commit/3fa91527201cd138ad3c20ef50547cfc17b734a2))

### 🧪 Testing

- *(proxy)* Use Hyper for HTTP/2 CONNECT-UDP regressions - ([2ad290d](https://github.com/0x676e67/netty/commit/2ad290de9c5a370eef31d7f8d949d44e82d6f706))
- *(proxy)* Answer SOCKS5 handshakes with fast-socks5 - ([b60241c](https://github.com/0x676e67/netty/commit/b60241c6bed814be134d1a0c212e255bc338ad4c))
- *(proxy)* Move QUIC relay fixture to local harness - ([586ef29](https://github.com/0x676e67/netty/commit/586ef29809baf3726559f3459c3b6f8a9241b8ce))
- *(proxy)* Relay SOCKS5 UDP through fast-socks5 - ([583916d](https://github.com/0x676e67/netty/commit/583916d5956fbf677dca2008efa87385879b9cc9))
- *(proxy)* Use Hyper for CONNECT regressions - ([9a2c673](https://github.com/0x676e67/netty/commit/9a2c673855e094be27e180447a2c12f1a924967b))

### ⚙️ Miscellaneous Tasks

- Bump MSRV to 1.98 and edition to 2024 ([#142](https://github.com/0x676e67/netty/issues/142)) - ([0b1799b](https://github.com/0x676e67/netty/commit/0b1799b6459a72186108bd8808f9ed11e0402999))
## [0.2.5] - 2026-09-25

### 🚀 Features

- *(client)* Expose HTTP/2 current max stream count (#35)
- *(client)* Implement Eq and Hash for HTTP options (#37)
- *(client)* Implement the HTTP/2 extended CONNECT protocol from RFC 8441 (#41)
- *(client)* Add a `TrySendError::message()` method (#43)
- *(client)* Add a `TrySendError::error()` method (#44)
- *(error)* Add `Error::is_shutdown()` (#45)
- *(client)* Add HTTP/2 `max_local_error_reset_streams` option (#47)
- *(http2)* Add  `reset_stream_duration()` client option (#49)
- *(http3)* Add client connections over external QUIC transports
- *(http3)* Expose request extensions and document cancellation
- *(http3)* Adapt http3 transports with rt::quic::Compat

### 🐛 Bug Fixes

- *(ci)* Use default Cargo Dependabot strategy
- *(http2)* Fix internals of HTTP/2 CONNECT upgrades (#38)
- *(http2)* Avoid buffering `Upgraded` writes without send capacity (#40)
- *(http1)* More strictly enforce max_buf_size when parsing (#53)
- *(http1)* Flush buffered data before shutdown (#54)
- *(http1)* Use append for repeat trailers (#55)
- *(http1)* Allow up to max_headers trailers (#56)
- *(release)* Configure workspace publishing and changelogs (#58)
- *(http1)* Use append for repeat trailer values in encoder (#59)
- *(http1)* Evict pooled conn on request-side Connection: close (#60)
- *(http1)* Flush bytes buffered by the write re-check before yielding (#61)
- *(http1)* Recognize `\n\r\n` as a head terminator in the partial-read fast path (#63)
- *(http1)* Preserve hop-by-hop when setting close or keep-alive (#78)
- *(http3)* Preserve uploads when response bodies are dropped
- *(http3)* Discard datagrams after receive cancellation
- *(http3)* Apply header preservation callback
- *(http3)* Omit implicit zero content length for bodyless methods
- *(http3)* Dispatch queued requests after sender drop
- *(http3)* Report remaining response body length
- *(http3)* Tolerate lengths on responses without content
- *(http3)* Strip connection headers before sending
- *(http3)* Wait for upload acknowledgment before draining
- *(bench)* Stop the native HTTP/3 driver after measurement
- *(http3)* Wake settings waiters on graceful shutdown
- *(http3)* Keep connections open after senders drop
- Restore empty default features
- *(http3)* Drain connections when the last sender drops
- *(http3)* Preserve CONNECT permission errors while draining
- *(deps)* Pin http3 dependencies directly to git
- *(ci)* Patch HTTP/3 for release-plz baseline

### 🚜 Refactor

- *(http3)* Reuse shared request dispatch
- *(http3)* Receive response bodies directly from split streams
- *(http3)* Replace SendStream::stopped with poll_stopped
- Use futures-util boxed future aliases and bump http3 patch
- *(http3)* Run requests in the caller's future and the connection task on the executor
- *(http3)* Simplify connection and datagram drivers
- *(http3)* Align connection generic bounds
- *(http3)* Align request body bounds
- *(http3)* Unify client task structure
- *(http3)* Use caller-driven requests (#81)
- *(http3)* Use named polling futures (#82)

### 📚 Documentation

- Improve `ext` module overview and `Protocol` docs (#42)
- *(error)* Add more information about `is_incomplete_message()` (#46)
- *(client)* Document Drop behavior for Connection types (#48)
- *(client)* Document cancel safety for client send_request futures (#50)
- *(error)* Add detailed doc comments to Error query methods (#51)
- *(body)* Add streaming read examples (#64)
- *(lib)* Expand crate-level cancel safety section with HTTP/1 vs HTTP/2 (#66)
- *(client)* Fix HTTP/2 max concurrent stream link to spec
- *(dispatch)* Explain envelope ownership and cancellation
- *(dispatch)* Describe receiver and callback lifetimes
- *(dispatch)* Document response delivery task
- Simplify README and list HTTP/3 support
- Shorten HTTP/3 feature description
- *(http3)* Clarify send completion contract
- *(http3)* Describe the connection model, feature gates and internal types
- *(http3)* Align request method documentation
- *(http3)* Clarify request recovery boundary
- *(http3)* Clarify generic executor implementations
- *(quic)* Require idempotent connection close
- *(rt)* Improve `rt` module overview (#79)
- *(client)* Fix HTTP/2 max concurrent stream link to spec (#80)

### ⚡ Performance

- *(http2)* Reserve minimal send capacity when piping request bodies (#62)
- *(body)* Simpler custom Incoming channel (#67)
- *(http3)* Borrow exchange failure state
- *(body)* Avoid waking closed senders
- *(body)* Batch HTTP/3 body chunks per channel handoff
- *(http3)* Parse the request content-length once
- *(http3)* Avoid repeated shutdown cancellation

### 🎨 Styling

- *(lib)* Fix missing_errors_doc lint (#65)
- Normalize release notes and HTTP/3 spacing
- Fmt code
- Fmt code

### 🧪 Testing

- *(http3)* Cover upload failures after response handoff
- *(http3)* Pin QUIC cancellation fix for validation
- *(http3)* Keep dependency lifecycle checks outside product suite
- *(http3)* Reuse http3-quic in the native QUIC test transport
- *(http3)* Drop GOAWAY rejection tests

### ⚙️ Miscellaneous Tasks

- *(http3)* Pin independent receive cancellation support
- *(http3)* Retain channel reception without receive-control dependency
- *(http3)* Remove unused tokio-util runtime feature
- Remove local workspace exclusions
- *(http3)* Update driver lifecycle dependency
- Update hwire repository links (#83)
## [wreq-rt-v0.2.2-rc.4] - 2026-05-31

### 🐛 Bug Fixes

- *(http1)* Fix busy loop when peer half-closes and open body (#27)

### 🧪 Testing

- *(client)* Fix misuse of `path_and_query` in CONNECT test (#25)

### ⚙️ Miscellaneous Tasks

- Release (#26)
## [wreq-rt-v0.2.2-rc.3] - 2026-05-21

### 🚜 Refactor

- *(lib)* Use a panic_if_poisoned() helper for mutexes (#21)
- *(lib)* Replace unwraps with expects (#22)

### 🧪 Testing

- *(proto)* Add dropped conn send incomplete body test (#20)

### ⚙️ Miscellaneous Tasks

- Release (#23)
## [wreq-rt-v0.2.2-rc.2] - 2026-05-10

### 💼 Other

- Add wreq-rt (#17)

### ⚡ Performance

- *(rt)* Improve poll read (#19)

### ⚙️ Miscellaneous Tasks

- Add homepage
- Release (#18)
## [0.2.2] - 2026-05-08

### 🐛 Bug Fixes

- *(http2)* Do not reserve capacity before body data is available (#15)

### ⚙️ Miscellaneous Tasks

- Release v0.2.2 (#14)

### ◀️ Revert

- "build(deps): reduce dependency on futures-channel" (#16)
## [0.2.1] - 2026-04-29

### 📚 Documentation

- *(body)* Fix docs build (#12)

### ⚙️ Miscellaneous Tasks

- Release v0.2.1 (#13)
## [0.2.0] - 2026-04-29

### 🚜 Refactor

- *(ext)* Rename method to `call_visit` and clarify its purpose (#10)

### ⚙️ Miscellaneous Tasks

- Release v0.2.0 (#11)
## [0.1.0] - 2026-04-29

### 🚀 Features

- *(rt)* Runtime-agnostic (#5)
- *(ext)* Add `ext::on_informational()` callback extension (#6)
- *(ext)* Add `ext::on_preserve_header()` callback extension (#7)

### 💼 Other

- Update benches

### 🧪 Testing

- Update tests (#4)

### ⚙️ Miscellaneous Tasks

- Release-plz
- Release v0.1.0 (#8)
