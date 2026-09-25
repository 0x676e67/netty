# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## netty [0.2.6](https://github.com/0x676e67/netty/compare/v0.2.5...v0.2.6) - 2026-09-25


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
