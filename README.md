# netty

[![CI](https://github.com/0x676e67/netty/actions/workflows/ci.yml/badge.svg)](https://github.com/0x676e67/netty/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/netty.svg)][license]
[![Crates.io](https://img.shields.io/crates/v/netty.svg)](https://crates.io/crates/netty)

Async network clients, down to the wire.

## Features


- [HTTP/1](https://www.rfc-editor.org/rfc/rfc9112.html) and [HTTP/2](https://www.rfc-editor.org/rfc/rfc9113.html) implementations.
- HTTP Upgrade and CONNECT tunnels, including [HTTP/2 Extended CONNECT](https://www.rfc-editor.org/rfc/rfc8441.html).
- [HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html) over a [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) connection established by the caller.
- HTTP/3 Extended CONNECT and [HTTP Datagrams](https://www.rfc-editor.org/rfc/rfc9297.html).
- Streaming bodies and trailers with backpressure.
- Pluggable executor, timer and transport interfaces implemented by the caller.
- Carries forward [Hyper]'s client-side implementation.

## Usage

Add the protocol crate to `Cargo.toml`:

```toml
[dependencies]
netty = "0.2"
```

The client APIs are organized by protocol:

```rust
use netty::conn::{http1, http2};

fn main() {
    // ...
}
```

## Documentation

- [Protocol API][protocol-api]
- [Runtime contracts](https://docs.rs/netty/latest/netty/rt/)

## License

Licensed under either of Apache License, Version 2.0 ([LICENSE][license] or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the [Apache-2.0][license] license, shall be licensed as above, without any additional terms or conditions.

## FAQ

**Is this the Java networking framework?**

[No](https://netty.io).

[Hyper]: https://github.com/hyperium/hyper
[protocol-api]: https://docs.rs/netty
[license]: ./LICENSE
