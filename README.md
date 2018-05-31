# Tox

[![Travis Build Status][travis-badge]][travis-url] [![Appveyor Build Status][appveyor-badge]][appveyor-url] [![Coverage Status][cov-badge]][cov-url] [![Docs][doc-badge]][doc-url] [![Current Crates.io Version][crates-badge]][crates-url] [![Join Gitter][gitter-badge]][gitter-url]

[travis-badge]: https://travis-ci.org/tox-rs/tox.svg?branch=master
[travis-url]: https://travis-ci.org/tox-rs/tox
[appveyor-badge]: https://ci.appveyor.com/api/projects/status/y3y2hi6552qgmfr0/branch/master?svg=true
[appveyor-url]: https://ci.appveyor.com/project/kpp/tox/branch/master
[cov-badge]: https://coveralls.io/repos/github/tox-rs/tox/badge.svg?branch=master
[cov-url]: https://coveralls.io/github/tox-rs/tox?branch=master
[doc-badge]: https://docs.rs/tox/badge.svg
[doc-url]: https://docs.rs/tox
[crates-badge]: https://img.shields.io/crates/v/tox.svg
[crates-url]: https://crates.io/crates/tox
[gitter-badge]: https://badges.gitter.im/tox-rs/tox.svg
[gitter-url]: https://gitter.im/tox-rs/tox

This library is an implementation of [toxcore][toxcore] in [Rust] - P2P,
distributed, encrypted, easy to use DHT-based network.

## Reference

[The Tox Reference](https://zetok.github.io/tox-spec) should be used for
implementing toxcore in Rust. [Reference source repository].

If existing documentation appears to not be complete, or is not clear enough,
issue / pull request should be filled on the reference repository.

## Contributions

... are welcome :smile:. For details, look at
[CONTRIBUTING.md](/CONTRIBUTING.md).

## Dependencies
| **Name** | **Version** |
|----------|-------------|
| libsodium | >=1.0.13 |

## Building
Fairly simple. You'll need [Rust] >= 1.24.0 and [libsodium].

When you'll have deps, build debug version with
```bash
cargo build
```

To run tests:
```bash
cargo test
```
To build docs:
```bash
cargo doc
```
They will be located under `target/doc/`

### With clippy
To build with support for [clippy](https://github.com/rust-lang-nursery/rust-clippy)
(linting), you need nightly Rust. Usually the latest available version is
required.

To build:
```bash
cargo build --features "clippy"
```

To build & test:
```bash
cargo test --features "clippy"
```


## Goals
 - improved toxcore implementation in Rust
 - Rust API
 - documentation
 - tests
 - more

## Progress
*Not listed items are on TODO*. If you're interested in them arriving sooner,
consider helping :wink:

 - [ ] implementing toxcore
    - [ ] DHT Node
        - [x] ping requests & responses
        - [x] nodes requests & responses
        - [x] CookieRequest
        - [ ] CookieResponse (parsed but ignored)
        - [ ] CryptoHandshake (parsed but ignored)
        - [ ] CryptoData (parsed but ignored)
        - [x] LanDiscovery
        - [x] OnionRequest[0,1,2]
        - [x] OnionResponse[3,2,1]
        - [x] OnionAnnounceRequest & OnionDataRequest
        - [ ] OnionAnnounceResponse & OnionDataResponse (parsed but ignored)
        - [x] BootstrapInfo
        - [x] NAT ping requests & responses
    - [ ] TCP Relay
        - [x] Handshake
        - [x] RouteRequest
        - [x] RouteResponse
        - [x] ConnectNotification
        - [x] DisconnectNotification
        - [x] PingRequest
        - [x] PongResponse
        - [x] OobSend
        - [x] OobReceive
        - [x] OnionRequest
        - [x] OnionResponse
        - [x] Data
    - [x] toxencryptsave (aka TES)
 - [x] Rust API

   It will be a subject to changes, and most likely parts that are currently
   public will at later point become hidden. That though depends on the needs.
 - [x] Documentation
    - [x] Simply great. Further improvements in progress.
 - [x] tests
    - [x] tests cover almost all functionality


## License

Licensed under GPLv3+. For details, see [COPYING](/COPYING).

[libsodium]: https://github.com/jedisct1/libsodium
[Reference source repository]: https://github.com/zetok/tox-spec
[Rust]: https://www.rust-lang.org/
[toxcore]: https://github.com/TokTok/c-toxcore
