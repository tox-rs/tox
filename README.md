# Tox  [![Build Status](https://travis-ci.org/zetok/tox.svg?branch=master)](https://travis-ci.org/zetok/tox) [![Coverage Status](https://coveralls.io/repos/github/zetok/tox/badge.svg?branch=master)](https://coveralls.io/github/zetok/tox?branch=master)

This library is an implementation of [toxcore][toxcore] in Rust - P2P,
distributed, encrypted, easy to use DHT-based network.

IRC channel: [#zetox @ freenode](https://webchat.freenode.net/?channels=zetox)

## Documentation

[The Tox Reference](https://zetok.github.io/tox-spec) should be used for
implementing toxcore in Rust.

If existing documentation appears to not be complete, or is not clear enough,
issue / pull request should be filled on the [reference repository].

Current [API docs](https://zetok.github.io/tox) are a subject to changes.

## Contributions

... are welcome :smile:. For details, look at
[CONTRIBUTING.md](/CONTRIBUTING.md).

## Dependencies
| **Name** | **Version** |
|----------|-------------|
| libsodium | >=1.0.0 |

## Building
Fairly simple. You'll need [Rust] >= 1.11.0 and [libsodium].

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
To build with support for [clippy](https://github.com/Manishearth/rust-clippy)
(linting), you need nightly Rust. Usually the latest available version is
required.

To build:
```
cargo build --features "clippy"
```

To build & test:
```
cargo test --features "clippy"
```


## Goals
 - improved toxcore implementation in Rust
 - Rust API
 - "old" C API for compatibility
 - documentation
 - tests
 - more

## Progress
*Not listed items are on TODO*. If you're interested in them arriving sooner,
consider helping :wink:

 - [ ] implementing toxcore
    - [ ] DHT
        - [x] ping requests & responses
        - [x] nodes requests & responses
        - [x] NAT ping requests & responses
    - [x] toxencryptsave (aka TES)
 - [ ] C API – [CAPI]
    - [x] toxencryptsave
 - [x] Rust API
   
   It will be a subject to changes, and most likely parts that are currently
   public will at later point become hidden. That though depends on the needs.
 - [x] Documentation
    - [x] Simply great. Further improvements in progress.
 - [x] tests
    - [x] tests cover almost all functionality
    - [x] tested against [hstox], using [Tox Tester], T.T for short


## License

Licensed under GPLv3+. For details, see [COPYING](/COPYING).

[CAPI]: https://github.com/quininer/tox-capi
[hstox]: https://github.com/TokTok/hstox
[libsodium]: https://github.com/jedisct1/libsodium
[reference repository]: https://github.com/zetok/tox-spec/issues/new
[Rust]: https://www.rust-lang.org/
[Tox Tester]: https://github.com/zetok/tox-protocol-test
[toxcore]: https://github.com/irungentoo/toxcore
