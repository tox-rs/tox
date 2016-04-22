# Tox  [![Build Status](https://travis-ci.org/zetok/tox.svg?branch=master)](https://travis-ci.org/zetok/tox)

This library is an implementation of [toxcore][toxcore] in Rust - P2P,
distributed, encrypted, easy to use DHT-based network.

IRC channel: [#zetox @ freenode](https://webchat.freenode.net/?channels=zetox)

## Documentation

[The Tox Reference](https://github.com/TokTok/tox-spec) should be used for
implementing toxcore in Rust.

Sadly, due to CLA upstream lacks with integrating documentation improvements,
so for now [fork](https://github.com/zetok/tox-spec) will have to do.

If existing documentation appears to not be complete, or is not clear enough,
issue / pull request should be filled on the [reference repository]
(https://github.com/TokTok/tox-spec/issues/new).

Current [API docs](https://zetok.github.io/tox) are a subject to changes.

## Contributions

... are welcome :smile:. For details, look at
[CONTRIBUTING.md](/CONTRIBUTING.md).

## Dependencies
| **Name** | **Version** |
|----------|-------------|
| libsodium | >=1.0.0 |

## Building
Fairly simple. You'll need [Rust] and [libsodium].

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
    - with help of [rusty-cheddar]?
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
 - [x] Rust API
   
   It will be a subject to changes, and most likely parts that are currently
   public will at later point become hidden. That though depends on the needs.
 - [x] Documentation
    - [x] Simply great. Further improvements in progress.
 - tests
    - [x] tests cover almost all functionality
    - [x] tested against [hstox], using [Tox Tester], T.T for short


## License

Licensed under GPLv3+. For details, see [COPYING](/COPYING).

[toxcore]: https://github.com/irungentoo/toxcore
[Rust]: https://www.rust-lang.org/
[libsodium]: https://github.com/jedisct1/libsodium
[rusty-cheddar]: https://github.com/Sean1708/rusty-cheddar
[hstox]: https://github.com/TokTok/hstox
[Tox Tester]: https://github.com/zetok/tox-protocol-test
