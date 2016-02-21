# Tox  [![Build Status](https://travis-ci.org/zetok/tox.svg)](https://travis-ci.org/zetok/tox)
This library is an implementation of [toxcore][toxcore] in Rust - P2P, distributed, encrypted, easy to use DHT-based network.

IRC channel: [#zetox @ freenode](https://webchat.freenode.net/?channels=zetox)

## Documentation

Documentation to use when implementing toxcore in Rust is a bit scattered around. It can be found at:
 - [The Tox Reference](https://github.com/iphydf/tox-spec)
 - [Docs bundled with toxcore](https://github.com/irungentoo/toxcore/tree/master/docs)
 - [Comments in toxcore source code](https://github.com/irungentoo/toxcore/tree/master/toxcore)

Existing documentation may not be complete, and as such reading toxcore's source in C might be a necessity.


## Contributing
Contributing guidelines: [CONTRIBUTING.md](/CONTRIBUTING.md).

## Dependencies
| **Name** | **Version** |
|----------|-------------|
| libsodium | 1.0.8 |

## Building
Fairly simple. You'll need [Rust](http://www.rust-lang.org/) and libsodium.

Currently git version of `sodiumoxide` is required. To compile it successfully:
```bash
git clone https://github.com/dnaq/sodiumoxide && \
mkdir .cargo
echo 'paths = ["sodiumoxide/libsodium-sys"]' >> .cargo/config
```

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


## Goals
 - improved toxcore implementation in Rust
 - Rust API
 - "old" C API for compatibility
 - documentation
 - tests
 - more


## License

Licensed under GPLv3+. For details, see [COPYING](/COPYING).

[toxcore]: https://github.com/irungentoo/toxcore
