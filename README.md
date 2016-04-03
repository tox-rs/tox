# Tox  [![Build Status](https://travis-ci.org/zetok/tox.svg?branch=master)](https://travis-ci.org/zetok/tox)
This library is an implementation of [toxcore][toxcore] in Rust - P2P,
distributed, encrypted, easy to use DHT-based network.

IRC channel: [#zetox @ freenode](https://webchat.freenode.net/?channels=zetox)

## Documentation

[The Tox Reference](https://github.com/TokTok/tox-spec) should be used for
implementing toxcore in Rust.

If existing documentation appears to not be complete, or is not clear enough,
issue / pull request should be filled on the [reference repository]
(https://github.com/TokTok/tox-spec/issues/new).

Current [API docs](https://zetok.github.io/tox) are a subject to changes.

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


## License

Licensed under GPLv3+. For details, see [COPYING](/COPYING).

[toxcore]: https://github.com/irungentoo/toxcore
