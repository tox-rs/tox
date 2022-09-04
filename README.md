# Tox

[![Github Build Status][gh-badge]][gh-url] [![Coverage Status][cov-badge]][cov-url] [![Docs][doc-badge]][doc-url] [![Current Crates.io Version][crates-badge]][crates-url] [![Join Gitter][gitter-badge]][gitter-url]

[gh-badge]: https://github.com/tox-rs/tox/workflows/Rust/badge.svg?branch=master
[gh-url]: https://github.com/tox-rs/tox/actions?query=branch%3Amaster
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

...are welcome. :smile: For details, look at
[CONTRIBUTING.md](/CONTRIBUTING.md).

## Building
Fairly simple. First, install [Rust] >= 1.58 and a C compiler ([Build Tools
for Visual Studio][VSBuild] on Windows, GCC or Clang on other platforms).

Then you can build the debug version with

```bash
cargo build
```

To run tests, use:

```bash
cargo test
```

To build docs and open them in your browser:

```bash
cargo doc --open
```

### With clippy
To check for [clippy](https://github.com/rust-lang-nursery/rust-clippy) warnings
(linting), you need nightly Rust with `clippy-preview` component.

To check:

```bash
cargo clippy --all
```

To check with tests:

```bash
cargo clippy --all --tests
```


## Goals
 - improved toxcore implementation in Rust
 - Rust API
 - documentation
 - tests
 - more

## Progress

A fully working tox-node written in pure Rust with a DHT server and a TCP relay
can be found [here](https://github.com/tox-rs/tox-node).

Right now we are working on the client part.


## Authors

[zetox](https://github.com/zetok/tox) was created by [Zetok Zalbavar](https://github.com/zetok/)
(zetok/openmailbox/org) and assimilated by the tox-rs team.

tox-rs has contributions from many users. See [AUTHORS.md](/AUTHORS.md). Thanks everyone!

## License

Licensed under [GPLv3+](/LICENSE) with [Apple app store exception](/COPYING.iOS).

[Reference source repository]: https://github.com/zetok/tox-spec
[Rust]: https://www.rust-lang.org/
[VSBuild]: https://visualstudio.microsoft.com/downloads/
[toxcore]: https://github.com/TokTok/c-toxcore
