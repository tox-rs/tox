# Tox Bootstrap Node

A server application to run tox bootstrap node.

## Building and running

You'll need [Rust] >= 1.26.0 and [libsodium].

Build with:

```sh
cargo build --release
```

Run with:

```sh
cargo run --release
```

If you want to change default log level you can do it via setting `RUST_LOG`
environment variable. For example, if you want to see all received and sent
packets you can change log level to `trace` for `tox_node`:

```sh
RUST_LOG=tox_node=trace cargo run --release
```

Also it's possible to use syslog via `--log-type` parameter.

## Keys generation

In order to run node you have to provide either secret key or path to a keys file.

### Keys file

Keys file is a binary file with sequentially stored public and secret keys. Path
to a keys file can be specified via `--keys-file` argument. If file doesn't
exist it will be created with automatically generated keys. The format of this
file is compatible with `tox-bootstrapd`.

You may also extract the key from the file:

```sh
hexdump -s32 -e '32/1 "%02x" "\n"' ./key
```

### Secret key

Secret key is a hexadecimal string of size 32 bytes. It can be specified via
`--secret-key` argument. Any random string will fit but note that only strong
random generators should be used to generate a secret key. Here are some
examples how you can do it in the terminal:

```sh
openssl rand -hex 32
hexdump -n 32 -e '8 "%08x" 1 "\n"' /dev/random
od -vN 32 -An -tx1 /dev/random | tr -d " \n" ; echo
```

[libsodium]: https://github.com/jedisct1/libsodium
[Rust]: https://www.rust-lang.org
