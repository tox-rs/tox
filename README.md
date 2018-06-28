# Tox Bootstrap Node

A server application to run tox bootstrap node.

## Building and running

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
