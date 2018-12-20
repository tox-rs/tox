# Tox Bootstrap Node

A server application to run tox bootstrap node.

## Building and running

You'll need [Rust] >= 1.31.0.

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
packets you can change log level to `trace` for `tox` crate:

```sh
RUST_LOG=tox=trace cargo run --release
```

Also it's possible to use syslog via `--log-type` parameter.

## MOTD

MOTD is an abbreviation for The Message of The Day. Tox bootstrap nodes have a
special packet kind called `BootstrapInfo` to retrieve the MOTD alongside with
version. Our node supports basic templates for the MOTD that can be specified
via `--motd` key. It's possible to use the following variables surrounded by
`{{ }}`:
- `start_date`: time when the node was started
- `uptime`: uptime in the format 'XX days XX hours XX minutes'
- `tcp_packets_in`: counter of tcp incoming packets
- `tcp_packets_out`: counter of tcp outgoing packets
- `udp_packets_in`: counter of udp incoming packets
- `udp_packets_out`: counter of udp outgoing packets

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
`TOX_SECRET_KEY` environment variable. Any random string will fit but note that
only strong random generators should be used to generate a secret key. Here are
some examples how you can do it in the terminal:

```sh
openssl rand -hex 32
hexdump -n 32 -e '8 "%08x" 1 "\n"' /dev/random
od -vN 32 -An -tx1 /dev/random | tr -d " \n" ; echo
```

## Config or CLI

In order to run with config, run with `--config <file>`.
Example config.yml is below.
```yaml
log-type: Stderr
keys-file: ./keys
udp-address: 0.0.0.0:33445
tcp-addresses:
  - 0.0.0.0:33445
motd: "{{start_date}} {{uptime}} Tcp: incoming {{tcp_packets_in}}, outgoing {{tcp_packets_out}}, Udp: incoming {{udp_packets_in}}, outgoing {{udp_packets_out}}"
bootstrap-nodes:
  - pk: 1D5A5F2F5D6233058BF0259B09622FB40B482E4FA0931EB8FD3AB8E7BF7DAF6F
    addr: 198.98.51.198:33445
  - pk: DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43
    addr: 185.25.116.107:33445
threads: auto # or any u16 > 0
lan-discovery: True
```
Or you can use it with CLI like this
```sh
tox-node --keys-file keys \
    --bootstrap-node 1D5A5F2F5D6233058BF0259B09622FB40B482E4FA0931EB8FD3AB8E7BF7DAF6F 198.98.51.198:33445 \
    --udp-address '0.0.0.0:33445' --tcp-address '0.0.0.0:33445' \
    --motd "{{start_date}} {{uptime}} Tcp: incoming {{tcp_packets_in}}, outgoing {{tcp_packets_out}}, Udp: incoming {{udp_packets_in}}, outgoing {{udp_packets_out}}"
```

[libsodium]: https://github.com/jedisct1/libsodium
[Rust]: https://www.rust-lang.org
