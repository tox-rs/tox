# Tox Bootstrap Node

A server application to run tox bootstrap node.

## Building and running

You'll need [Rust] >= 1.64.

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

### Running tox-node in docker

There is a [docker repository] of tox-node with exposed 443/tcp 3389/tcp 33445/tcp 33445/udp ports.
You can run tox-node using docker like this:

```sh
TOX_SECRET_KEY=<secret key> docker run -e TOX_SECRET_KEY toxrust/tox-node <ARGS>
```

or

```sh
docker run --mount type=bind,source=<path/to/config.yml>,target=<path/to/target/config.yml> \
    --mount type=bind,source=<path/to/keys>,target=/var/lib/tox-node/keys toxrust/tox-node config <path/to/config.yml>
```

Example commands:

```sh
TOX_SECRET_KEY="4a2d4098e9d6ae6addb8035085cf1467fd7611edd2e22df2f1b60a71763b4ce4" \
    docker run -e TOX_SECRET_KEY toxrust/tox-node \
    --bootstrap-node 1D5A5F2F5D6233058BF0259B09622FB40B482E4FA0931EB8FD3AB8E7BF7DAF6F 198.98.51.198:33445 \
    --udp-address '0.0.0.0:33445' --tcp-address '0.0.0.0:33445' \
    --motd "{{start_date}} {{uptime}} Tcp: incoming {{tcp_packets_in}}, outgoing {{tcp_packets_out}}, Udp: incoming {{udp_packets_in}}, outgoing {{udp_packets_out}}"
```

or

```sh
docker run --mount type=bind,source=$PWD/dpkg/config.yml,target=/config.yml \
    --mount type=bind,source=$PWD/keys,target=/var/lib/tox-node/keys toxrust/tox-node config /config.yml
```

### Running tox-node on NixOS

If you are using NixOS (unstable channel), you can install and run tox-node by adding `services.tox-node.enable = true;` to your `configuration.nix`.

Configuration options are also available. An example of configuration:

```nix
{
  services.tox-node = {
    enable = true;

    logType = "Syslog";
    keysFile = "/var/lib/tox-node/keys";
    udpAddress = "0.0.0.0:33445";
    tcpAddresses = [ "0.0.0.0:33445" ];
    tcpConnectionLimit = 8192;
    lanDiscovery = true;
    threads = 1;
    motd = "Hi from tox-rs! I'm up {{uptime}}. TCP: incoming {{tcp_packets_in}}, outgoing {{tcp_packets_out}}, UDP: incoming {{udp_packets_in}}, outgoing {{udp_packets_out}}";
  };
}
```

### Running tox-node on Arch Linux

Install [tox-node-rs] or [tox-node-rs-git] from AUR in any convenient way. See
[ArchWiki] for more information.

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

In order to run with config, run with `config` subcommand, e.g. `tox-node config <file>`.
Example config.yml is below.
```yaml
log-type: Stderr
keys-file: ./keys
udp-address: 0.0.0.0:33445
tcp-addresses:
  - 0.0.0.0:33445
tcp-connections-limit: 512
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

## Build Debian package

Install [cargo-deb] - a Cargo helper command which automatically creates binary Debian packages (.deb) from Cargo projects:

```sh
cargo install cargo-deb
```

And build binary Debian package:

```sh
cargo deb
```

This command will create a Debian package in `target/debian` directory.
The description of the package:

* Binary in `/usr/bin/tox-node`
* Default config in `/etc/tox-node/config.yml`
* Systemd config in `/lib/systemd/system/tox-node.service`
* postinstall creates user `tox-node` and its home in `/var/lib/tox-node/`
* keys will be generated in `/var/lib/tox-node/keys` if missing during service startup

bootstrap-nodes from config.yml can be generated with:

```sh
curl 'https://nodes.tox.chat/json' -s | jq -r '.nodes[] | select(.status_udp) | .public_key + " " + .ipv4 + " " + .ipv6 + " " + (.port | tostring)' | \
  while read -r pk ipv4 ipv6 port
  do
    if [ "$ipv4" != "NONE" ]
    then
      echo "  - pk: $pk"
      echo "    addr: $ipv4:$port"
    fi
    if [ "$ipv6" != "-" ] && [ "$ipv6" != "$ipv4" ]
    then
      echo "  - pk: $pk"
      echo "    addr: $ipv6:$port"
    fi
  done
```

[libsodium]: https://github.com/jedisct1/libsodium
[Rust]: https://www.rust-lang.org
[cargo-deb]: https://crates.io/crates/cargo-deb
[tox-node-rs]: https://aur.archlinux.org/packages/tox-node-rs
[tox-node-rs-git]: https://aur.archlinux.org/packages/tox-node-rs-git
[ArchWiki]: https://wiki.archlinux.org/index.php/Arch_User_Repository#Installing_packages
[docker repository]: https://hub.docker.com/r/toxrust/tox-node
