/*
    Copyright © 2016 Zetok Zalbavar <zexavexxe@gmail.com>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

/*!
Rust implementation of the [Tox protocol](https://zetok.github.io/tox-spec).

Repo: https://github.com/zetok/tox

C API: https://github.com/ze-tox/tox-capi

Current API allows one to e.g. find info about DHT nodes from bootstrap
nodes by sending [`GetNodes`](./toxcore/dht/struct.GetNodes.html) or request
[`Ping`](./toxcore/dht/struct.Ping.html) response.

To request a ping response:

```
// for networking
extern crate tokio_core;
use tokio_core::reactor::Core;

// to get bytes from PK in hex and to make PK from them
extern crate rustc_serialize;
use rustc_serialize::hex::FromHex;

extern crate tox;
use tox::toxcore::binary_io::*;
use tox::toxcore::crypto_core::*;
use tox::toxcore::dht::*;
use tox::toxcore::network::*;
use tox::toxcore::packet_kind::PacketKind;

fn main() {
    let mut reactor = Core::new().unwrap();
    let handle = reactor.handle();
    // get PK bytes from some "random" bootstrap node (Impyy's)
    let bootstrap_pk_bytes = FromHex::from_hex("6FC41E2BD381D37E9748FC0E0328CE086AF9598BECC8FEB7DDF2E440475F300E").unwrap();
    // create PK from bytes
    let bootstrap_pk = PublicKey::from_slice(&bootstrap_pk_bytes).unwrap();

    // generate own PublicKey, SecretKey keypair
    let (pk, sk) = gen_keypair();

    // and to encrypt data there precomputed symmetric key is needed, created
    // from PK of the peer you want to send data to, and your own secret key.
    let precomp = precompute(&bootstrap_pk, &sk);

    // also generate nonce that will be needed to make the encryption happen
    let nonce = gen_nonce();

    // now create Ping request
    let ping = &PingReq::new();

    // with Ping packet create DhtPacket, and serialize it to bytes
    let dhtpacket = DhtPacket::new(&precomp, &pk, &nonce, ping).to_bytes();

    // and since packet is ready, prepare the network part;
    // bind to given address and port in given range
    // `0.0.0.0` is used instead of `::` to appease windows' rage
    let socket = bind_udp("0.0.0.0".parse().unwrap(), 33445..33546, &handle)
        .expect("Failed to bind to socket!");

    // send DhtPacket via socket to the node (Imppy's)
    let sent_bytes = socket.send_dgram(&dhtpacket,
                 "51.15.37.145:33445".parse().unwrap());
    let (socket, _) = reactor.run(sent_bytes)
        .expect("Failed to send bytes!");

    // since data was sent, now receive response – for that, first prepare
    // buffer to receive data into
    let mut buf = [0; MAX_UDP_PACKET_SIZE];

    // and wait for the answer
    let future_data = socket.recv_dgram(&mut buf[..]);

    let (_socket, buf, n_bytes, _sender) = reactor.run(future_data)
        .expect("Failed to receive data");

    // try to deserialize received bytes as `DhtPacket`
    let recv_packet = match DhtPacket::from_bytes(&buf[..n_bytes]) {
        Some(p) => p,
        // if parsing fails ↓
        None => panic!("Received packet could not have been parsed!\n{:?}",
                        &buf[..n_bytes]),
    };

    // decrypt payload of the received packet
    let payload: PingResp = recv_packet.get_payload(&sk)
        .expect("Failed to decrypt payload!");

    assert_eq!(PacketKind::PingResp, payload.kind());
    assert_eq!(ping.id(), payload.id());
    println!("And contents of payload:\n{:?}", payload);
}
```

*/

#![cfg_attr(feature = "clippy", feature(plugin))]

#![cfg_attr(feature = "clippy", plugin(clippy))]

// Turn off clippy warnings that gives false positives
#![cfg_attr(feature = "clippy", allow(doc_markdown))]
#![cfg_attr(feature = "clippy", allow(useless_format))]
#![cfg_attr(feature = "clippy", allow(new_without_default, new_without_default_derive))]
// Remove it when in will be fixed in nom parser
#![cfg_attr(feature = "clippy", allow(redundant_closure))]
// Too many false positives in tests
#![cfg_attr(feature = "clippy", allow(needless_pass_by_value))]

extern crate byteorder;
extern crate futures;
#[macro_use]
extern crate log;
#[macro_use]
extern crate nom;
// for Zero trait
extern crate num_traits;
extern crate sodiumoxide;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

extern crate tokio_core;
extern crate tokio_proto;


// TODO: refactor macros
#[cfg(test)]
#[macro_use]
pub mod toxcore_tests {
    extern crate rand;
    extern crate rustc_serialize;
    extern crate regex;

    // Helper macros for testing, no tests
    #[warn(missing_docs)]
    #[macro_use]
    pub mod test_macros;

    // tests
    mod binary_io_tests;
    mod crypto_core_tests;
    mod dht_tests;
    mod network_tests;
    mod packet_kind_tests;
    mod state_format_old_tests;
    mod toxid_tests;
}


/** Core Tox module. Provides an API on top of which other modules and
    applications may be build.
*/
#[warn(missing_docs)]
pub mod toxcore {
    #[macro_use]
    pub mod binary_io;
    pub mod crypto_core;
    pub mod dht;
    pub mod dht_node;
    pub mod hole_punching;
    pub mod network;
    pub mod packet_kind;
    pub mod state_format;
    pub mod timeout;
    pub mod toxid;
}

/// Tox Encrypt Save (a.k.a. **TES**) module. Can be used to ecrypt / decrypt
/// data that will be stored on persistent storage.
// TODO: ↑ expand doc
#[warn(missing_docs)]
pub mod toxencryptsave;


#[cfg(test)]
mod toxencryptsave_tests {
    extern crate rand;

    mod encryptsave_tests;
}
