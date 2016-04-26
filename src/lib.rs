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
Rust implementation of the [Tox protocol](https://toktok.github.io/spec).

Current API allows one to e.g. find info about DHT nodes from bootstrap
nodes by sending [`GetNodes`](./toxcore/dht/struct.GetNodes.html) or request
[`Ping`](./toxcore/dht/struct.Ping.html) response.

To request a ping response:

```
// to get bytes from PK in hex and to make PK from them
extern crate rustc_serialize;
use rustc_serialize::hex::FromHex;

extern crate tox;
use tox::toxcore::binary_io::*;
use tox::toxcore::crypto_core::*;
use tox::toxcore::dht::*;
use tox::toxcore::network::*;

fn main() {
    // get PK bytes from some "random" bootstrap node (Impyy's)
    let bootstrap_pk_bytes = FromHex::from_hex("788236D34978D1D5BD822F0A5BEBD2C53C64CC31CD3149350EE27D4D9A2F9B6B").unwrap();
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
    let ping = Ping::new()
                 .as_packet(); // and make Ping usable by DhtPacket

    // with Ping packet create DhtPacket, and serialize it to bytes
    let dhtpacket = DhtPacket::new(&precomp, &pk, &nonce, ping).to_bytes();

    // and since packet is ready, prepare the network part;
    // bind to some UDP socket
    let socket = match bind_udp() {
        Some(s) => s,
        None => {
            println!("Failed to bind to socket, exiting.");
            return;
        },
    };

    // send DhtPacket via socket to the node (Imppy's)
    let sent_bytes = match socket.send_to(&dhtpacket, "178.62.250.138:33445") {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("Failed to send bytes: {}", e);
            return;
        },
    };

    println!("Sent {} bytes of Ping request to the bootstrap node", sent_bytes);
    // since data was sent, now receive response – for that, first prepare
    // buffer to receive data into
    let mut buf = [0; 2048];  // Tox UDP packet won't be bigger

    // and wait for the answer
    let (bytes, sender) = match socket.recv_from(&mut buf) {
        Ok(d) => d,
        Err(e) => {
            println!("Failed to receive data from socket: {}", e);
            return;
        },
    };

    // try to de-serialize received bytes as `DhtPacket`
    let recv_packet = match DhtPacket::from_bytes(&buf[..bytes]) {
        Some(p) => p,
        // if parsing fails ↓
        None => {
            println!("Received packet could not have been parsed!\n{:?}",
                       &buf[..bytes]);
            return;
        },
    };

    println!("Received packet from {}, with an encrypted payload:\n{:?}",
             sender, recv_packet);

    // decrypt payload of the received packet
    let payload = match recv_packet.get_packet(&sk) {
        Some(p) => p,
        None => {
            println!("Failed to decrypt payload!");
            return;
        },
    };
    println!("And contents of payload:\n{:?}", payload);
}
```

*/

#![cfg_attr(feature="clippy", feature(plugin))]

#![cfg_attr(feature="clippy", plugin(clippy))]

#[macro_use]
extern crate log;

extern crate sodiumoxide;


/** Core Tox module. Provides an API on top of which other modules and
    applications may be build.
*/
#[warn(missing_docs)]
pub mod toxcore {
    pub mod binary_io;
    pub mod crypto_core;
    pub mod dht;
    pub mod network;
    pub mod packet_kind;
    pub mod hole_punching;
}


#[cfg(test)]
mod toxcore_tests {
    extern crate quickcheck;
    extern crate rustc_serialize;

    mod binary_io_tests;
    mod crypto_core_tests;
    mod dht_tests;
    mod network_tests;
    mod packet_kind_tests;
}
