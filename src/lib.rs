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
Tox API.

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
    let dhtpacket = DhtPacket::new(&precomp, &pk, &nonce, ping).as_bytes();

    // and since packet is ready, prepare the network part;
    // bind to some UDP socket
    let socket = bind_udp().unwrap();

    // send DhtPacket via socket to the node (Imppy's)
    let sent_bytes = socket.send_to(&dhtpacket, "178.62.250.138:33445").unwrap();
    println!("Sent {} bytes of Ping request to the bootstrap node", sent_bytes);
    // since data was sent, now receive response – for that, first prepare
    // buffer to receive data into
    let mut buf = [0; 2048];  // Tox UDP packet won't be bigger

    // and wait for the answer
    let (bytes, sender) = socket.recv_from(&mut buf).unwrap();

    // try to de-serialize received bytes as `DhtPacket`
    let recv_packet = match DhtPacket::from_bytes(&buf[..bytes]) {
        Some(p) => p,
        // if parsing fails ↓
        None => panic!("Received packet could not have been parsed!\n{:?}",
                       &buf[..bytes]),
    };

    println!("Received packet, with an encrypted payload:\n{:?}", recv_packet);
    // print decrypted contents of the received packet
    println!("And contents of payload:\n{:?}", recv_packet.get_packet(&sk).unwrap());
}
```

*/


extern crate sodiumoxide;

extern crate ip;

#[cfg(test)]
extern crate rustc_serialize;


/// Core Tox module. Provides an API on top of which other modules and
/// applications may be build.
#[warn(missing_docs)]
pub mod toxcore {
    pub mod binary_io;
    pub mod crypto_core;
    pub mod dht;
    pub mod network;
}

#[cfg(test)]
extern crate quickcheck;

#[cfg(test)]
mod toxcore_tests {
    mod binary_io_tests;
    mod crypto_core_tests;
    mod dht_tests;
    mod network_tests;
}
