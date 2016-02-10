/*
    Copyright (C) 2013 Tox project All Rights Reserved.
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


// ↓ FIXME doc
//! DHT part of the toxcore

use ip::*;
use std::net::SocketAddr;

#[cfg(test)]
use std::net::{Ipv4Addr, SocketAddrV4};

use toxcore::binary_io::{u16_to_slice};//, slice_to_u16};
use toxcore::crypto_core::*;

/// `IpType` is used by [`PackedNode`](./struct.PackedNode.html).
///
/// * 1st bit – protocol
/// * 3 bits – `0`
/// * 4th bit – address family
///
/// Values for 1st byte:
///
/// * `2` – UDP IPv4
/// * `10` – UDP IPv6
/// * `130` – TCP IPv4
/// * `138` – TCP IPv6
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IpType {
    /// UDP over IPv4
    UdpIpv4 = 2,
    /// UDP over IPv6
    UdpIpv6 = 10,
    /// TCP over IPv4
    TcpIpv4 = 130,
    /// TCP over IPv6
    TcpIpv6 = 138,
}


/// `Packed Node` format is a way to store the node info in a small yet easy to
/// parse format.
///
/// It is used in many places in Tox, e.g. in `DHT Send nodes`.
///
/// To store more than one node, simply append another on to the previous one:
///
/// `[packed node 1][packed node 2][...]`
///
/// Packed node format:
///
/// ```text
///                          (39 bytes minimum, 51 max)
/// +-----------------------------------+
/// | ip_type                ( 1 byte ) |
/// |                                   |
/// | IPv4 Address           ( 4 bytes) |
/// |  -OR-                     -OR-    |
/// | IPv6 Address           (16 bytes) |
/// | Port                   ( 2 bytes) |
/// | Node ID                (32 bytes) |
/// +-----------------------------------+
/// ```
///
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PackedNode {
    ip_type: IpType,
    socketaddr: SocketAddr,
    node_id: PublicKey,
}

// TODO: {de,}serliazation of `PackedNode`

// TODO: ↓ add a method for printing either Ipv{4,6}
impl PackedNode {
    /// New `PackedNode`
    pub fn new(ip_type: IpType,
               socketaddr: SocketAddr,
               node_id: &PublicKey) -> Self {

        PackedNode {
            ip_type: ip_type,
            socketaddr: socketaddr,
            node_id: *node_id,
        }
    }

    /// Serialize `PackedNode` into bytes.
    ///
    /// Can be either `39` or `51` bytes long, depending on whether IPv4 or
    /// IPv6 is being used.
    // TODO: test ↑
    pub fn into_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::with_capacity(39);

        result.push(self.ip_type as u8);

        let addr: Vec<u8> = match self.socketaddr {
            SocketAddr::V4(addr) => addr.ip().octets().iter()
                                        .map(|b| *b).collect(),
            SocketAddr::V6(addr) => {
                let mut result: Vec<u8> = vec![];
                for n in addr.ip().segments().iter() {
                    result.extend_from_slice(&u16_to_slice(*n));
                }
                result
            },
        };
        result.extend_from_slice(&addr);
        // port
        result.extend_from_slice(&u16_to_slice(self.socketaddr.port()));

        let PublicKey(ref pk) = self.node_id;
        result.extend_from_slice(pk);

        result
    }
}

#[test]
fn packed_node_new_test() {
    let info = PackedNode::new(IpType::UdpIpv4,
                               SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
                               &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap());
    assert_eq!(IpType::UdpIpv4, info.ip_type);
    // TODO: finish writing test; include:
    //  * assert whether IP matches
    //  * assert whether PK matches
}


#[test]
fn packed_node_into_bytes_test() {
    let info = PackedNode::new(IpType::UdpIpv4,
                               SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 1)),
                               &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap());

    assert_eq!(info.into_bytes()[0], 2);
    assert!(info.into_bytes().len() == 39);
}

// TODO: write more tests for `packed_node_into_bytes` - including, but not
// limited to info with IPv6
