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

//! Tests for the DHT module.

//#![cfg(test)]

use toxcore::crypto_core::*;
use toxcore::dht::*;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;


// TODO: finish writing test; include:
//  * assert whether IP matches
//  * assert whether PK matches

#[test]
#[allow(non_snake_case)]
fn packed_node_new_test_ip_type_UDP_IPv4() {
    let info = PackedNode::new(IpType::UdpIpv4,
                               SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
                               &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap());
    assert_eq!(IpType::UdpIpv4, info.ip_type);
}

#[test]
fn packed_node_as_bytes_test_length_min() {
    let info = PackedNode::new(IpType::UdpIpv4,
                               SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 1)),
                               &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap());

    assert_eq!(info.as_bytes()[0], 2);
    assert!(info.as_bytes().len() == 39);
}

#[test]
fn packed_node_as_bytes_test_length_max() {
    let info = PackedNode::new(IpType::UdpIpv6,
                               SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from_str("::0").unwrap(),
                                   0, 0, 0)),
                               &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap());

    assert_eq!(info.as_bytes()[0], 10);
    assert!(info.as_bytes().len() == 51);
}

// TODO: write more tests for `packed_node_as_bytes` - including, but not
// limited to info with IPv6
