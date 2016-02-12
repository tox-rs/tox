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

use ip::IpAddr;


// PackedNode::

// TODO: finish writing test; include:
//  * assert whether IP matches
//  * assert whether PK matches

// ::new()

#[test]
#[allow(non_snake_case)]
// TODO: when `::new()` will be able to fail, this test should check for whether
// it works/fails when needed;
// e.g. `IpType::UdpIpv4` and supplied `SocketAddr:V6(_)` should fail
fn packed_node_new_test_ip_type_UDP_IPv4() {
    let info = PackedNode::new(IpType::UdpIpv4,
                               SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
                               &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap());
    assert_eq!(IpType::UdpIpv4, info.ip_type);
}


// ::ip()

#[test]
fn packed_node_ip_test() {
    let ipv4 = PackedNode::new(IpType::UdpIpv4,
                               SocketAddr::V4(SocketAddrV4::from_str("0.0.0.0:0").unwrap()),
                               &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap());

    match ipv4.ip() {
        IpAddr::V4(_) => {},
        IpAddr::V6(_) => panic!("This should not have happened, since IPv4 was supplied!"),
    }

    let ipv6 = PackedNode::new(IpType::UdpIpv6,
                               SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from_str("::0").unwrap(),
                                   0, 0, 0)),
                               &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap());

    match ipv6.ip() {
        IpAddr::V4(_) => panic!("This should not have happened, since IPv6 was supplied!"),
        IpAddr::V6(_) => {},
    }
}


// ::as_bytes()

// TODO: tests for `::as_bytes()` should include:
// * tests for various IPv4 – use quickcheck
// * tests for various IPv6 – quickckeck currently doesn't seem to have
//   needed functionality, as it would require from quickcheck support for
//   more than 4 function arguments
//    - this requires a workaround with loops and hops - i.e. supply to the
//      quickcheck a function that takes 2 `u64` arguments, convert those
//      numbers to slices, and use numbers from slices to do the job
// * tests for various ports with both IPv4 and IPv6 – can be done, but easily
//   only with same hardcoded IPv{4,6}, since quickcheck ↑
// * tests for various PKs - quickcheck doesn't support supplying more than 4
//   function arguments
//    - this requires a workaround with loops and hops - i.e. supply to the
//      quickcheck 4 `u64` arguments, cast to slices, put slices into a single
//      vec and use vec to create PK
//
// Each test ↑ should have all possible types of `IpType`
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
