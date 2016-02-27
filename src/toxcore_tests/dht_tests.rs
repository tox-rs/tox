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


use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::dht::*;

use std::cmp::Ordering;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use ip::IpAddr;
use quickcheck::{Arbitrary, Gen, quickcheck};


/// Safely casts `u64` to 4 `u16`.
fn u64_as_u16s(num: u64) -> (u16, u16, u16, u16) {
    let mut array: [u16; 4] = [0; 4];
    for n in 0..array.len() {
        array[n] = (num >> (16 * n)) as u16;
    }
    (array[0], array[1], array[2], array[3])
}


// Ping::

impl Arbitrary for Ping {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let request: bool = g.gen();
        if request { Ping::new() } else { Ping::new().response().unwrap() }
    }
}

// PingType::from_bytes()

#[test]
fn ping_type_from_bytes_test() {
    fn random_invalid(bytes: Vec<u8>) {
        if bytes.len() == 0 {
            return;
        } else if bytes[0] == 0 {
            assert_eq!(PingType::Req, PingType::from_bytes(&bytes).unwrap());
        } else if bytes[0] == 1 {
            assert_eq!(PingType::Resp, PingType::from_bytes(&bytes).unwrap());
        } else {
            assert_eq!(None, PingType::from_bytes(&bytes));
        }
    }
    quickcheck(random_invalid as fn(Vec<u8>));

    // just in case
    let p0 = vec![0];
    assert_eq!(PingType::Req, PingType::from_bytes(&p0).unwrap());

    let p1 = vec![1];
    assert_eq!(PingType::Resp, PingType::from_bytes(&p1).unwrap());
}


// Ping::

// ::new()

#[test]
fn ping_new_test() {
    let p1 = Ping::new();
    let p2 = Ping::new();
    assert!(p1 != p2);
    assert!(p1.id != p2.id);
}

// Ping::is_request()

#[test]
fn ping_is_request_test() {
    assert_eq!(true, Ping::new().is_request());
}

// Ping::response()

#[test]
fn ping_response_test() {
    let ping_req = Ping::new();
    let ping_res = ping_req.response().unwrap();
    assert_eq!(ping_req.id, ping_res.id);
    assert_eq!(false, ping_res.is_request());
    assert_eq!(None, ping_res.response());
}

// Ping::as_bytes()

#[test]
fn ping_as_bytes_test() {
    let p = Ping::new();
    let pb = p.as_bytes();
    assert_eq!(PING_SIZE, pb.len());
    // new ping is always a request
    assert_eq!(0, pb[0]);
    let prb = p.response().unwrap().as_bytes();
    // and response is `1`
    assert_eq!(1, prb[0]);
    // `id` of ping should not change
    assert_eq!(pb[1..], prb[1..]);
}

// Ping::from_bytes()

#[test]
fn ping_from_bytes_test() {
    fn with_bytes(bytes: Vec<u8>) {
        if bytes.len() < PING_SIZE || bytes[0] != 0 && bytes[0] != 1 {
            assert_eq!(None, Ping::from_bytes(&bytes));
        } else {
            let p = Ping::from_bytes(&bytes).unwrap();
            // `id` should not differ
            assert_eq!(&u64_to_array(p.id)[..], &bytes[1..9]);

            if bytes[0] == 0 {
                assert_eq!(true, p.is_request());
            } else {
                assert_eq!(false, p.is_request());
            }
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));

    // just in case
    let mut p_req = vec![0];
    p_req.extend_from_slice(&u64_to_array(random_u64()));
    with_bytes(p_req);

    let mut p_resp = vec![1];
    p_resp.extend_from_slice(&u64_to_array(random_u64()));
    with_bytes(p_resp);
}


// IpType::from_bytes()

#[test]
fn ip_type_from_bytes_test() {
    fn with_bytes(bytes: Vec<u8>) {
        if bytes.len() == 0 { return }
        match bytes[0] {
            2   => assert_eq!(IpType::U4, IpType::from_bytes(&bytes).unwrap()),
            10  => assert_eq!(IpType::U6, IpType::from_bytes(&bytes).unwrap()),
            130 => assert_eq!(IpType::T4, IpType::from_bytes(&bytes).unwrap()),
            138 => assert_eq!(IpType::T6, IpType::from_bytes(&bytes).unwrap()),
            _   => assert_eq!(None, IpType::from_bytes(&bytes)),
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));

    // just in case
    with_bytes(vec![0]);
    with_bytes(vec![2]);
    with_bytes(vec![10]);
    with_bytes(vec![130]);
    with_bytes(vec![138]);
}


// IpAddr::as_bytes()

// NOTE: sadly, implementing `Arbitrary` for `IpAddr` doesn't appear to be
// (easily/nicely) dobale, since neither is a part of this crate.
// https://github.com/rust-lang/rfcs/pull/1023

#[test]
fn ip_addr_as_bytes_test() {
    fn with_ipv4(a: u8, b: u8, c: u8, d: u8) {
        let a4 = Ipv4Addr::new(a, b, c, d);
        let ab = IpAddr::V4(a4).as_bytes();
        assert_eq!(4, ab.len());
        assert_eq!(a, ab[0]);
        assert_eq!(b, ab[1]);
        assert_eq!(c, ab[2]);
        assert_eq!(d, ab[3]);
    }
    quickcheck(with_ipv4 as fn(u8, u8, u8, u8));

    fn with_ipv6(n1: u64, n2: u64) {
        let (a, b, c, d) = u64_as_u16s(n1);
        let (e, f, g, h) = u64_as_u16s(n2);
        let a6 = Ipv6Addr::new(a, b, c, d, e, f, g, h);
        let ab = IpAddr::V6(a6).as_bytes();
        assert_eq!(16, ab.len());
        assert_eq!(a, array_to_u16(&[ab[0], ab[1]]));
        assert_eq!(b, array_to_u16(&[ab[2], ab[3]]));
        assert_eq!(c, array_to_u16(&[ab[4], ab[5]]));
        assert_eq!(d, array_to_u16(&[ab[6], ab[7]]));
        assert_eq!(e, array_to_u16(&[ab[8], ab[9]]));
        assert_eq!(f, array_to_u16(&[ab[10], ab[11]]));
        assert_eq!(g, array_to_u16(&[ab[12], ab[13]]));
        assert_eq!(h, array_to_u16(&[ab[14], ab[15]]));
    }
    quickcheck(with_ipv6 as fn(u64, u64));
}


// Ipv6Addr::from_bytes()

#[test]
fn ipv6_addr_from_bytes_test() {
    fn with_bytes(b: Vec<u8>) {
        if b.len() < 16 {
            assert_eq!(None, Ipv6Addr::from_bytes(&b));
        } else {
            let addr = Ipv6Addr::from_bytes(&b).unwrap();
            assert_eq!(&IpAddr::V6(addr).as_bytes()[..16], &b[..16]);
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));
}


// PackedNode::

/// Valid, random PackedNode.
impl Arbitrary for PackedNode {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let udp: bool = g.gen();
        let ipv4: bool = g.gen();

        let mut pk_bytes = [0; PUBLICKEYBYTES];
        g.fill_bytes(&mut pk_bytes);
        let pk = PublicKey::from_slice(&pk_bytes).unwrap();

        if ipv4 {
            let iptype = { if udp { IpType::U4 } else { IpType::T4 }};
            let addr = Ipv4Addr::new(g.gen(), g.gen(), g.gen(), g.gen());
            let saddr = SocketAddrV4::new(addr, g.gen());

            return PackedNode::new(iptype, SocketAddr::V4(saddr), &pk);
        } else {
            let iptype = { if udp { IpType::U6 } else { IpType::T6 }};
            let addr = Ipv6Addr::new(g.gen(), g.gen(), g.gen(), g.gen(),
                                     g.gen(), g.gen(), g.gen(), g.gen());
            let saddr = SocketAddrV6::new(addr, g.gen(), 0, 0);

            return PackedNode::new(iptype, SocketAddr::V6(saddr), &pk);
        }
    }
}

// PackedNode::new()

#[test]
#[allow(non_snake_case)]
// TODO: when `::new()` will be able to fail, this test should check for whether
// it works/fails when needed;
// e.g. `IpType::U4` and supplied `SocketAddr:V6(_)` should fail
fn packed_node_new_test_ip_type_UDP_IPv4() {
    let info = PackedNode::new(IpType::U4,
                               SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
                               &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap());
    assert_eq!(IpType::U4, info.ip_type);
}


// PackedNode::ip()

#[test]
fn packed_node_ip_test() {
    let ipv4 = PackedNode::new(IpType::U4,
                               SocketAddr::V4(SocketAddrV4::from_str("0.0.0.0:0").unwrap()),
                               &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap());

    match ipv4.ip() {
        IpAddr::V4(_) => {},
        IpAddr::V6(_) => panic!("This should not have happened, since IPv4 was supplied!"),
    }

    let ipv6 = PackedNode::new(IpType::U6,
                               SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from_str("::0").unwrap(),
                                   0, 0, 0)),
                               &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap());

    match ipv6.ip() {
        IpAddr::V4(_) => panic!("This should not have happened, since IPv6 was supplied!"),
        IpAddr::V6(_) => {},
    }
}


// PackedNode::from_bytes_multiple()

#[test]
fn packed_node_from_bytes_multiple_test() {
    fn with_nodes(nodes: Vec<PackedNode>) {
        if nodes.len() == 0 {
            assert_eq!(None, PackedNode::from_bytes_multiple(&vec![]));
            return
        }
        let mut bytes = vec![];
        for n in nodes.clone() {
            bytes.extend_from_slice(&n.as_bytes());
        }
        let nodes2 = PackedNode::from_bytes_multiple(&bytes).unwrap();

        assert_eq!(nodes.len(), nodes2.len());
        assert_eq!(nodes, nodes2);
    }
    quickcheck(with_nodes as fn(Vec<PackedNode>));
}


// PackedNode::as_bytes()

/// Returns all possible variants of `PackedNode` `ip_type`, in order
/// listed by `IpType` enum.
fn packed_node_all_ip_types(saddr: SocketAddr, pk: &PublicKey)
    -> (PackedNode, PackedNode, PackedNode, PackedNode)
{
    let u4 = PackedNode::new(IpType::U4, saddr, pk);
    let u6 = PackedNode::new(IpType::U6, saddr, pk);
    let t4 = PackedNode::new(IpType::T4, saddr, pk);
    let t6 = PackedNode::new(IpType::T6, saddr, pk);
    (u4, u6, t4, t6)
}


#[test]
// tests for various IPv4 – use quickcheck
fn packed_node_as_bytes_test_ipv4() {
    fn with_random_ip(a: u8, b: u8, c: u8, d: u8) {
        let pk = &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap();
        let saddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), 1));
        let (u4, _, t4, _) = packed_node_all_ip_types(saddr, pk);
        // check whether ip_type variant matches
        assert!(u4.as_bytes()[0] == 2);
        assert!(t4.as_bytes()[0] == 130);

        // check whether IP matches ..
        //  ..with UDP
        assert!(u4.as_bytes()[1] == a);
        assert!(u4.as_bytes()[2] == b);
        assert!(u4.as_bytes()[3] == c);
        assert!(u4.as_bytes()[4] == d);
        //  ..with TCP
        assert!(t4.as_bytes()[1] == a);
        assert!(t4.as_bytes()[2] == b);
        assert!(t4.as_bytes()[3] == c);
        assert!(t4.as_bytes()[4] == d);

        // check whether length matches
        assert!(u4.as_bytes().len() == PACKED_NODE_IPV4_SIZE);
        assert!(t4.as_bytes().len() == PACKED_NODE_IPV4_SIZE);
    }
    quickcheck(with_random_ip as fn(u8, u8, u8, u8));
}

#[test]
// test for various IPv6 – quickckeck currently doesn't seem to have
// needed functionality, as it would require from quickcheck support for
// more than 4 function arguments
//  - this requires a workaround with loops and hops - i.e. supply to the
//    quickcheck a function that takes 2 `u64` arguments, convert those
//    numbers to arrays, and use numbers from arrays to do the job
fn packed_node_as_bytes_test_ipv6() {
    fn with_random_ip(num1: u64, num2: u64, flowinfo: u32, scope_id: u32) {
        let pk = &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap();

        let (a, b, c, d) = u64_as_u16s(num1);
        let (e, f, g, h) = u64_as_u16s(num2);
        let saddr = SocketAddr::V6(
                        SocketAddrV6::new(
                            Ipv6Addr::new(a, b, c, d, e, f, g, h),
                   /*port*/ 1, flowinfo, scope_id));
        let (_, u6, _, t6) = packed_node_all_ip_types(saddr, pk);
        // check whether ip_type variant matches
        assert_eq!(u6.as_bytes()[0], IpType::U6 as u8);
        assert_eq!(t6.as_bytes()[0], IpType::T6 as u8);

        // check whether IP matches ..
        //  ..with UDP
        assert_eq!(&u6.as_bytes()[1..3], &u16_to_array(a)[..]);
        assert_eq!(&u6.as_bytes()[3..5], &u16_to_array(b)[..]);
        assert_eq!(&u6.as_bytes()[5..7], &u16_to_array(c)[..]);
        assert_eq!(&u6.as_bytes()[7..9], &u16_to_array(d)[..]);
        assert_eq!(&u6.as_bytes()[9..11], &u16_to_array(e)[..]);
        assert_eq!(&u6.as_bytes()[11..13], &u16_to_array(f)[..]);
        assert_eq!(&u6.as_bytes()[13..15], &u16_to_array(g)[..]);
        assert_eq!(&u6.as_bytes()[15..17], &u16_to_array(h)[..]);
        //  ..with TCP
        assert_eq!(&t6.as_bytes()[1..3], &u16_to_array(a)[..]);
        assert_eq!(&t6.as_bytes()[3..5], &u16_to_array(b)[..]);
        assert_eq!(&t6.as_bytes()[5..7], &u16_to_array(c)[..]);
        assert_eq!(&t6.as_bytes()[7..9], &u16_to_array(d)[..]);
        assert_eq!(&t6.as_bytes()[9..11], &u16_to_array(e)[..]);
        assert_eq!(&t6.as_bytes()[11..13], &u16_to_array(f)[..]);
        assert_eq!(&t6.as_bytes()[13..15], &u16_to_array(g)[..]);
        assert_eq!(&t6.as_bytes()[15..17], &u16_to_array(h)[..]);

        // check whether length matches
        assert!(u6.as_bytes().len() == PACKED_NODE_IPV6_SIZE);
        assert!(t6.as_bytes().len() == PACKED_NODE_IPV6_SIZE);
    }
    quickcheck(with_random_ip as fn(u64, u64, u32, u32));
}

#[test]
// test serialization of various ports
fn packed_nodes_as_bytes_test_port() {
    fn with_port(port: u16) {
        let pk = &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap();
        let saddr4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), port));
        let saddr6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from_str("::0").unwrap(), port, 0, 0));

        let (u4, _, t4, _) = packed_node_all_ip_types(saddr4, pk);
        assert_eq!(&u16_to_array(port)[..], &u4.as_bytes()[5..7]);
        assert_eq!(&u16_to_array(port)[..], &t4.as_bytes()[5..7]);

        // and IPv6
        let (_, u6, _, t6) = packed_node_all_ip_types(saddr6, pk);
        assert_eq!(&u16_to_array(port)[..], &u6.as_bytes()[17..19]);
        assert_eq!(&u16_to_array(port)[..], &t6.as_bytes()[17..19]);

    }
    quickcheck(with_port as fn (u16));
}

#[test]
// test for serialization of random PKs
//  - this requires a workaround with loops and hops - i.e. supply to the
//    quickcheck 4 `u64` arguments, cast to arrays, put elements from arrays
//    into a single vec and use vec to create PK
fn packed_nodes_as_bytes_test_pk() {
    fn with_pk(a: u64, b: u64, c: u64, d: u64) {
        let saddr4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 1));
        let saddr6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from_str("::0").unwrap(), 1, 0, 0));

        let mut pk_bytes: Vec<u8> = Vec::with_capacity(PUBLICKEYBYTES);
        pk_bytes.extend_from_slice(&u64_to_array(a));
        pk_bytes.extend_from_slice(&u64_to_array(b));
        pk_bytes.extend_from_slice(&u64_to_array(c));
        pk_bytes.extend_from_slice(&u64_to_array(d));
        let pk_bytes = &pk_bytes[..];

        let pk = &PublicKey::from_slice(pk_bytes).unwrap();

        let (u4, _, t4, _) = packed_node_all_ip_types(saddr4, pk);
        assert_eq!(&u4.as_bytes()[7..], pk_bytes);
        assert_eq!(&t4.as_bytes()[7..], pk_bytes);

        let (_, u6, _, t6) = packed_node_all_ip_types(saddr6, pk);
        assert_eq!(&u6.as_bytes()[19..], pk_bytes);
        assert_eq!(&t6.as_bytes()[19..], pk_bytes);
    }
    quickcheck(with_pk as fn(u64, u64, u64, u64));
}


// PackedNode::from_bytes()

#[test]
fn packed_nodes_from_bytes_test() {
    fn fully_random(pn: PackedNode) {
        assert_eq!(pn, PackedNode::from_bytes(&pn.as_bytes()[..]).unwrap());
    }
    quickcheck(fully_random as fn(PackedNode));
}

#[test]
// test for fail when length is too small
fn packed_nodes_from_bytes_test_length_short() {
    fn fully_random(pn: PackedNode) {
        let pnb = pn.as_bytes();
        assert_eq!(None, PackedNode::from_bytes(&pnb[..(pnb.len() - 1)]));
        if let None = IpType::from_bytes(&pnb[1..]) {
            assert_eq!(None, PackedNode::from_bytes(&pnb[1..]));
        }
    }
    quickcheck(fully_random as fn(PackedNode));
}

#[test]
// test for when length is too big - should work, and parse only first bytes
fn packed_nodes_from_bytes_test_length_too_long() {
    fn fully_random(pn: PackedNode, r_u8: Vec<u8>) {
        let mut vec = Vec::with_capacity(PACKED_NODE_IPV6_SIZE);
        vec.extend_from_slice(&pn.as_bytes()[..]);
        vec.extend_from_slice(&r_u8);
        assert_eq!(pn, PackedNode::from_bytes(&vec[..]).unwrap());
    }
    quickcheck(fully_random as fn(PackedNode, Vec<u8>));
}

#[test]
// test for fail when first byte is not an `IpType`
fn packed_nodes_from_bytes_test_no_iptype() {
    fn fully_random(pn: PackedNode, r_u8: u8) {
        // not interested in valid options
        if r_u8 == 2 || r_u8 == 10 || r_u8 == 130 || r_u8 == 138 {
            return;
        }
        let mut vec = Vec::with_capacity(PACKED_NODE_IPV6_SIZE);
        vec.push(r_u8);
        vec.extend_from_slice(&pn.as_bytes()[1..]);
        assert_eq!(None, PackedNode::from_bytes(&vec[..]));
    }
    quickcheck(fully_random as fn(PackedNode, u8));
}

#[test]
// test for when `IpType` doesn't match length
fn packed_nodes_from_bytes_test_wrong_iptype() {
    fn fully_random(pn: PackedNode) {
        let mut vec = Vec::with_capacity(PACKED_NODE_IPV6_SIZE);
        match pn.ip_type {
            IpType::U4 => vec.push(IpType::U6 as u8),
            IpType::T4 => vec.push(IpType::T6 as u8),
            _ => return,
        }
        vec.extend_from_slice(&pn.as_bytes()[1..]);

        assert_eq!(None, PackedNode::from_bytes(&vec[..]));
    }
    quickcheck(fully_random as fn(PackedNode));
}


// GetNodes::

impl Arbitrary for GetNodes {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let mut a: [u8; PUBLICKEYBYTES] = [0; PUBLICKEYBYTES];
        g.fill_bytes(&mut a);
        let pk = PublicKey::from_slice(&a).unwrap();
        GetNodes { pk: pk, id: g.gen() }
    }
}

// GetNodes::new()

#[test]
fn get_nodes_new_test() {
    fn with_pk(a: u64, b: u64, c: u64, d: u64) {
        let mut v: Vec<u8> = Vec::with_capacity(PUBLICKEYBYTES);
        v.extend_from_slice(&u64_to_array(a));
        v.extend_from_slice(&u64_to_array(b));
        v.extend_from_slice(&u64_to_array(c));
        v.extend_from_slice(&u64_to_array(d));
        let pk = PublicKey::from_slice(&v).unwrap();
        let gn = GetNodes::new(&pk);
        assert_eq!(gn.pk, pk);
    }
    quickcheck(with_pk as fn(u64, u64, u64, u64));
}

// GetNodes::as_bytes()

#[test]
fn get_nodes_as_bytes_test() {
    fn with_gn(gn: GetNodes) {
        let g_bytes = gn.as_bytes();
        let PublicKey(pk_bytes) = gn.pk;
        assert_eq!(&pk_bytes, &g_bytes[..PUBLICKEYBYTES]);
        assert_eq!(&u64_to_array(gn.id), &g_bytes[PUBLICKEYBYTES..]);
    }
    quickcheck(with_gn as fn(GetNodes));
}

// GetNodes::from_bytes()

#[test]
fn get_nodes_from_bytes_test() {
    fn with_bytes(bytes: Vec<u8>) {
        if bytes.len() < GET_NODES_SIZE {
            assert_eq!(None, GetNodes::from_bytes(&bytes));
        } else {
            let gn = GetNodes::from_bytes(&bytes).unwrap();
            // ping_id as bytes should match "original" bytes
            assert_eq!(&bytes[PUBLICKEYBYTES..GET_NODES_SIZE],
                       &u64_to_array(gn.id));

            let PublicKey(ref pk) = gn.pk;
            assert_eq!(pk, &bytes[..PUBLICKEYBYTES]);
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));
}


// SendNodes::

impl Arbitrary for SendNodes {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let mut nodes: Vec<PackedNode> = vec![];
        for _ in 0..g.gen_range(1, 4) {
            nodes.push(Arbitrary::arbitrary(g));
        }
        SendNodes { nodes: nodes, id: g.gen() }
    }
}

// SendNodes::from_request()

#[test]
fn send_nodes_from_request_test() {
    fn with_request(req: GetNodes, nodes: Vec<PackedNode>) {
        if nodes.len() > 4 || nodes.len() == 0 {
            assert_eq!(None, SendNodes::from_request(&req, nodes));
        } else {
            let sn = SendNodes::from_request(&req, nodes.clone()).unwrap();
            assert_eq!(req.id, sn.id);
            assert_eq!(nodes, sn.nodes);
        }
    }
    quickcheck(with_request as fn(GetNodes, Vec<PackedNode>));
}

// SendNodes::as_bytes()

#[test]
fn send_nodes_as_bytes_test() {
    // there should be at least 1 valid node; there can be up to 4 nodes
    fn with_nodes(req: GetNodes, n1: PackedNode, n2: Option<PackedNode>,
                  n3: Option<PackedNode>, n4: Option<PackedNode>) {

        let mut nodes = vec![n1];
        if let Some(n) = n2 { nodes.push(n); }
        if let Some(n) = n3 { nodes.push(n); }
        if let Some(n) = n4 { nodes.push(n); }
        let sn_bytes = SendNodes::from_request(&req, nodes.clone())
                        .unwrap().as_bytes();

        // number of nodes should match
        assert_eq!(nodes.len(), sn_bytes[0] as usize);

        // bytes before current PackedNode in serialized SendNodes
        // starts from `1` since first byte of serialized SendNodes is number of
        // nodes
        let mut len_before = 1;
        for node in 0..nodes.len() {
            let cur_len = nodes[node].as_bytes().len();
            assert_eq!(&nodes[node].as_bytes()[..],
                       &sn_bytes[len_before..(len_before + cur_len)]);
            len_before += cur_len;
        }
        // ping id should be the same as in request
        assert_eq!(&u64_to_array(req.id), &sn_bytes[len_before..]);
    }
    quickcheck(with_nodes as fn(GetNodes, PackedNode, Option<PackedNode>,
                                Option<PackedNode>, Option<PackedNode>));
}


// SendNodes::from_bytes()

#[test]
fn send_nodes_from_bytes_test() {
    fn with_nodes(nodes: Vec<PackedNode>, r_u64: u64) {
        let mut bytes = vec![nodes.len() as u8];
        for node in &nodes {
            bytes.extend_from_slice(&node.as_bytes());
        }
        // and ping id
        bytes.extend_from_slice(&u64_to_array(r_u64));

        if nodes.len() > 4 || nodes.len() == 0 {
            assert_eq!(None, SendNodes::from_bytes(&bytes));
        } else {
            let nodes2 = SendNodes::from_bytes(&bytes).unwrap();
            assert_eq!(&nodes, &nodes2.nodes);
            assert_eq!(r_u64, nodes2.id);
        }
    }
    quickcheck(with_nodes as fn(Vec<PackedNode>, u64));
}


// DPacketT::

impl Arbitrary for DPacketT {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let choice = g.gen_range(0, 3);
        match choice {
            0 => DPacketT::Ping(Arbitrary::arbitrary(g)),
            1 => DPacketT::GetNodes(Arbitrary::arbitrary(g)),
            2 => DPacketT::SendNodes(Arbitrary::arbitrary(g)),
            _ => panic!("Arbitrary for DPacketT – should not have happened!"),
        }
    }
}

// DPacketT::as_type()

#[test]
fn d_packet_t_as_type_test() {
    fn with_dpacket(dpt: DPacketT) {
        match dpt {
            DPacketT::GetNodes(_) => assert_eq!(DPacketTnum::GetN, dpt.as_type()),
            DPacketT::SendNodes(_) => assert_eq!(DPacketTnum::SendN, dpt.as_type()),
            DPacketT::Ping(p) => {
                if p.is_request() {
                    assert_eq!(DPacketTnum::PingReq, dpt.as_type());
                } else {
                    assert_eq!(DPacketTnum::PingResp, dpt.as_type());
                }
            },
        }
    }
    quickcheck(with_dpacket as fn(DPacketT));
}

// DPacketT::as_bytes()

#[test]
fn d_packet_t_as_bytes_test() {
    fn with_dpacket(dp: DPacketT) {
        let dbytes = dp.as_bytes();
        match dp {
            DPacketT::Ping(d)      => assert_eq!(d.as_bytes(), dbytes),
            DPacketT::GetNodes(d)  => assert_eq!(d.as_bytes(), dbytes),
            DPacketT::SendNodes(d) => assert_eq!(d.as_bytes(), dbytes),
        }
    }
    quickcheck(with_dpacket as fn(DPacketT));
}


// DPacketTnum::from_bytes()

#[test]
fn d_packet_t_num_from_bytes_test() {
    fn with_bytes(bytes: Vec<u8>) {
        if bytes.len() == 0 {
            assert_eq!(None, DPacketTnum::from_bytes(&bytes));
            return
        }
        match bytes[0] {
            0 => assert_eq!(DPacketTnum::PingReq, DPacketTnum::from_bytes(&bytes).unwrap()),
            1 => assert_eq!(DPacketTnum::PingResp, DPacketTnum::from_bytes(&bytes).unwrap()),
            2 => assert_eq!(DPacketTnum::GetN, DPacketTnum::from_bytes(&bytes).unwrap()),
            4 => assert_eq!(DPacketTnum::SendN, DPacketTnum::from_bytes(&bytes).unwrap()),
            _ => assert_eq!(None, DPacketTnum::from_bytes(&bytes)),
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));

    // just in case
    with_bytes(vec![]);
    with_bytes(vec![0]);
    with_bytes(vec![1]);
    with_bytes(vec![2]);
    with_bytes(vec![3]);  // incorrect
    with_bytes(vec![4]);
}


// DhtPacket::

impl Arbitrary for DhtPacket {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let (pk, sk) = gen_keypair();  // "sender" keypair
        let (r_pk, _) = gen_keypair();  // receiver PK
        let precomputed = precompute(&r_pk, &sk);
        let nonce = gen_nonce();

        let packet: DPacketT = Arbitrary::arbitrary(g);

        DhtPacket::new(&precomputed, &pk, &nonce, packet)
    }
}

// DhtPacket::new()

// TODO: improve test ↓ (perhaps by making other struct fields public?)
#[test]
fn dht_packet_new_test() {
    fn with_dpacket(dpt: DPacketT) {
        let (pk, sk) = gen_keypair();
        let precomputed = precompute(&pk, &sk);
        let nonce = gen_nonce();
        let dhtp = DhtPacket::new(&precomputed, &pk, &nonce, dpt);
        assert_eq!(dhtp.sender_pk, pk);
    }
    quickcheck(with_dpacket as fn(DPacketT));
}

// DhtPacket::get_packet()

#[test]
fn dht_paket_get_packet_test() {
    fn with_dpackett(dpt: DPacketT) {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();
        let precomputed = precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();

        let new_packet = DhtPacket::new(&precomputed, &alice_pk, &nonce,
                                        dpt.clone());

        let bob_packet = new_packet.get_packet(&bob_sk).unwrap();
        assert_eq!(dpt, bob_packet);
    }
    quickcheck(with_dpackett as fn(DPacketT));
}

// DhtPacket::as_bytes()

#[test]
fn dht_packet_as_bytes_test() {
    fn with_dpacket(dpt: DPacketT) {
        // Alice serializes & encrypts packet, Bob decrypts
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();
        let precomputed = precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();

        let packet = DhtPacket::new(&precomputed, &alice_pk, &nonce, dpt.clone())
                        .as_bytes();

        // check whether packet type was serialized correctly
        let packet_type = match dpt {
            DPacketT::Ping(ref ping) => { if ping.is_request() { 0 } else { 1 } },
            DPacketT::GetNodes(_) => 2,
            DPacketT::SendNodes(_) => 4,
        };
        assert_eq!(packet_type, packet[0]);

        // sender's PK
        let PublicKey(send_pk) = alice_pk;
        assert_eq!(send_pk, packet[1..(1 + PUBLICKEYBYTES)]);

        // nonce
        let nonce_start = 1 + PUBLICKEYBYTES;
        let nonce_end = nonce_start + NONCEBYTES;
        let Nonce(nonce_bytes) = nonce;
        assert_eq!(nonce_bytes, packet[nonce_start..nonce_end]);

        let decrypted = open(&packet[nonce_end..], &nonce, &alice_pk, &bob_sk).unwrap();
        match dpt {
            DPacketT::Ping(d) => assert_eq!(d, Ping::from_bytes(&decrypted).unwrap()),
            DPacketT::GetNodes(d) => assert_eq!(d, GetNodes::from_bytes(&decrypted).unwrap()),
            DPacketT::SendNodes(d) => assert_eq!(d, SendNodes::from_bytes(&decrypted).unwrap()),
        }
    }
    quickcheck(with_dpacket as fn(DPacketT));
}

// DhtPacket::from_bytes()

#[test]
fn dht_packet_from_bytes_test() {
    fn with_packet(p: DhtPacket, invalid: Vec<u8>) {
        let from_bytes = DhtPacket::from_bytes(&p.as_bytes()).unwrap();
        assert_eq!(p, from_bytes);

        if let None = DPacketTnum::from_bytes(&invalid) {
            assert_eq!(None, DhtPacket::from_bytes(&invalid));
        }
    }
    quickcheck(with_packet as fn(DhtPacket, Vec<u8>));
}

// PublicKey::distance()

#[test]
// TODO: possible to use quickcheck?
fn public_key_distance_test() {
    let pk_0 = PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap();
    let pk_1 = PublicKey::from_slice(&[1; PUBLICKEYBYTES]).unwrap();
    let pk_2 = PublicKey::from_slice(&[2; PUBLICKEYBYTES]).unwrap();
    let pk_ff = PublicKey::from_slice(&[0xff; PUBLICKEYBYTES]).unwrap();
    let pk_fe = PublicKey::from_slice(&[0xfe; PUBLICKEYBYTES]).unwrap();

    assert_eq!(Ordering::Less, pk_0.distance(&pk_1, &pk_2));
    assert_eq!(Ordering::Equal, pk_2.distance(&pk_2, &pk_2));
    // `0` key is always closest due to XOR used
    assert_eq!(Ordering::Less, pk_2.distance(&pk_0, &pk_1));
    assert_eq!(Ordering::Greater, pk_2.distance(&pk_ff, &pk_fe));
    assert_eq!(Ordering::Greater, pk_2.distance(&pk_ff, &pk_fe));
    assert_eq!(Ordering::Less, pk_fe.distance(&pk_ff, &pk_2));
}
