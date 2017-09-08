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
use toxcore::packet_kind::PacketKind;

use std::cmp::Ordering;
use std::net::{
            IpAddr,
            Ipv4Addr,
            Ipv6Addr,
            SocketAddr,
            SocketAddrV4,
            SocketAddrV6
};
use std::str::FromStr;
use byteorder::{ByteOrder, BigEndian, LittleEndian, NativeEndian, WriteBytesExt};

use super::quickcheck::{Arbitrary, Gen, quickcheck, StdGen};
use super::rand::chacha::ChaChaRng;


/// Safely casts `u64` to 4 `u16`.
fn u64_as_u16s(num: u64) -> (u16, u16, u16, u16) {
    let mut array: [u16; 4] = [0; 4];
    for (pos, item) in array.iter_mut().enumerate() {
        *item = (num >> (16 * pos)) as u16;
    }
    (array[0], array[1], array[2], array[3])
}


/// Get a PK from 4 `u64`s.
fn nums_to_pk(a: u64, b: u64, c: u64, d: u64) -> PublicKey {
    let mut pk_bytes: Vec<u8> = Vec::with_capacity(PUBLICKEYBYTES);
    pk_bytes.write_u64::<NativeEndian>(a)
        .expect("Failed to write private key bytes!");
    pk_bytes.write_u64::<NativeEndian>(b)
        .expect("Failed to write private key bytes!");
    pk_bytes.write_u64::<NativeEndian>(c)
        .expect("Failed to write private key bytes!");
    pk_bytes.write_u64::<NativeEndian>(d)
        .expect("Failed to write private key bytes!");
    let pk_bytes = &pk_bytes[..];
    PublicKey::from_slice(pk_bytes).expect("Making PK out of bytes failed!")
}



// PingReq::

impl Arbitrary for PingReq {
    fn arbitrary<G: Gen>(_g: &mut G) -> Self {
        PingReq::new()
    }
}

// PingReq::new()

#[test]
fn ping_req_new_test() {
    let p1 = PingReq::new();
    let p2 = PingReq::new();
    assert!(p1 != p2);
    assert!(p1.id() != p2.id());
}

// PingReq::id()

#[test]
fn ping_req_id_test() {
    let ping = PingReq::new();
    assert_eq!(ping.id(), ping.id());
}



// PingResp::

impl Arbitrary for PingResp {
    fn arbitrary<G: Gen>(_g: &mut G) -> Self {
        PingReq::new().into()
    }
}

// PingResp::id()

#[test]
fn ping_resp_id_test() {
    fn with_ping_req(p: PingReq) {
        assert_eq!(p.id(), PingResp::from(p).id());
    }
    quickcheck(with_ping_req as fn(PingReq));
}

// PingResp::to_bytes()

#[test]
fn ping_resp_to_bytes_test_cmp_ping_req() {
    fn with_ping_req(p: PingReq) {
        let pqb = p.to_bytes();
        let prb = PingResp::from(p).to_bytes();
        assert!(pqb[0] != prb[0]);
        assert_eq!(pqb[1..], prb[1..]);
    }
    quickcheck(with_ping_req as fn(PingReq));
}


macro_rules! tests_for_pings {
    ($($p:ident $k_t:ident $b_t:ident $f_t:ident $p_t:ident)+) => ($(
        // ::kind()

        #[test]
        fn $k_t() {
            fn with_ping(p: $p) {
                assert_eq!(PacketKind::$p, p.kind())
            }
            quickcheck(with_ping as fn($p));
        }

        // ::to_bytes()

        #[test]
        fn $b_t() {
            fn with_ping(p: $p) {
                let pb = p.to_bytes();
                assert_eq!(PING_SIZE, pb.len());
                assert_eq!(PacketKind::$p as u8, pb[0]);
            }
            quickcheck(with_ping as fn($p));
        }

        // ::from_bytes()

        #[test]
        fn $f_t() {
            fn with_bytes(bytes: Vec<u8>) {
                if bytes.len() < PING_SIZE ||
                   bytes[0] != PacketKind::$p as u8 {
                    assert_eq!(None, $p::from_bytes(&bytes));
                } else {
                    let p = $p::from_bytes(&bytes).unwrap();
                    // `id` should not differ
                    assert_eq!(p.id(), NativeEndian::read_u64(&bytes[1..PING_SIZE]));
                }
            }
            quickcheck(with_bytes as fn(Vec<u8>));
        
            // just in case
            let mut ping = vec![PacketKind::$p as u8];
            ping.write_u64::<NativeEndian>(random_u64())
                .expect("Failed to write Ping id!");
            with_bytes(ping);
        }

        // ::parse_bytes()

        #[test]
        fn $p_t() {
            fn with_bytes(p: $p, r_rest: Vec<u8>) {
                let mut bytes = Vec::with_capacity(PING_SIZE + r_rest.len());
                bytes.extend_from_slice(&p.to_bytes());
                bytes.extend_from_slice(&r_rest);
        
                let Parsed(_, rest) = $p::parse_bytes(&bytes)
                    .expect("Ping parsing failure.");
                assert_eq!(&r_rest[..], rest);
            }
            quickcheck(with_bytes as fn($p, Vec<u8>));
        }
    )+)
}
tests_for_pings!(PingReq
                    ping_req_kind_test
                    ping_req_to_bytes_test
                    ping_req_from_bytes_test
                    ping_req_parse_test
                PingResp
                    ping_resp_kind_test
                    ping_resp_to_bytes_test
                    ping_resp_from_bytes_test
                    ping_resp_parse_test
);


// IpType

impl Arbitrary for IpType {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        *g.choose(&[IpType::U4, IpType::U6, IpType::T4, IpType::T6])
            .unwrap()
    }
}


// IpType::from_bytes()

#[test]
fn ip_type_from_bytes_test() {
    fn with_bytes(bytes: Vec<u8>) {
        if bytes.is_empty() {
            assert_eq!(None, IpType::from_bytes(&bytes));
            return
        }
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
    with_bytes(vec![]);
    for i in 0x00 .. 0xff {
        with_bytes(vec![i]);
    }
}

// IpType::parse_bytes()

#[test]
fn ip_type_parse_bytes_rest_test() {
    fn with_bytes(it: IpType, r_rest: Vec<u8>) {
        let mut bytes = vec![it as u8];
        bytes.extend_from_slice(&r_rest);

        let Parsed(_, rest) = IpType::parse_bytes(&bytes)
            .expect("IpType parsing failure.");
        assert_eq!(&r_rest[..], rest);
    }
    quickcheck(with_bytes as fn(IpType, Vec<u8>));
}

// IpAddr

#[derive(Clone, Debug)]
struct IpAddrWrap(IpAddr);

impl Arbitrary for IpAddrWrap {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let v4: bool = g.gen();

        if v4 {
            let res = IpAddr::V4(Ipv4Addr::new(g.gen(), g.gen(),
                                               g.gen(), g.gen()));
            IpAddrWrap(res)
        } else {
            let res = IpAddr::V6(Ipv6Addr::new(g.gen(), g.gen(),
                                               g.gen(), g.gen(),
                                               g.gen(), g.gen(),
                                               g.gen(), g.gen()));
            IpAddrWrap(res)
        }
    }
}

// IpAddr::to_bytes()

#[test]
fn ip_addr_to_bytes_test() {
    fn with_ipv4(a: u8, b: u8, c: u8, d: u8) {
        let a4 = Ipv4Addr::new(a, b, c, d);
        let ab = IpAddr::V4(a4).to_bytes();
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
        let ab = IpAddr::V6(a6).to_bytes();
        assert_eq!(16, ab.len());
        assert_eq!(a, LittleEndian::read_u16(&ab[0..2]));
        assert_eq!(b, LittleEndian::read_u16(&ab[2..4]));
        assert_eq!(c, LittleEndian::read_u16(&ab[4..6]));
        assert_eq!(d, LittleEndian::read_u16(&ab[6..8]));
        assert_eq!(e, LittleEndian::read_u16(&ab[8..10]));
        assert_eq!(f, LittleEndian::read_u16(&ab[10..12]));
        assert_eq!(g, LittleEndian::read_u16(&ab[12..14]));
        assert_eq!(h, LittleEndian::read_u16(&ab[14..16]));
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
            assert_eq!(&IpAddr::V6(addr).to_bytes()[..16], &b[..16]);
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));
}

// Ipv4Addr::from_bytes()

#[test]
fn ipv4_addr_from_bytes_test() {
    fn with_bytes(b: Vec<u8>) {
        if b.len() < 4 {
            assert_eq!(None, Ipv4Addr::from_bytes(&b));
        } else {
            let addr = Ipv4Addr::from_bytes(&b).unwrap();
            assert_eq!(&IpAddr::V4(addr).to_bytes()[..4], &b[..4]);
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));
}

// Ipv[4,6]Addr::parse_bytes()

#[test]
fn ip_addr_parse_bytes_rest_test() {
    fn with_bytes(IpAddrWrap(ip_addr): IpAddrWrap, r_rest: Vec<u8>) {
        let mut bytes = vec![];
        bytes.extend_from_slice(&ip_addr.to_bytes());
        bytes.extend_from_slice(&r_rest);

        let rest = match ip_addr {
            IpAddr::V4(_) => {
                let Parsed(_, rest) = Ipv4Addr::parse_bytes(&bytes)
                    .expect("Ipv4Addr parsing failure.");
                rest
            },
            IpAddr::V6(_) => {
                let Parsed(_, rest) = Ipv6Addr::parse_bytes(&bytes)
                    .expect("Ipv6Addr parsing failure.");
                rest
            }
        };

        assert_eq!(&r_rest[..], rest);
    }
    quickcheck(with_bytes as fn(IpAddrWrap, Vec<u8>));
}


// PackedNode::

/// Valid, random `PackedNode`.
impl Arbitrary for PackedNode {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let ipv4: bool = g.gen();

        let mut pk_bytes = [0; PUBLICKEYBYTES];
        g.fill_bytes(&mut pk_bytes);
        let pk = PublicKey(pk_bytes);

        if ipv4 {
            let addr = Ipv4Addr::new(g.gen(), g.gen(), g.gen(), g.gen());
            let saddr = SocketAddrV4::new(addr, g.gen());

            PackedNode::new(g.gen(), SocketAddr::V4(saddr), &pk)
        } else {
            let addr = Ipv6Addr::new(g.gen(), g.gen(), g.gen(), g.gen(),
                                     g.gen(), g.gen(), g.gen(), g.gen());
            let saddr = SocketAddrV6::new(addr, g.gen(), 0, 0);

            PackedNode::new(g.gen(), SocketAddr::V6(saddr), &pk)
        }
    }
}

// PackedNode::new()

#[test]
#[allow(non_snake_case)]
fn packed_node_new_test_ip_type_UDP_IPv4() {
    let pk = PublicKey([0; PUBLICKEYBYTES]);
    let info = PackedNode::new(true,
                               SocketAddr::V4("0.0.0.0:0".parse().unwrap()),
                               &pk);
    assert_eq!(IpType::U4, info.ip_type);
    assert_eq!(pk, info.pk);
}


// PackedNode::ip()

#[test]
fn packed_node_ip_test() {
    let ipv4 = PackedNode::new(true,
                               SocketAddr::V4("0.0.0.0:0".parse().unwrap()),
                               &PublicKey([0; PUBLICKEYBYTES]));

    match ipv4.ip() {
        IpAddr::V4(_) => {},
        IpAddr::V6(_) => panic!("This should not have happened, since IPv4 was supplied!"),
    }

    let ipv6 = PackedNode::new(true,
                               SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from_str("::0").unwrap(),
                                   0, 0, 0)),
                               &PublicKey([0; PUBLICKEYBYTES]));

    match ipv6.ip() {
        IpAddr::V4(_) => panic!("This should not have happened, since IPv6 was supplied!"),
        IpAddr::V6(_) => {},
    }
}


// PackedNode::parse_bytes()

#[test]
// check if always fails when there's not enough bytes for port
fn packed_node_parse_bytes_test_port() {
    fn with_pn(pn: PackedNode) {
        let bytes = &pn.to_bytes()[..];
        let bytes = &bytes[..bytes.len() - PUBLICKEYBYTES];
        let err_1 = PackedNode::parse_bytes(&bytes[..bytes.len() - 1]);
        let err_2 = PackedNode::parse_bytes(&bytes[..bytes.len() - 2]);
        let err_msg = "Not enough bytes for port.";
        assert!(format!("{:?}", err_1.unwrap_err()).contains(&err_msg));
        assert!(format!("{:?}", err_2.unwrap_err()).contains(&err_msg));
    }
    quickcheck(with_pn as fn(PackedNode));
}


// PackedNode::parse_bytes_multiple()

#[test]
fn packed_node_parse_bytes_multiple_test() {
    fn with_nodes(nodes: Vec<PackedNode>, random_rest: Vec<u8>) {
        let mut bytes = vec![];
        for n in &nodes {
            bytes.extend_from_slice(&n.to_bytes());
        }
        let mut expected_rest = vec![];
        if !random_rest.is_empty() {
            expected_rest.push(0); // Incorrect IpType
            expected_rest.extend_from_slice(&random_rest);
        }
        bytes.extend_from_slice(&expected_rest);

        let Parsed(nodes2, rest) = PackedNode::parse_bytes_multiple(&bytes).unwrap();

        assert_eq!(nodes.len(), nodes2.len());
        assert_eq!(nodes, nodes2);
        assert_eq!(&expected_rest[..], rest);
    }
    quickcheck(with_nodes as fn(Vec<PackedNode>, Vec<u8>));
}

// PackedNode::parse_bytes_multiple_n()

#[test]
fn packed_node_parse_bytes_multiple_n_test() {
    fn with_nodes(nodes: Vec<PackedNode>, random_rest: Vec<u8>) {
        { // should parse nodes
            let mut bytes = vec![];
            for n in &nodes {
                bytes.extend_from_slice(&n.to_bytes());
            }
            bytes.extend_from_slice(&random_rest);

            let Parsed(nodes2, rest) =
                PackedNode::parse_bytes_multiple_n(nodes.len(), &bytes)
                    .expect("Nodes parsing failed.");

            assert_eq!(nodes.len(), nodes2.len());
            assert_eq!(nodes, nodes2);
            assert_eq!(&random_rest[..], rest);
        }

        { // should fail if not enough nodes
            let mut bytes = vec![];
            for n in &nodes {
                bytes.extend_from_slice(&n.to_bytes());
            }
            bytes.push(0); // Incorrect IpType
            bytes.extend_from_slice(&random_rest);

            assert!(PackedNode::parse_bytes_multiple_n(nodes.len() + 1, &bytes)
                    .ok().is_none());
        }

        // should not parse too many nodes
        if !nodes.is_empty() {
            let mut bytes = vec![];
            for n in &nodes {
                bytes.extend_from_slice(&n.to_bytes());
            }
            bytes.extend_from_slice(&random_rest);

            let mut expected_rest = vec![];
            expected_rest.extend_from_slice(&nodes[nodes.len() - 1].to_bytes());
            expected_rest.extend_from_slice(&random_rest);


            let Parsed(nodes2, rest) =
                PackedNode::parse_bytes_multiple_n(nodes.len() - 1, &bytes)
                    .expect("Nodes parsing failed.");

            assert_eq!(nodes.len() - 1, nodes2.len());
            assert_eq!(&nodes[..nodes.len() - 1], &nodes2[..]);
            assert_eq!(&expected_rest[..], rest);
        }
    }
    quickcheck(with_nodes as fn(Vec<PackedNode>, Vec<u8>));
}



// PackedNode::to_bytes()

/// Returns all possible variants of `PackedNode` `ip_type`, in order
/// listed by `IpType` enum.
fn packed_node_protocol(saddr: SocketAddr, pk: &PublicKey)
    -> (PackedNode, PackedNode)
{
    let u = PackedNode::new(true, saddr, pk);
    let t = PackedNode::new(false, saddr, pk);
    (u, t)
}


#[test]
// tests for various IPv4 – use quickcheck
fn packed_node_to_bytes_test_ipv4() {
    fn with_random_saddr(a: u8, b: u8, c: u8, d: u8, port: u16) {
        let pk = &PublicKey([0; PUBLICKEYBYTES]);
        let saddr = SocketAddr::V4(
                     format!("{}.{}.{}.{}:{}", a, b, c, d, port)
                        .parse()
                        .expect("Failed to parse as IPv4!"));

        let (u, t) = packed_node_protocol(saddr, pk);
        // check whether ip_type variant matches
        assert!(u.to_bytes()[0] == IpType::U4 as u8);
        assert!(t.to_bytes()[0] == IpType::T4 as u8);

        // check whether IP matches ..
        //  ..with UDP
        assert!(u.to_bytes()[1] == a);
        assert!(u.to_bytes()[2] == b);
        assert!(u.to_bytes()[3] == c);
        assert!(u.to_bytes()[4] == d);
        //  ..with TCP
        assert!(t.to_bytes()[1] == a);
        assert!(t.to_bytes()[2] == b);
        assert!(t.to_bytes()[3] == c);
        assert!(t.to_bytes()[4] == d);

        // check whether port matches
        assert_eq!(port, BigEndian::read_u16(&u.to_bytes()[5..7]));
        assert_eq!(port, BigEndian::read_u16(&t.to_bytes()[5..7]));

        // check whether length matches
        assert!(u.to_bytes().len() == PACKED_NODE_IPV4_SIZE);
        assert!(t.to_bytes().len() == PACKED_NODE_IPV4_SIZE);
    }
    quickcheck(with_random_saddr as fn(u8, u8, u8, u8, u16));
}

#[test]
fn packed_node_to_bytes_test_ipv6() {
    fn with_random_saddr(num1: u64, num2: u64, flowinfo: u32, scope_id: u32,
                      port: u16) {
        let pk = &PublicKey([0; PUBLICKEYBYTES]);

        let (a, b, c, d) = u64_as_u16s(num1);
        let (e, f, g, h) = u64_as_u16s(num2);
        let saddr = SocketAddr::V6(
                        SocketAddrV6::new(
                            Ipv6Addr::new(a, b, c, d, e, f, g, h),
                                          port, flowinfo, scope_id));
        let (u, t) = packed_node_protocol(saddr, pk);
        // check whether ip_type variant matches
        assert_eq!(u.to_bytes()[0], IpType::U6 as u8);
        assert_eq!(t.to_bytes()[0], IpType::T6 as u8);

        // check whether IP matches ..
        //  ..with UDP
        assert_eq!(LittleEndian::read_u16(&u.to_bytes()[1..3]), a);
        assert_eq!(LittleEndian::read_u16(&u.to_bytes()[3..5]), b);
        assert_eq!(LittleEndian::read_u16(&u.to_bytes()[5..7]), c);
        assert_eq!(LittleEndian::read_u16(&u.to_bytes()[7..9]), d);
        assert_eq!(LittleEndian::read_u16(&u.to_bytes()[9..11]), e);
        assert_eq!(LittleEndian::read_u16(&u.to_bytes()[11..13]), f);
        assert_eq!(LittleEndian::read_u16(&u.to_bytes()[13..15]), g);
        assert_eq!(LittleEndian::read_u16(&u.to_bytes()[15..17]), h);
        //  ..with TCP
        assert_eq!(LittleEndian::read_u16(&t.to_bytes()[1..3]), a);
        assert_eq!(LittleEndian::read_u16(&t.to_bytes()[3..5]), b);
        assert_eq!(LittleEndian::read_u16(&t.to_bytes()[5..7]), c);
        assert_eq!(LittleEndian::read_u16(&t.to_bytes()[7..9]), d);
        assert_eq!(LittleEndian::read_u16(&t.to_bytes()[9..11]), e);
        assert_eq!(LittleEndian::read_u16(&t.to_bytes()[11..13]), f);
        assert_eq!(LittleEndian::read_u16(&t.to_bytes()[13..15]), g);
        assert_eq!(LittleEndian::read_u16(&t.to_bytes()[15..17]), h);

        // check whether port matches
        assert_eq!(port, BigEndian::read_u16(&u.to_bytes()[17..19]));
        assert_eq!(port, BigEndian::read_u16(&t.to_bytes()[17..19]));

        // check whether length matches
        assert!(u.to_bytes().len() == PACKED_NODE_IPV6_SIZE);
        assert!(t.to_bytes().len() == PACKED_NODE_IPV6_SIZE);
    }
    quickcheck(with_random_saddr as fn(u64, u64, u32, u32, u16));
}

#[test]
/* test for serialization of random PKs
    - this requires a workaround with loops and hops - i.e. supply to the
      quickcheck 4 `u64` arguments, cast to arrays, put elements from arrays
      into a single vec and use vec to create PK
*/
fn packed_nodes_to_bytes_test_pk() {
    fn with_pk(a: u64, b: u64, c: u64, d: u64) {
        let saddr4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 1));
        let saddr6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from_str("::0").unwrap(), 1, 0, 0));

        let pk = nums_to_pk(a, b, c, d);
        let PublicKey(ref pk_bytes) = pk;

        let (u4, t4) = packed_node_protocol(saddr4, &pk);
        assert_eq!(&u4.to_bytes()[7..], pk_bytes);
        assert_eq!(&t4.to_bytes()[7..], pk_bytes);

        let (u6, t6) = packed_node_protocol(saddr6, &pk);
        assert_eq!(&u6.to_bytes()[19..], pk_bytes);
        assert_eq!(&t6.to_bytes()[19..], pk_bytes);
    }
    quickcheck(with_pk as fn(u64, u64, u64, u64));
}


// PackedNode::from_bytes()

#[test]
fn packed_nodes_from_bytes_test() {
    fn fully_random(pn: PackedNode) {
        assert_eq!(pn, PackedNode::from_bytes(&pn.to_bytes()[..]).unwrap());
    }
    quickcheck(fully_random as fn(PackedNode));
}

#[test]
// test for fail when length is too small
fn packed_nodes_from_bytes_test_length_short() {
    fn fully_random(pn: PackedNode) {
        let pnb = pn.to_bytes();
        assert_eq!(None, PackedNode::from_bytes(&pnb[..(pnb.len() - 1)]));
        if IpType::from_bytes(&pnb[1..]).is_none() {
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
        vec.extend_from_slice(&pn.to_bytes()[..]);
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
        vec.extend_from_slice(&pn.to_bytes()[1..]);
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
        vec.extend_from_slice(&pn.to_bytes()[1..]);

        assert_eq!(None, PackedNode::from_bytes(&vec[..]));
    }
    quickcheck(fully_random as fn(PackedNode));
}

// PackedNode::parse_bytes()

#[test]
// test for when length is too big - should work, and parse only first bytes
fn packed_nodes_parse_bytes_test_length_too_long() {
    fn fully_random(pn: PackedNode, r_u8: Vec<u8>) {
        let mut vec = Vec::with_capacity(PACKED_NODE_IPV6_SIZE);
        vec.extend_from_slice(&pn.to_bytes()[..]);
        vec.extend_from_slice(&r_u8);

        let Parsed(result, rest) = PackedNode::parse_bytes(&vec[..])
            .expect("PackedNode parsing failure.");
        assert_eq!(pn, result);
        assert_eq!(&r_u8[..], rest);
    }
    quickcheck(fully_random as fn(PackedNode, Vec<u8>));
}


// GetNodes::

impl Arbitrary for GetNodes {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let mut a: [u8; PUBLICKEYBYTES] = [0; PUBLICKEYBYTES];
        g.fill_bytes(&mut a);
        GetNodes { pk: PublicKey(a), id: g.gen() }
    }
}

// GetNodes::new()

#[test]
fn get_nodes_new_test() {
    fn with_pk(a: u64, b: u64, c: u64, d: u64) {
        let pk = nums_to_pk(a, b, c, d);
        let gn = GetNodes::new(&pk);
        assert_eq!(gn.pk, pk);
    }
    quickcheck(with_pk as fn(u64, u64, u64, u64));
}

// GetNodes::kind()()

#[test]
fn get_nodes_kind_test() {
    fn with_gn(gn: GetNodes) {
        assert_eq!(PacketKind::GetN, gn.kind());
    }
    quickcheck(with_gn as fn(GetNodes));
}

// GetNodes::to_bytes()

#[test]
fn get_nodes_to_bytes_test() {
    fn with_gn(gn: GetNodes) {
        let g_bytes = gn.to_bytes();
        let PublicKey(pk_bytes) = gn.pk;
        assert_eq!(&pk_bytes, &g_bytes[..PUBLICKEYBYTES]);
        assert_eq!(gn.id, NativeEndian::read_u64(&g_bytes[PUBLICKEYBYTES..]));
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
            assert_eq!(NativeEndian::read_u64(&bytes[PUBLICKEYBYTES..GET_NODES_SIZE]), gn.id);

            let PublicKey(ref pk) = gn.pk;
            assert_eq!(pk, &bytes[..PUBLICKEYBYTES]);
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));
}

// GetNodes::parse_bytes()

#[test]
fn get_nodes_parse_bytes_rest_test() {
    fn with_bytes(bytes: Vec<u8>) {
        if bytes.len() >= GET_NODES_SIZE {
            let Parsed(_, rest) = GetNodes::parse_bytes(&bytes)
                .expect("GetNodes parsing failed.");
            assert_eq!(rest, &bytes[GET_NODES_SIZE..]);
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
        if nodes.len() > 4 || nodes.is_empty() {
            assert_eq!(None, SendNodes::from_request(&req, nodes));
        } else {
            let sn = SendNodes::from_request(&req, nodes.clone()).unwrap();
            assert_eq!(req.id, sn.id);
            assert_eq!(nodes, sn.nodes);
        }
    }
    quickcheck(with_request as fn(GetNodes, Vec<PackedNode>));
}

// SendNodes::kind()

#[test]
fn send_nodes_kind_test() {
    fn with_sn(sn: SendNodes) {
        assert_eq!(PacketKind::SendN, sn.kind());
    }
    quickcheck(with_sn as fn(SendNodes));
}

// SendNodes::to_bytes()

#[test]
fn send_nodes_to_bytes_test() {
    // there should be at least 1 valid node; there can be up to 4 nodes
    fn with_nodes(req: GetNodes, n1: PackedNode, n2: Option<PackedNode>,
                  n3: Option<PackedNode>, n4: Option<PackedNode>) {

        let mut nodes = vec![n1];
        if let Some(n) = n2 { nodes.push(n); }
        if let Some(n) = n3 { nodes.push(n); }
        if let Some(n) = n4 { nodes.push(n); }
        let sn_bytes = SendNodes::from_request(&req, nodes.clone())
                        .unwrap().to_bytes();

        // number of nodes should match
        assert_eq!(nodes.len(), sn_bytes[0] as usize);

        // bytes before current PackedNode in serialized SendNodes
        // starts from `1` since first byte of serialized SendNodes is number of
        // nodes
        let mut len_before = 1;
        for node in &nodes {
            let cur_len = node.to_bytes().len();
            assert_eq!(&node.to_bytes()[..],
                       &sn_bytes[len_before..(len_before + cur_len)]);
            len_before += cur_len;
        }
        // ping id should be the same as in request
        assert_eq!(req.id, NativeEndian::read_u64(&sn_bytes[len_before..]));
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
            bytes.extend_from_slice(&node.to_bytes());
        }
        // and ping id
        bytes.write_u64::<NativeEndian>(r_u64)
            .expect("Failed to write Ping id!");

        if nodes.len() > 4 || nodes.is_empty() {
            assert_eq!(None, SendNodes::from_bytes(&bytes));
        } else {
            let nodes2 = SendNodes::from_bytes(&bytes).unwrap();
            assert_eq!(&nodes, &nodes2.nodes);
            assert_eq!(r_u64, nodes2.id);
        }
    }
    quickcheck(with_nodes as fn(Vec<PackedNode>, u64));
}

// SendNodes::parse_bytes()

#[test]
fn send_nodes_parse_bytes_rest_test() {
    fn with_nodes(nodes: Vec<PackedNode>, r_u64: u64, r_rest: Vec<u8>) {
        let mut bytes = vec![nodes.len() as u8];
        for node in &nodes {
            bytes.extend_from_slice(&node.to_bytes());
        }
        // and ping id
        bytes.write_u64::<NativeEndian>(r_u64)
            .expect("Failed to write Ping id!");
        bytes.extend_from_slice(&r_rest);

        if nodes.len() <= 4 && !nodes.is_empty() {
            let Parsed(_, rest) = SendNodes::parse_bytes(&bytes)
                .expect("SendNodes parsing failed.");
            assert_eq!(&r_rest[..], rest);
        }
    }
    quickcheck(with_nodes as fn(Vec<PackedNode>, u64, Vec<u8>));
}



// DhtPacket::

impl Arbitrary for DhtPacket {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let (pk, sk) = gen_keypair();  // "sender" keypair
        let (r_pk, _) = gen_keypair();  // receiver PK
        let precomputed = precompute(&r_pk, &sk);
        let nonce = gen_nonce();

        let choice = g.gen_range(0, 4);
        match choice {
            0 =>
                DhtPacket::new(&precomputed, &pk, &nonce, &PingReq::arbitrary(g)),
            1 =>
                DhtPacket::new(&precomputed, &pk, &nonce, &PingResp::arbitrary(g)),
            2 =>
                DhtPacket::new(&precomputed, &pk, &nonce, &GetNodes::arbitrary(g)),
            3 =>
                DhtPacket::new(&precomputed, &pk, &nonce, &SendNodes::arbitrary(g)),
            _ => panic!("Arbitrary for DhtPacketT – should not have happened!"),
        }
    }
}

// DhtPacket::new()

// TODO: improve test ↓ (perhaps by making other struct fields public?)
#[test]
fn dht_packet_new_test() {
    fn with_dht_packet<P>(dpt: P)
        where P: DhtPacketT
    {
        let (pk, sk) = gen_keypair();
        let precomputed = precompute(&pk, &sk);
        let nonce = gen_nonce();
        let dhtp = DhtPacket::new(&precomputed, &pk, &nonce, &dpt);
        assert_eq!(dhtp.sender_pk, pk);
    }
    quickcheck(with_dht_packet as fn(PingReq));
    quickcheck(with_dht_packet as fn(PingResp));
    quickcheck(with_dht_packet as fn(GetNodes));
    quickcheck(with_dht_packet as fn(SendNodes));
}

// DhtPacket::get_packet()

#[test]
fn dht_paket_get_packet_test() {
    fn with_dht_packet<P>(dpt: P)
        where P: DhtPacketT
    {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();
        let precomputed = precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();

        let new_packet = DhtPacket::new(&precomputed,
                                        &alice_pk,
                                        &nonce,
                                        &dpt);

        let bob_packet = new_packet.get_packet(&bob_sk).unwrap();
        assert_eq!(dpt, bob_packet);
    }
    quickcheck(with_dht_packet as fn(PingReq));
    quickcheck(with_dht_packet as fn(PingResp));
    quickcheck(with_dht_packet as fn(GetNodes));
    quickcheck(with_dht_packet as fn(SendNodes));
}

// DhtPacket::ping_resp()

#[test]
fn dht_packet_ping_resp_test() {
    fn with_dpt<P>(dpt: P)
        where P: DhtPacketT
    {
        let (pk, sk) = gen_keypair();
        let prec = precompute(&pk, &sk);
        let nonce = gen_nonce();

        let response = DhtPacket::new(&prec, &pk, &nonce, &dpt)
            .ping_resp(&sk, &prec, &pk);

        if dpt.kind() == PacketKind::PingReq {
            // FIXME: assume that it's a correct response ;/
        } else {
            assert_eq!(None, response);
        }
    }
    quickcheck(with_dpt as fn(PingReq));
    quickcheck(with_dpt as fn(PingResp));
    quickcheck(with_dpt as fn(GetNodes));
    quickcheck(with_dpt as fn(SendNodes));
}

// DhtPacket::to_bytes()

#[test]
fn dht_packet_to_bytes_test() {
    fn with_dht_packet<P>(dpt: P)
        where P: DhtPacketT
    {
        // Alice serializes & encrypts packet, Bob decrypts
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();
        let precomputed = precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();

        let packet = DhtPacket::new(&precomputed, &alice_pk, &nonce, &dpt)
                        .to_bytes();

        // check whether packet type was serialized correctly
        let packet_type = dpt.kind() as u8;
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
        assert_eq!(dpt, P::from_bytes(&decrypted).unwrap());
    }
    quickcheck(with_dht_packet as fn(PingReq));
    quickcheck(with_dht_packet as fn(PingResp));
    quickcheck(with_dht_packet as fn(GetNodes));
    quickcheck(with_dht_packet as fn(SendNodes));
}

// DhtPacket::from_bytes()

#[test]
fn dht_packet_from_bytes_test() {
    fn with_packet(p: DhtPacket) {
        let from_bytes = DhtPacket::from_bytes(&p.to_bytes()).unwrap();
        assert_eq!(p, from_bytes);
    }
    quickcheck(with_packet as fn(DhtPacket));
}

// DhtPacket::parse_bytes()

#[test]
fn dht_packet_parse_bytes_rest_test() {
    fn with_packet(p: DhtPacket, r_rest: Vec<u8>) {
        let mut bytes = vec![];
        bytes.extend_from_slice(&p.to_bytes());
        bytes.extend_from_slice(&r_rest);

        let Parsed(_, rest) = DhtPacket::parse_bytes(&bytes)
            .expect("DhtPacket parsing failed.");
        assert!(rest.is_empty()); // all remaining bytes are in payload
    }
    quickcheck(with_packet as fn(DhtPacket, Vec<u8>));
}

// PublicKey::distance()

#[test]
// TODO: possible to use quickcheck?
fn public_key_distance_test() {
    let pk_0 = PublicKey([0; PUBLICKEYBYTES]);
    let pk_1 = PublicKey([1; PUBLICKEYBYTES]);
    let pk_2 = PublicKey([2; PUBLICKEYBYTES]);
    let pk_ff = PublicKey([0xff; PUBLICKEYBYTES]);
    let pk_fe = PublicKey([0xfe; PUBLICKEYBYTES]);

    assert_eq!(Ordering::Less, pk_0.distance(&pk_1, &pk_2));
    assert_eq!(Ordering::Equal, pk_2.distance(&pk_2, &pk_2));
    assert_eq!(Ordering::Less, pk_2.distance(&pk_0, &pk_1));
    assert_eq!(Ordering::Greater, pk_2.distance(&pk_ff, &pk_fe));
    assert_eq!(Ordering::Greater, pk_2.distance(&pk_ff, &pk_fe));
    assert_eq!(Ordering::Less, pk_fe.distance(&pk_ff, &pk_2));
}


// Node::

impl Arbitrary for Node {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        Node::new(&Arbitrary::arbitrary(g), g.gen())
    }
}


// Node::new()

#[test]
fn node_new_test() {
    fn with_pn(pn: PackedNode, timeout: u64) {
        let node = Node::new(&pn, timeout);
        assert_eq!(timeout, node.timeout);
        assert_eq!(0, node.id);
        assert_eq!(pn, node.node);
    }
    quickcheck(with_pn as fn(PackedNode, u64));
}

// Node::id()

#[test]
fn node_id_test() {
    fn with_id(node: Node, id: u64) {
        let mut node = node;
        node.id(id);
        assert_eq!(id, node.id);
    }
    quickcheck(with_id as fn(Node, u64));
}

// Nodes::pk()

#[test]
fn node_pk_test() {
    fn with_pn(pn: PackedNode, timeout: u64) {
        let node = Node::new(&pn, timeout);
        assert_eq!(pn.pk, *node.pk());
    }
    quickcheck(with_pn as fn(PackedNode, u64));
}


// kbucket_index()

#[test]
fn kbucket_index_test() {
    let pk1 = PublicKey([0b10101010; PUBLICKEYBYTES]);
    let pk2 = PublicKey([0; PUBLICKEYBYTES]);
    let pk3 = PublicKey([0b00101010; PUBLICKEYBYTES]);
    assert_eq!(None, kbucket_index(&pk1, &pk1));
    assert_eq!(Some(0), kbucket_index(&pk1, &pk2));
    assert_eq!(Some(2), kbucket_index(&pk2, &pk3));
}


// Bucket::

// Bucket::new()

#[test]
fn bucket_new_test() {
    fn with_capacity(num: u8) {
        let default = Bucket::new(None);
        assert_eq!(BUCKET_DEFAULT_SIZE, default.nodes.capacity());
        let bucket = Bucket::new(Some(num));
        assert_eq!(num as usize, bucket.nodes.capacity());

        // check if always the same with same parameters
        let default2 = Bucket::new(None);
        assert_eq!(default, default2);
        let bucket2 = Bucket::new(Some(num));
        assert_eq!(bucket, bucket2);

        if num as usize != BUCKET_DEFAULT_SIZE  {
            assert!(default != bucket);
        } else {
            assert_eq!(default, bucket);
        }
    }
    quickcheck(with_capacity as fn(u8));
}

// Bucket::try_add()

#[test]
fn bucket_try_add_test() {
    fn with_nodes(n1: PackedNode, n2: PackedNode, n3: PackedNode,
                  n4: PackedNode, n5: PackedNode, n6: PackedNode,
                  n7: PackedNode, n8: PackedNode) {
        let pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut node = Bucket::new(None);
        assert_eq!(true, node.try_add(&pk, &n1));
        assert_eq!(true, node.try_add(&pk, &n2));
        assert_eq!(true, node.try_add(&pk, &n3));
        assert_eq!(true, node.try_add(&pk, &n4));
        assert_eq!(true, node.try_add(&pk, &n5));
        assert_eq!(true, node.try_add(&pk, &n6));
        assert_eq!(true, node.try_add(&pk, &n7));
        assert_eq!(true, node.try_add(&pk, &n8));

        // updating node
        assert_eq!(true, node.try_add(&pk, &n1));

        // TODO: check whether adding a closest node will always work
    }
    quickcheck(with_nodes as fn(PackedNode, PackedNode, PackedNode, PackedNode,
                PackedNode, PackedNode, PackedNode, PackedNode));
}

// Bucket::remove()

#[test]
fn bucket_remove_test() {
    fn with_nodes(num: u8, bucket_size: u8, rng_num: usize) {
        let pk = PublicKey([0; PUBLICKEYBYTES]);

        let mut rm_pubkeys: Vec<PublicKey> = Vec::new();
        let mut bucket = Bucket::new(Some(bucket_size));

        drop(bucket.remove(&pk));  // "removing" non-existent node
        assert_eq!(true, bucket.is_empty());

        let mut rng = StdGen::new(ChaChaRng::new_unseeded(), rng_num);
        for _ in 0..num {
            let node: PackedNode = Arbitrary::arbitrary(&mut rng);
            rm_pubkeys.push(node.pk);
            drop(bucket.try_add(&pk, &node));
        }

        for pubkey in &rm_pubkeys {
            bucket.remove(pubkey);
        }
        assert_eq!(true, bucket.is_empty());
    }
    quickcheck(with_nodes as fn(u8, u8, usize))
}


// Bucket::is_empty()

#[test]
fn bucket_is_empty_test() {
    fn with_pns(pns: Vec<PackedNode>, p1: u64, p2: u64, p3: u64, p4: u64) {
        let mut bucket = Bucket::new(None);
        assert_eq!(true, bucket.is_empty());

        let pk = nums_to_pk(p1, p2, p3, p4);
        for n in &pns {
            drop(bucket.try_add(&pk, n));
        }
        if !pns.is_empty() {
            assert_eq!(false, bucket.is_empty());
        }
    }
    quickcheck(with_pns as fn(Vec<PackedNode>, u64, u64, u64, u64));
}


// Kbucket::

impl Arbitrary for Kbucket {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let mut pk = [0; PUBLICKEYBYTES];
        g.fill_bytes(&mut pk);
        let pk = PublicKey([0; PUBLICKEYBYTES]);

        let mut kbucket = Kbucket::new(g.gen(), &pk);

        // might want to add some buckets
        for _ in 0..(g.gen_range(0, KBUCKET_MAX_ENTRIES as usize *
                        BUCKET_DEFAULT_SIZE as usize * 2)) {
            drop(kbucket.try_add(&Arbitrary::arbitrary(g)));
        }
        kbucket
    }
}

// Kbucket::new()

#[test]
fn kbucket_new_test() {
    fn with_pk(a: u64, b: u64, c: u64, d: u64, buckets: u8) {
        let pk = nums_to_pk(a, b, c, d);
        let kbucket = Kbucket::new(buckets, &pk);
        assert_eq!(buckets, kbucket.n);
        assert_eq!(pk, kbucket.pk);
    }
    quickcheck(with_pk as fn(u64, u64, u64, u64, u8));
}

// Kbucket::try_add()

#[test]
fn kbucket_try_add_test() {
    fn with_pns(pns: Vec<PackedNode>, n: u8, p1: u64, p2: u64, p3: u64, p4: u64) {
        let pk = nums_to_pk(p1, p2, p3, p4);
        let mut kbucket = Kbucket::new(n, &pk);
        for node in pns {
            // result may vary, so discard it
            // TODO: can be done better?
            drop(kbucket.try_add(&node));
        }
    }
    quickcheck(with_pns as fn(Vec<PackedNode>, u8, u64, u64, u64, u64));
}

// Kbucket::remove()

#[test]
fn kbucket_remove_test() {
    // TODO: test for actually removing something
    fn with_kbucket(kb: Kbucket, remove: usize) {
        let mut kb = kb;
        for _ in 0..remove {
            let pk = nums_to_pk(random_u64(), random_u64(), random_u64(),
                random_u64());
            kb.remove(&pk);
        }
    }
    quickcheck(with_kbucket as fn(Kbucket, usize));
}

// Kbucket::get_closest()

#[test]
fn kbucket_get_closest_test() {
    fn with_kbucket(kb: Kbucket, a: u64, b: u64, c: u64, d: u64) {
        let pk = nums_to_pk(a, b, c, d);
        assert!(kb.get_closest(&pk).len() <= 4);
        assert_eq!(kb.get_closest(&pk), kb.get_closest(&pk));
    }
    quickcheck(with_kbucket as fn(Kbucket, u64, u64, u64, u64));


    fn with_nodes(n1: PackedNode, n2: PackedNode, n3: PackedNode,
                    n4: PackedNode, a: u64, b: u64, c: u64, d: u64) {

        let pk = nums_to_pk(a, b, c, d);
        let mut kbucket = Kbucket::new(::std::u8::MAX, &pk);

        // check whether number of correct nodes that are returned is right
        let correctness = |should, kbc: &Kbucket| {
            assert_eq!(kbc.get_closest(&pk), kbc.get_closest(&kbc.pk));

            let got_nodes = kbc.get_closest(&pk);
            let mut got_correct = 0;
            for node in got_nodes {
                if node == n1 || node == n2 || node == n3 || node == n4 {
                    got_correct += 1;
                }
            }
            assert_eq!(should, got_correct);
        };

        correctness(0, &kbucket);

        assert_eq!(true, kbucket.try_add(&n1));
        correctness(1, &kbucket);
        assert_eq!(true, kbucket.try_add(&n2));
        correctness(2, &kbucket);
        assert_eq!(true, kbucket.try_add(&n3));
        correctness(3, &kbucket);
        assert_eq!(true, kbucket.try_add(&n4));
        correctness(4, &kbucket);
    }
    quickcheck(with_nodes as fn(PackedNode, PackedNode, PackedNode,
                    PackedNode, u64, u64, u64, u64));
}


// NatPingReq::

// NatPingReq::new()

#[test]
fn nat_ping_req_new_test() {
    let p1 = NatPingReq::new();
    let p2 = NatPingReq::new();
    assert!(p1 != p2);
    assert!(p1.id() != p2.id());
}

// NatPingReq::id()

#[test]
fn nat_ping_req_id_test() {
    let ping = NatPingReq::new();
    assert_eq!(ping.id(), ping.id());
}



// NatPingResp::

// NatPingResp::id()

#[test]
fn nat_ping_resp_id_test() {
    fn with_np(np: NatPingReq) {
        assert_eq!(np.id(), NatPingResp::from(np).id());
    }
    quickcheck(with_np as fn(NatPingReq));
}

// NatPingResp::to_bytes()

#[test]
fn nat_ping_resp_to_bytes_test_cmp_to_req() {
    fn with_np(p: NatPingReq) {
        let pqb = p.to_bytes();
        let prb = NatPingResp::from(p).to_bytes();
        assert_eq!(pqb[0], prb[0]);
        assert!(pqb[1] != prb[1]);
        // `id` of the ping should not change
        assert_eq!(pqb[2..], prb[2..]);
    }
    quickcheck(with_np as fn(NatPingReq));
}

macro_rules! impls_tests_for_nat_pings {
    ($($np:ident($p:ident) $b_t:ident $f_t:ident $p_t:ident $d_t:ident)+) => ($(
        impl Arbitrary for $np {
            fn arbitrary<G: Gen>(g: &mut G) -> Self {
                $np(Arbitrary::arbitrary(g))
            }
        }

        #[test]
        fn $b_t() {
            fn with_np(p: $np) {
                let pb = p.to_bytes();
                assert_eq!(NAT_PING_SIZE, pb.len());
                // check the magic ping type value
                assert_eq!(NAT_PING_TYPE, pb[0]);
                assert_eq!(p.kind() as u8, pb[1]);
            }
            quickcheck(with_np as fn($np));
        }

        // ::from_bytes()

        #[test]
        fn $f_t() {
            fn with_bytes(bytes: Vec<u8>) {
                if bytes.len() < NAT_PING_SIZE ||
                   bytes[0] != NAT_PING_TYPE ||
                   bytes[1] != PacketKind::$p as u8
                {
                    assert_eq!(None, $np::from_bytes(&bytes));
                } else {
                    let p = $np::from_bytes(&bytes)
                        .expect("De-serialization failed");
        
                    assert_eq!(p.id(), NativeEndian::read_u64(&bytes[2..NAT_PING_SIZE]));
                }
            }
            quickcheck(with_bytes as fn(Vec<u8>));
        
            // just in case
            let mut ping = vec![NAT_PING_TYPE, PacketKind::$p as u8];
            ping.write_u64::<NativeEndian>(random_u64())
                .expect("Failed to write Ping id!");
            with_bytes(ping);
        }

        // ::parse_bytes()

        #[test]
        fn $p_t() {
            fn with_bytes(np: $np, r_rest: Vec<u8>) {
                let mut bytes = vec![];
                bytes.extend_from_slice(&np.to_bytes());
                bytes.extend_from_slice(&r_rest);
        
                let Parsed(_, rest) = $np::parse_bytes(&bytes)
                    .expect("Parsing failure.");
                assert_eq!(&r_rest[..], rest);
            }
            quickcheck(with_bytes as fn($np, Vec<u8>));
        }

        // ::deref()

        #[test]
        fn $d_t() {
            fn with_ping(ping: $p) {
                assert_eq!(*$np(ping), ping);
            }
            quickcheck(with_ping as fn($p));
        }
    )+)
}
impls_tests_for_nat_pings!(
    NatPingReq(PingReq)
        nat_ping_req_to_bytes_test
        nat_ping_req_from_bytes_test
        nat_ping_req_parse_bytes_test
        nat_ping_req_deref_test
    NatPingResp(PingResp)
        nat_ping_resp_to_bytes_test
        nat_ping_resp_from_bytes_test
        nat_ping_resp_parse_bytes_test
        nat_ping_resp_deref_test
);



// DhtRequest::new()

#[test]
fn dht_request_new_test() {
    // TODO: once DhtRequest will support more types, expand the test
    fn with_req<R>(req: R)
        where R: DhtRequestT
    {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _) = gen_keypair();
        let nonce = gen_nonce();
        let dr = DhtRequest::new(&alice_sk, &alice_pk, &bob_pk, &nonce, &req);
        let dr2 = DhtRequest::new(&alice_sk, &alice_pk, &bob_pk, &nonce, &req);
        assert_eq!(dr, dr2);
        assert_eq!(dr.receiver, bob_pk);
        assert_eq!(dr.sender, alice_pk);

        let nonce2 = gen_nonce();
        let dr3 = DhtRequest::new(&alice_sk, &alice_pk, &bob_pk, &nonce2, &req);
        assert!(dr != dr3);
    }
    quickcheck(with_req as fn(NatPingReq));
    quickcheck(with_req as fn(NatPingResp));
}

// DhtRequest::get_request()

#[test]
fn dht_request_get_request_test() {
    fn with_req<R>(req: R)
        where R: DhtRequestT
    {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();
        let nonce = gen_nonce();
        let dreq = DhtRequest::new(&alice_sk, &alice_pk, &bob_pk, &nonce, &req);

        let received = dreq.get_request(&bob_sk).expect("Failed to get request");
        assert_eq!(req, received);
    }
    quickcheck(with_req as fn(NatPingReq));
    quickcheck(with_req as fn(NatPingResp));
}
