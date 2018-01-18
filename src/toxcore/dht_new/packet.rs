/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2016-2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2018 Namsoo CHO <nscho66@gmail.com>

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

/*
    Packet structure

    first class                         second class
    ------------------------+--------------------------------------------
    PingRequest             +    ----------------------
    PingResponse            +    | this 4 first class packet is also
    GetNodes                + <--| grouped as DhtPacket
    SendNodes               +    ----------------------
    ------------------------+--------------------------------------------
    DhtRequest              +    NatPingRequest and NatPingResponse
    ------------------------+--------------------------------------------
*/

/*! DHT packet part of the toxcore.
    * takes care of the serializing and de-serializing DHT packets
*/

use nom::{le_u8, le_u16, be_u64, be_u16};

use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    SocketAddr,
};

use toxcore::dht_new::binary_io::*;
use toxcore::crypto_core::*;

/// Length in bytes of [`PingRequest`](./struct.PingRequest.html) and
/// [`PingResponse`](./struct.PingResponse.html) when serialized into bytes.
pub const PING_SIZE: usize = 9;

/** Standard DHT packet that encapsulates in the payload
[`DhtPacketT`](./trait.DhtPacketT.html).

https://zetok.github.io/tox-spec/#dht-packet
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DhtPacket {
    /// [`PingRequest`](./struct.PingRequest.html) structure.
    PingRequest(PingRequest),
    /// [`PingResponse`](./struct.PingResponse.html) structure.
    PingResponse(PingResponse),
    /// [`GetNodes`](./struct.GetNodes.html) structure.
    GetNodes(GetNodes),
    /// [`SendNodes`](./struct.SendNodes.html) structure.
    SendNodes(SendNodes),
}

impl ToBytes for DhtPacket {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            DhtPacket::PingRequest(ref p) => p.to_bytes(buf),
            DhtPacket::PingResponse(ref p) => p.to_bytes(buf),
            DhtPacket::GetNodes(ref p) => p.to_bytes(buf),
            DhtPacket::SendNodes(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for DhtPacket {
    named!(from_bytes<DhtPacket>, alt!(
        map!(PingRequest::from_bytes, DhtPacket::PingRequest) |
        map!(PingResponse::from_bytes, DhtPacket::PingResponse) |
        map!(GetNodes::from_bytes, DhtPacket::GetNodes) |
        map!(SendNodes::from_bytes, DhtPacket::SendNodes)
    ));
}

/**
Used to request/respond to ping. Used in an encrypted form.

Used in:

- [`DhtPacket`](./struct.DhtPacket.html)
- [`DhtRequest`](./struct.DhtRequest.html)

Serialized form:

Ping Packet (request and response)

Packet type `0x00` for request.

Response ID must match ID of the request, otherwise ping is invalid.

Length      | Contents
----------- | --------
`1`         | 0x00
`8`         | Ping ID

Serialized form should be put in the encrypted part of DHT packet.

[`PingResponse`](./struct.PingResponse.html) can only be created as a response
to [`PingRequest`](./struct.PingRequest.html).
*/

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PingRequest {
    /// Request ping id
    pub id: u64,
}

impl FromBytes for PingRequest {
    named!(from_bytes<PingRequest>, do_parse!(
        tag!("\x00") >>
        id: be_u64 >>
        (PingRequest { id: id})
    ));
}

impl ToBytes for PingRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x00) >>
            gen_be_u64!(self.id)
        )
    }
}

/**
Used to request/respond to ping. Used in an encrypted form.

Used in:

- [`DhtPacket`](./struct.DhtPacket.html)
- [`DhtRequest`](./struct.DhtRequest.html)

Serialized form:

Ping Packet (request and response)

Packet type `0x01` for response.

Response ID must match ID of the request, otherwise ping is invalid.

Length      | Contents
----------- | --------
`1`         | 0x01
`8`         | Ping ID

Serialized form should be put in the encrypted part of DHT packet.

[`PingResponse`](./struct.PingResponse.html) can only be created as a response
to [`PingRequest`](./struct.PingRequest.html).
*/

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PingResponse {
    /// Ping id same as requested from PingRequest
    pub id: u64,
}

impl FromBytes for PingResponse {
    named!(from_bytes<PingResponse>, do_parse!(
        tag!("\x01") >>
        id: be_u64 >>
        (PingResponse { id: id})
    ));
}

impl ToBytes for PingResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x01) >>
            gen_be_u64!(self.id)
        )
    }
}

// Ip Type
// Value | Type
// ----- | ----
// `2`   | UDP IPv4
// `10`  | UDP IPv6
// `130` | TCP IPv4
// `138` | TCP IPv6

// TODO: move it somewhere else
impl ToBytes for IpAddr {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            IpAddr::V4(ref p) => p.to_bytes(buf),
            IpAddr::V6(ref p) => p.to_bytes(buf),
        }
    }
}

// TODO: move it somewhere else
impl FromBytes for Ipv4Addr {
    named!(from_bytes<Ipv4Addr>, map!(count!(le_u8, 4), 
        |v| Ipv4Addr::new(v[0], v[1], v[2], v[3])
    ));
}

impl ToBytes for Ipv4Addr {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        let o = self.octets();
        do_gen!(buf,
            gen_be_u8!(o[0]) >>
            gen_be_u8!(o[1]) >>
            gen_be_u8!(o[2]) >>
            gen_be_u8!(o[3]) 
        )
    }
}

// TODO: move it somewhere else
impl FromBytes for Ipv6Addr {
    named!(from_bytes<Ipv6Addr>, map!(count!(le_u16, 8), 
        |v| Ipv6Addr::new(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7])
    ));
}

impl ToBytes for Ipv6Addr {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        let s = self.segments();
        do_gen!(buf,
            gen_le_u16!(s[0]) >>
            gen_le_u16!(s[1]) >>
            gen_le_u16!(s[2]) >>
            gen_le_u16!(s[3]) >>
            gen_le_u16!(s[4]) >>
            gen_le_u16!(s[5]) >>
            gen_le_u16!(s[6]) >>
            gen_le_u16!(s[7]) 
        )
    }
}

/** `PackedNode` format is a way to store the node info in a small yet easy to
parse format.

It is used in many places in Tox, e.g. in `DHT Send nodes`.

To store more than one node, simply append another on to the previous one:

`[packed node 1][packed node 2][...]`

Serialized Packed node:

Length | Content
------ | -------
1      | Ip type (v4 or v6)
4 or 16| IPv4 or IPv6 address
2      | port
32     | node ID

Size of serialized `PackedNode` is 39 bytes with IPv4 node info, or 51 with
IPv6 node info.

DHT module *should* use only UDP variants of Ip type, given that DHT runs
solely on the UDP.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PackedNode {
    /// Socket addr of node.
    saddr: SocketAddr,
    /// Public Key of the node.
    pub pk: PublicKey,
}

impl ToBytes for PackedNode {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_if_else!(self.saddr.is_ipv4(), gen_be_u8!(2), gen_be_u8!(10)) >>
            gen_call!(|buf, addr| IpAddr::to_bytes(addr, buf), &self.saddr.ip()) >>
            gen_be_u16!(self.saddr.port()) >>
            gen_slice!(self.pk.as_ref())
        )
    }
}

/** Deserialize bytes into `PackedNode`. Returns `Error` if deseralizing
failed.

Can fail if:

 - length is too short for given Ip Type
 - PK can't be parsed

Blindly trusts that provided `Ip Type` matches - i.e. if there are provided
51 bytes (which is length of `PackedNode` that contains IPv6), and `Ip Type`
says that it's actually IPv4, bytes will be parsed as if that was an IPv4
address.
*/

impl FromBytes for PackedNode {
    named!(from_bytes<PackedNode>, do_parse!(
        addr: switch!(le_u8,
            2  => map!(Ipv4Addr::from_bytes, IpAddr::V4) |
            10 => map!(Ipv6Addr::from_bytes, IpAddr::V6)
        ) >>
        port: be_u16 >>
        saddr: value!(SocketAddr::new(addr, port)) >>
        pk: call!(PublicKey::from_bytes) >>
        (PackedNode { saddr: saddr, pk: pk })
    ));
}

/** Request to get address of given DHT PK, or nodes that are closest in DHT
to the given PK.

Serialized form:

Length | Content
------ | ------
`32`   | DHT Public Key
`8`    | ping id

Serialized form should be put in the encrypted part of DHT packet.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GetNodes {
    /// Public Key of the DHT node `GetNodes` is supposed to get address of.
    pub pk: PublicKey,
    /// An ID of the request.
    pub id: u64,
}

impl ToBytes for GetNodes {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.pk.as_ref()) >>
            gen_be_u64!(self.id)
        )
    }
}

impl FromBytes for GetNodes {
    named!(from_bytes<GetNodes>, do_parse!(
        pk: call!(PublicKey::from_bytes) >>
        id: be_u64 >>
        (GetNodes { pk: pk, id: id })
    ));
}

/** Response to [`GetNodes`](./struct.GetNodes.html) request, containing up to
`4` nodes closest to the requested node.

Serialized form:

Length      | Contents
----------- | --------
`1`         | Number of packed nodes (maximum 4)
`[39, 204]` | Nodes in packed format
`8`         | ping id

An IPv4 node is 39 bytes, an IPv6 node is 51 bytes, so the maximum size is
`51 * 4 = 204` bytes.

Serialized form should be put in the encrypted part of DHT packet.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendNodes {
    /** Nodes sent in response to [`GetNodes`](./struct.GetNodes.html) request.

    There can be only 1 to 4 nodes in `SendNodes`.
    */
    pub nodes: Vec<PackedNode>,
    /// request id
    pub id: u64,
}

impl ToBytes for SendNodes {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_if_else!(!self.nodes.is_empty() && self.nodes.len() <= 4,
                gen_be_u8!(self.nodes.len() as u8), gen_call!(|_,_| Err(GenError::CustomError(0)), 1) ) >>
            gen_many_ref!(&self.nodes, |buf, node| PackedNode::to_bytes(node, buf)) >>
            gen_be_u64!(self.id)
        )
    }
}

impl FromBytes for SendNodes {
    named!(from_bytes<SendNodes>, do_parse!(
        nodes_number: le_u8 >>
        nodes: cond_reduce!(
            nodes_number > 0 && nodes_number <= 4,
            count!(PackedNode::from_bytes, nodes_number as usize)
        ) >>
        id: be_u64 >>
        (SendNodes {
            nodes: nodes,
            id: id,
        })
    ));
}

/** DHT Request packet.

https://zetok.github.io/tox-spec/#dht-request-packets
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DhtRequest {
    /// [`NatPingRequest`](./struct.NatPingRequest.html) structure.
    NatPingRequest(NatPingRequest),
    /// [`NatPingResponse`](./struct.NatPingResponse.html) structure.
    NatPingResponse(NatPingResponse),
}

/** NatPing request of DHT Request packet.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NatPingRequest {
    /// Request ping id
    pub id: u64,
}

/** NatPing response of DHT Request packet.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NatPingResponse {
    /// Ping id same as requested from PingRequest
    pub id: u64,
}

impl ToBytes for DhtRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            DhtRequest::NatPingRequest(ref p) => p.to_bytes(buf),
            DhtRequest::NatPingResponse(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for DhtRequest {
    named!(from_bytes<DhtRequest>, alt!(
        map!(NatPingRequest::from_bytes, DhtRequest::NatPingRequest) |
        map!(NatPingResponse::from_bytes, DhtRequest::NatPingResponse)
    ));
}

impl FromBytes for NatPingRequest {
    named!(from_bytes<NatPingRequest>, do_parse!(
        tag!(&[0xfe][..]) >>
        tag!("\x00") >>
        id: be_u64 >>
        (NatPingRequest { id: id})
    ));
}

impl ToBytes for NatPingRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0xfe) >>
            gen_be_u8!(0x00) >>
            gen_be_u64!(self.id)
        )
    }
}

impl FromBytes for NatPingResponse {
    named!(from_bytes<NatPingResponse>, do_parse!(
        tag!(&[0xfe][..]) >>
        tag!("\x01") >>
        id: be_u64 >>
        (NatPingResponse { id: id})
    ));
}

impl ToBytes for NatPingResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0xfe) >>
            gen_be_u8!(0x01) >>
            gen_be_u64!(self.id)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fmt::Debug;
    use std::net::{SocketAddrV4, SocketAddrV6};
    use byteorder::{ByteOrder, BigEndian, WriteBytesExt};

    use quickcheck::{Arbitrary, Gen, quickcheck};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum PacketKind {
        PingRequest       = 0,
        PingResponse      = 1,
    }
    const NatPingRequest: PacketKind = PacketKind::PingRequest;
    const NatPingResponse: PacketKind = PacketKind::PingResponse;

    // PingRequest::
    impl Arbitrary for PingRequest {
        fn arbitrary<G: Gen>(_g: &mut G) -> Self {
            PingRequest::new()
        }
    }
    
    // PingResponse::
    impl Arbitrary for PingResponse {
        fn arbitrary<G: Gen>(_g: &mut G) -> Self {
            PingRequest::new().into()
        }
    }

    impl PingRequest {
        /// Create new ping request with a randomly generated `request id`.
        pub fn new() -> Self {
            trace!("Creating new Ping.");
            PingRequest { id: random_u64() }
        }

        /// An ID of the request / response.
        pub fn id(&self) -> u64 {
            self.id
        }
    }

    impl PingResponse {
        /// An ID of the request / response.
        pub fn id(&self) -> u64 {
            self.id
        }
    }

    impl From<PingRequest> for PingResponse {
        fn from(p: PingRequest) -> Self {
            PingResponse { id: p.id }
        }
    }

    // PingRequest::
    impl Arbitrary for NatPingRequest {
        fn arbitrary<G: Gen>(_g: &mut G) -> Self {
            NatPingRequest::new()
        }
    }
    
    // PingResponse::
    impl Arbitrary for NatPingResponse {
        fn arbitrary<G: Gen>(_g: &mut G) -> Self {
            NatPingRequest::new().into()
        }
    }

    impl NatPingRequest {
        /// Create new ping request with a randomly generated `request id`.
        pub fn new() -> Self {
            trace!("Creating new Ping.");
            NatPingRequest { id: random_u64() }
        }

        /// An ID of the request / response.
        pub fn id(&self) -> u64 {
            self.id
        }
    }

    impl NatPingResponse {
        /// An ID of the request / response.
        pub fn id(&self) -> u64 {
            self.id
        }
    }

    impl From<NatPingRequest> for NatPingResponse {
        fn from(p: NatPingRequest) -> Self {
            NatPingResponse { id: p.id }
        }
    }

    /// Trait for types of DHT packets that can be put in [`DhtPacket`]
    /// (./struct.DhtPacket.html).
    pub trait DhtPacketT: ToBytes + FromBytes + Eq + PartialEq + Debug {
        /// Provide packet type number.
        ///
        /// To use for serialization: `.kind() as u8`.
        fn kind(&self) -> PacketKind;

    }

    macro_rules! tests_for_pings {
        ($($p:ident $b_t:ident $f_t:ident)+) => ($(

            // ::to_bytes()
            #[test]
            fn $b_t() {
                fn with_ping(p: $p) {
                    let mut _buf = [0; 1024];
                    let pb = p.to_bytes((&mut _buf, 0)).ok().unwrap();
                    assert_eq!(PING_SIZE, pb.1);
                    assert_eq!(PacketKind::$p as u8, pb.0[0]);
                }
                quickcheck(with_ping as fn($p));
            }

            // ::from_bytes()
            #[test]
            fn $f_t() {
                fn with_bytes(bytes: Vec<u8>) {
                    if bytes.len() < PING_SIZE ||
                    bytes[0] != PacketKind::$p as u8 {
                        assert!(!($p::from_bytes(&bytes)).is_done());
                    } else {
                        let p = $p::from_bytes(&bytes).unwrap();
                        // `id` should not differ
                        assert_eq!(p.1.id(), BigEndian::read_u64(&bytes[1..PING_SIZE]));
                    }
                }
                quickcheck(with_bytes as fn(Vec<u8>));

                // just in case
                let mut ping = vec![PacketKind::$p as u8];
                ping.write_u64::<BigEndian>(random_u64()).unwrap();
                with_bytes(ping);
            }
        )+)
    }
    tests_for_pings!(PingRequest
                        packet_ping_req_to_bytes_test
                        packet_ping_req_from_bytes_test
                    PingResponse
                        packet_ping_resp_to_bytes_test
                        packet_ping_resp_from_bytes_test
    );

    // GetNodes::
    impl Arbitrary for GetNodes {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let mut a: [u8; PUBLICKEYBYTES] = [0; PUBLICKEYBYTES];
            g.fill_bytes(&mut a);
            GetNodes { pk: PublicKey(a), id: g.gen() }
        }
    }

    impl Arbitrary for DhtPacket {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let mut a: [u8; PUBLICKEYBYTES] = [0; PUBLICKEYBYTES];
            g.fill_bytes(&mut a);
            DhtPacket::GetNodes(GetNodes { pk: PublicKey(a), id: g.gen() })
        }
    }

    // GetNodes::to_bytes()
    #[test]
    fn packet_get_nodes_to_bytes_test() {
        fn with_gn(gn: GetNodes) {
            let mut _buf = [0;1024];
            let g_bytes = gn.to_bytes((&mut _buf, 0)).ok().unwrap().0;
            let PublicKey(pk_bytes) = gn.pk;
            assert_eq!(&pk_bytes, &g_bytes[..PUBLICKEYBYTES]);
            assert_eq!(gn.id, BigEndian::read_u64(&g_bytes[PUBLICKEYBYTES..]));
        }
        quickcheck(with_gn as fn(GetNodes));
    }

    /// Size of serialized [`GetNodes`](./struct.GetNodes.html) in bytes.
    pub const GET_NODES_SIZE: usize = PUBLICKEYBYTES + 8;

    // GetNodes::from_bytes()
    #[test]
    fn packet_get_nodes_from_bytes_test() {
        fn with_bytes(bytes: Vec<u8>) {
            if bytes.len() < GET_NODES_SIZE {
                assert!(!GetNodes::from_bytes(&bytes).is_done());
            } else {
                let gn = GetNodes::from_bytes(&bytes).unwrap().1;
                // ping_id as bytes should match "original" bytes
                assert_eq!(BigEndian::read_u64(&bytes[PUBLICKEYBYTES..GET_NODES_SIZE]), gn.id);

                let PublicKey(ref pk) = gn.pk;
                assert_eq!(pk, &bytes[..PUBLICKEYBYTES]);
            }
        }
        quickcheck(with_bytes as fn(Vec<u8>));
    }

    // DhtPacket::GetNodes::to_bytes()
    #[test]
    fn dht_packet_get_nodes_to_bytes_test() {
        fn with_gn(gn: DhtPacket) {
            let mut _buf = [0;1024];
            let g_bytes = gn.to_bytes((&mut _buf, 0)).ok().unwrap().0;
            if let DhtPacket::GetNodes(gp) = gn {
                let PublicKey(pk_bytes) = gp.pk;
                assert_eq!(&pk_bytes, &g_bytes[..PUBLICKEYBYTES]);
                assert_eq!(gp.id, BigEndian::read_u64(&g_bytes[PUBLICKEYBYTES..]));
            }
        }
        quickcheck(with_gn as fn(DhtPacket));
    }

    // DhtPacket::GetNodes::from_bytes()
    #[test]
    fn dht_packet_get_nodes_from_bytes_test() {
        fn with_bytes(bytes: Vec<u8>) {
            if bytes.len() < GET_NODES_SIZE {
                assert!(!DhtPacket::from_bytes(&bytes).is_done());
            } else {
                let gn = DhtPacket::from_bytes(&bytes).unwrap().1;
                if let DhtPacket::GetNodes(gp) = gn {
                    // ping_id as bytes should match "original" bytes
                    assert_eq!(BigEndian::read_u64(&bytes[PUBLICKEYBYTES..GET_NODES_SIZE]), gp.id);

                    let PublicKey(ref pk) = gp.pk;
                    assert_eq!(pk, &bytes[..PUBLICKEYBYTES]);
                }
            }
        }
        quickcheck(with_bytes as fn(Vec<u8>));
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

    impl PackedNode {
        /** New `PackedNode`.

        `udp` - whether UDP or TCP should be used. UDP is used for DHT nodes,
        whereas TCP is used for TCP relays. When `true`, UDP is used, otherwise
        TCP is used.
        */
        pub fn new(udp: bool, saddr: SocketAddr, pk: &PublicKey) -> Self {
            debug!(target: "PackedNode", "Creating new PackedNode.");
            trace!(target: "PackedNode", "With args: udp: {}, saddr: {:?}, PK: {:?}",
                udp, &saddr, pk);

            PackedNode {
                saddr: saddr,
                pk: *pk,
            }
        }

        /// Get an IP type from the `PackedNode`.
        pub fn ip_type(&self) -> u8 {
            trace!(target: "PackedNode", "Getting IP type from PackedNode.");
            trace!("With address: {:?}", self);
            if self.saddr.is_ipv4() {
                2
            }
            else {
                10
            }
        }

        /// Get an IP address from the `PackedNode`.
        pub fn ip(&self) -> IpAddr {
            trace!(target: "PackedNode", "Getting IP address from PackedNode.");
            trace!("With address: {:?}", self);
            match self.saddr {
                SocketAddr::V4(addr) => IpAddr::V4(*addr.ip()),
                SocketAddr::V6(addr) => IpAddr::V6(*addr.ip()),
            }
        }

        /// Get a Socket address from the `PackedNode`.
        pub fn socket_addr(&self) -> SocketAddr {
            trace!(target: "PackedNode", "Getting Socket address from PackedNode.");
            trace!("With address: {:?}", self);
            self.saddr
        }

        /// Get an PK from the `PackedNode`.
        pub fn pk(&self) -> &PublicKey {
            trace!(target: "PackedNode", "Getting PK from PackedNode.");
            trace!("With PK: {:?}", self);
            &self.pk
        }

    }

    // SendNodes::
    impl Arbitrary for SendNodes {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let nodes = vec![Arbitrary::arbitrary(g); g.gen_range(1,4)];
            let id = g.gen();
            SendNodes { nodes: nodes, id: id }
        }
    }

    impl SendNodes {
        /**
        Create new `SendNodes`. Returns `None` if 0 or more than 4 nodes are
        supplied.

        Created as a response to `GetNodes` request.
        */
        pub fn with_nodes(request: &GetNodes, nodes: Vec<PackedNode>) -> Option<Self> {
            debug!(target: "SendNodes", "Creating SendNodes from GetNodes.");
            trace!(target: "SendNodes", "With GetNodes: {:?}", request);
            trace!("With nodes: {:?}", &nodes);

            if nodes.is_empty() || nodes.len() > 4 {
                warn!(target: "SendNodes", "Wrong number of nodes supplied!");
                return None
            }

            Some(SendNodes { nodes: nodes, id: request.id })
        }
    }

    // SendNodes::to_bytes()
    #[test]
    fn packet_send_nodes_to_bytes_test() {
        // there should be at least 1 valid node; there can be up to 4 nodes
        fn with_nodes(req: GetNodes, n1: PackedNode, n2: Option<PackedNode>,
                    n3: Option<PackedNode>, n4: Option<PackedNode>) {

            let mut _buf = [0;1024];
            let mut nodes = vec![n1];
            if let Some(n) = n2 { nodes.push(n); }
            if let Some(n) = n3 { nodes.push(n); }
            if let Some(n) = n4 { nodes.push(n); }
            let sn_bytes = SendNodes::with_nodes(&req, nodes.clone())
                            .unwrap().to_bytes((&mut _buf, 0)).ok().unwrap().0;

            // number of nodes should match
            assert_eq!(nodes.len(), sn_bytes[0] as usize);

            // bytes before current PackedNode in serialized SendNodes
            // starts from `1` since first byte of serialized SendNodes is number of
            // nodes
            let mut len_before = 1;
            for node in &nodes {
                let mut _buf = [0; 1024];
                let cur_len = node.to_bytes((&mut _buf, 0)).ok().unwrap().1;
                assert_eq!(&_buf[..cur_len],
                        &sn_bytes[len_before..(len_before + cur_len)]);
                len_before += cur_len;
            }
            // ping id should be the same as in request
            assert_eq!(req.id, BigEndian::read_u64(&sn_bytes[len_before..]));
        }
        quickcheck(with_nodes as fn(GetNodes, PackedNode, Option<PackedNode>,
                                    Option<PackedNode>, Option<PackedNode>));
    }

    // SendNodes::from_bytes()
    #[test]
    fn packet_send_nodes_from_bytes_test() {
        fn with_nodes(nodes: Vec<PackedNode>, r_u64: u64) {
            let mut bytes = vec![nodes.len() as u8];
            let mut _buf = [0; 1024];
            for node in &nodes {
                let buf = node.to_bytes((&mut _buf, 0)).ok().unwrap();
                bytes.extend_from_slice(&buf.0[..buf.1]);
            }
            // and ping id
            bytes.write_u64::<BigEndian>(r_u64).unwrap();

            if nodes.len() > 4 || nodes.is_empty() {
                assert!(!SendNodes::from_bytes(&bytes).is_done());
            } else {
                let nodes2 = SendNodes::from_bytes(&bytes).unwrap().1;
                assert_eq!(&nodes, &nodes2.nodes);
                assert_eq!(r_u64, nodes2.id);
            }
        }
        quickcheck(with_nodes as fn(Vec<PackedNode>, u64));
    }
    
    /** `NatPing` type byte for [`NatPingRequest`] and [`NatPingResponse`].
    [./struct.PingRequest.html] [./struct.PingResponse.html]
    */
    pub const NAT_PING_TYPE: u8 = 0xfe;

    /** Length in bytes of NatPings when serialized into bytes.
    */
    pub const NAT_PING_SIZE: usize = PING_SIZE + 1;

    macro_rules! impls_tests_for_nat_pings {
        ($($np:ident $b_t:ident $f_t:ident)+) => ($(
            // impl Arbitrary for $np {
            //     fn arbitrary<G: Gen>(g: &mut G) -> Self {
            //         $np(Arbitrary::arbitrary(g))
            //     }
            // }

            #[test]
            fn $b_t() {
                fn with_np(p: $np) {
                    let mut _buf = [0; 1024];
                    let pb = p.to_bytes((&mut _buf, 0)).ok().unwrap();
                    assert_eq!(NAT_PING_SIZE, pb.1);
                    assert_eq!(NAT_PING_TYPE as u8, pb.0[0]);
                    assert_eq!($np as u8, pb.0[1]);
                }
                quickcheck(with_np as fn($np));
            }

            // ::from_bytes()
            #[test]
            fn $f_t() {
                fn with_bytes(bytes: Vec<u8>) {
                    if bytes.len() < NAT_PING_SIZE ||
                    bytes[0] != NAT_PING_TYPE as u8 {
                        assert!(!($np::from_bytes(&bytes)).is_done());
                    } else {
                        let p = $np::from_bytes(&bytes).unwrap().1;
                        // `id` should not differ
                        assert_eq!(p.id(), BigEndian::read_u64(&bytes[2..NAT_PING_SIZE]));
                    }
                }
                quickcheck(with_bytes as fn(Vec<u8>));

                // just in case
                let mut ping = vec![NAT_PING_TYPE, $np as u8];
                ping.write_u64::<BigEndian>(random_u64())
                    .unwrap();
                with_bytes(ping);
            }
        )+)
    }

    impls_tests_for_nat_pings!(
        NatPingRequest
            packet_nat_ping_req_to_bytes_test
            packet_nat_ping_req_from_bytes_test
        NatPingResponse
            packet_nat_ping_resp_to_bytes_test
            packet_nat_ping_resp_from_bytes_test
    );
}
