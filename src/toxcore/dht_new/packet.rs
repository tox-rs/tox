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


// ↓ FIXME expand doc
/*! DHT part of the toxcore.

    * takes care of the serializing and de-serializing DHT packets
    * ..
*/

use nom::{le_u8, le_u16, be_u64, be_u16};

//use std::cmp::{Ord, Ordering};
//use std::convert::From;
//use std::fmt::Debug;
use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    SocketAddr,
    SocketAddrV4,
    SocketAddrV6
};
//use std::ops::Deref;

use toxcore::dht_new::binary_io::*;
use toxcore::crypto_core::*;

/// Length in bytes of [`PingReq`](./struct.PingReq.html) and
/// [`PingResp`](./struct.PingResp.html) when serialized into bytes.
pub const PING_SIZE: usize = 9;

/** `NatPing` type byte for [`NatPingReq`] and [`NatPingResp`].

https://zetok.github.io/tox-spec/#nat-ping-request

[`NatPingReq`]: ./struct.PingReq.html
[`NatPingResp`]: ./struct.PingResp.html
*/
pub const NAT_PING_TYPE: u8 = 0xfe;

/** Length in bytes of NatPings when serialized into bytes.

NatPings:

 - [`NatPingReq`](./struct.PingReq.html)
 - [`NatPingResp`](./struct.PingResp.html)
*/
pub const NAT_PING_SIZE: usize = PING_SIZE + 1;

/** Standard DHT packet that encapsulates in the payload
[`DhtPacketT`](./trait.DhtPacketT.html).

https://zetok.github.io/tox-spec/#dht-packet
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DhtPacket {
    /// [`PingReq`](./struct.PingReq.html) structure.
    PingReq(PingReq),
    /// [`PingResp`](./struct.PingResp.html) structure.
    PingResp(PingResp),
    /// [`GetNodes`](./struct.GetNodes.html) structure.
    GetNodes(GetNodes),
    /// [`SendNodes`](./struct.SendNodes.html) structure.
    SendNodes(SendNodes),
}

impl ToBytes for DhtPacket {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            DhtPacket::PingReq(ref p) => p.to_bytes(buf),
            DhtPacket::PingResp(ref p) => p.to_bytes(buf),
            DhtPacket::GetNodes(ref p) => p.to_bytes(buf),
            DhtPacket::SendNodes(ref p) => p.to_bytes(buf),
        }
    }
}
/// De-serialize bytes into `DhtPacket`.
impl FromBytes for DhtPacket {
    named!(from_bytes<DhtPacket>, alt!(
        map!(PingReq::from_bytes, DhtPacket::PingReq) |
        map!(PingResp::from_bytes, DhtPacket::PingResp) |
        map!(GetNodes::from_bytes, DhtPacket::GetNodes) |
        map!(SendNodes::from_bytes, DhtPacket::SendNodes)
    ));
}

/** Standard DHT request packet.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DhtRequest {
    /// [`NatPingReq`](./struct.PingReq.html) structure.
    NatPingReq(PingReq),
    /// [`NatPingResp`](./struct.PingResp.html) structure.
    NatPingResp(PingResp),
}

/** NatPing request DHT request packet.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NatPingReq(pub PingReq);
/** NatPing response DHT request packet.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NatPingResp(pub PingResp);

impl ToBytes for DhtRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            DhtRequest::NatPingReq(ref p) => p.to_bytes(buf),
            DhtRequest::NatPingResp(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for DhtRequest {
    named!(from_bytes<DhtRequest>, alt!(
        map!(PingReq::from_bytes, DhtRequest::NatPingReq) |
        map!(PingResp::from_bytes, DhtRequest::NatPingResp)
    ));
}

impl FromBytes for NatPingReq {
    named!(from_bytes<NatPingReq>, do_parse!(
        tag!(&[0xfe][..]) >>
        ping: call!(PingReq::from_bytes) >>
        (NatPingReq(ping))
    ));
}

/// Serialize to bytes.
impl ToBytes for NatPingReq {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        let &NatPingReq(x) = self;
        do_gen!(buf,
            gen_be_u8!(0xfe) >>
            gen_call!(|buf, data| PingReq::to_bytes(data, buf), &x)
        )
    }
}

impl FromBytes for NatPingResp {
    named!(from_bytes<NatPingResp>, do_parse!(
        tag!(&[0xfe][..]) >>
        ping: call!(PingResp::from_bytes) >>
        (NatPingResp(ping))
    ));
}

/// Serialize to bytes.
impl ToBytes for NatPingResp {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        let &NatPingResp(x) = self;
        do_gen!(buf,
            gen_be_u8!(0xfe) >>
            gen_call!(|buf, data| PingResp::to_bytes(data, buf), &x)
        )
    }
}

/**
Used to request/respond to ping. Use in an encrypted form.

Used in:

- [`DhtPacket`](./struct.DhtPacket.html)
- [`DhtRequest`](./struct.DhtRequest.html)

Serialized form:

Ping Packet (request and response)

Packet type `0x00` for request and `0x01` for response.

Response ID must match ID of the request, otherwise ping is invalid.

Length      | Contents
----------- | --------
`1`         | 0x00
`8`         | Ping ID

Serialized form should be put in the encrypted part of DHT packet.

# Creating new

[`PingResp`](./struct.PingResp.html) can only be created as a response
to [`PingReq`](./struct.PingReq.html).
*/

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PingReq {
    /// Request ping id
    pub id: u64,
}

impl FromBytes for PingReq {
    named!(from_bytes<PingReq>, do_parse!(
        tag!("\x00") >>
        id: be_u64 >>
        (PingReq { id: id})
    ));
}

/// Serialize to bytes.
impl ToBytes for PingReq {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x00) >>
            gen_be_u64!(self.id)
        )
    }
}

/**
Used to request/respond to ping. Use in an encrypted form.

Used in:

- [`DhtPacket`](./struct.DhtPacket.html)
- [`DhtRequest`](./struct.DhtRequest.html)

Serialized form:

Ping Packet (request and response)

Packet type `0x00` for request and `0x01` for response.

Response ID must match ID of the request, otherwise ping is invalid.

Length      | Contents
----------- | --------
`1`         | 0x01
`8`         | Ping ID

Serialized form should be put in the encrypted part of DHT packet.

# Creating new

[`PingResp`](./struct.PingResp.html) can only be created as a response
to [`PingReq`](./struct.PingReq.html).
*/

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PingResp {
    /// Ping id same as requested from PingReq
    pub id: u64,
}

impl FromBytes for PingResp {
    named!(from_bytes<PingResp>, do_parse!(
        tag!("\x01") >>
        id: be_u64 >>
        (PingResp { id: id})
    ));
}

/// Serialize to bytes.
impl ToBytes for PingResp {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x01) >>
            gen_be_u64!(self.id)
        )
    }
}

/** Used by [`PackedNode`](./struct.PackedNode.html).

* 1st bit – protocol
* 3 bits – `0`
* 4th bit – address family

Value | Type
----- | ----
`2`   | UDP IPv4
`10`  | UDP IPv6
`130` | TCP IPv4
`138` | TCP IPv6

DHT module *should* use only UDP variants of `IpType`, given that DHT runs
solely over the UDP.

TCP variants are to be used for sending/receiving info about TCP relays.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IpType {
    /// UDP over IPv4.
    U4 = 2,
    /// UDP over IPv6.
    U6 = 10,
    /// TCP over IPv4.
    T4 = 130,
    /// TCP over IPv6.
    T6 = 138,
}

/// Match first byte from the provided slice as `IpType`. If no match found,
/// return `Error`.
impl FromBytes for IpType {
    named!(from_bytes<IpType>, switch!(le_u8,
        2   => value!(IpType::U4) |
        10  => value!(IpType::U6) |
        130 => value!(IpType::T4) |
        138 => value!(IpType::T6)
    ));
}

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
/// Fail if there are less than 4 bytes supplied, otherwise parses first
/// 4 bytes as an `Ipv4Addr`.
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
/// Fail if there are less than 16 bytes supplied, otherwise parses first
/// 16 bytes as an `Ipv6Addr`.
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
`1`    | [`IpType`](./.enum.IpType.html)
`4` or `16` | IPv4 or IPv6 address
`2`    | port
`32`   | node ID

Size of serialized `PackedNode` is 39 bytes with IPv4 node info, or 51 with
IPv6 node info.

DHT module *should* use only UDP variants of `IpType`, given that DHT runs
solely on the UDP.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PackedNode {
    /// IP type, includes also info about protocol used.
    ip_type: IpType,
    /// Socket addr of node.
    saddr: SocketAddr,
    /// Public Key of the node.
    pub pk: PublicKey,
}

/// Size in bytes of serialized [`PackedNode`](./struct.PackedNode.html) with
/// IPv4.
pub const PACKED_NODE_IPV4_SIZE: usize = PUBLICKEYBYTES + 7;
/// Size in bytes of serialized [`PackedNode`](./struct.PackedNode.html) with
/// IPv6.
pub const PACKED_NODE_IPV6_SIZE: usize = PUBLICKEYBYTES + 19;
/** Serialize `PackedNode` into bytes.

Can be either [`PACKED_NODE_IPV4_SIZE`]
(./constant.PACKED_NODE_IPV4_SIZE.html) or [`PACKED_NODE_IPV6_SIZE`]
(./constant.PACKED_NODE_IPV6_SIZE.html) bytes long, depending on whether
IPv4 or IPv6 is being used.
*/
impl ToBytes for PackedNode {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(self.ip_type as u8) >>
            gen_call!(|buf, addr| IpAddr::to_bytes(addr, buf), &self.saddr.ip()) >>
            gen_be_u16!(self.saddr.port()) >>
            gen_slice!(self.pk.as_ref())
        )
    }
}

/** Deserialize bytes into `PackedNode`. Returns `Error` if deseralizing
failed.

Can fail if:

 - length is too short for given [`IpType`](./enum.IpType.html)
 - PK can't be parsed

Blindly trusts that provided `IpType` matches - i.e. if there are provided
51 bytes (which is length of `PackedNode` that contains IPv6), and `IpType`
says that it's actually IPv4, bytes will be parsed as if that was an IPv4
address.
*/
named_args!(as_ipv4_packed_node(iptype: IpType) <PackedNode>, do_parse!(
    addr: call!(Ipv4Addr::from_bytes) >>
    port: be_u16 >>
    saddr: value!(SocketAddrV4::new(addr, port)) >>
    pk: call!(PublicKey::from_bytes) >>
    (PackedNode {
        ip_type: iptype,
        saddr: SocketAddr::V4(saddr),
        pk: pk
    })
));

// Parse bytes as an IPv6 PackedNode.
named_args!(as_ipv6_packed_node(iptype: IpType) <PackedNode>, do_parse!(
    addr: call!(Ipv6Addr::from_bytes) >>
    port: be_u16 >>
    saddr: value!(SocketAddrV6::new(addr, port, 0, 0)) >>
    pk: call!(PublicKey::from_bytes) >>
    (PackedNode {
        ip_type: iptype,
        saddr: SocketAddr::V6(saddr),
        pk: pk
    })
));

impl FromBytes for PackedNode {
    named!(from_bytes<PackedNode>, switch!(call!(IpType::from_bytes),
        IpType::U4 => call!(as_ipv4_packed_node, IpType::U4) |
        IpType::T4 => call!(as_ipv4_packed_node, IpType::T4) |
        IpType::U6 => call!(as_ipv6_packed_node, IpType::U6) |
        IpType::T6 => call!(as_ipv6_packed_node, IpType::T6)
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

/// Size of serialized [`GetNodes`](./struct.GetNodes.html) in bytes.
pub const GET_NODES_SIZE: usize = PUBLICKEYBYTES + 8;

/// Serialization of `GetNodes`. Resulting length should be
/// [`GET_NODES_SIZE`](./constant.GET_NODES_SIZE.html).
impl ToBytes for GetNodes {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.pk.as_ref()) >>
            gen_be_u64!(self.id)
        )
    }
}

/** De-serialization of bytes into `GetNodes`. If less than
[`GET_NODES_SIZE`](./constant.GET_NODES_SIZE.html) bytes are provided,
de-serialization will fail, returning `Error`.
*/
impl FromBytes for GetNodes {
    named!(from_bytes<GetNodes>, do_parse!(
        pk: call!(PublicKey::from_bytes) >>
        id: be_u64 >>
        (GetNodes { pk: pk, id: id })
    ));
}

/** Response to [`GetNodes`](./struct.GetNodes.html) request, containing up to
`4` nodes closest to the requested node.

Packet type `0x04`.

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

/// Method assumes that supplied `SendNodes` has correct number of nodes
/// included – `[1, 4]`.
impl ToBytes for SendNodes {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_if_else!(self.nodes.len() > 0 && self.nodes.len() < 5,
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

/** DHT Request packet structure.

Used to send data via one node1 to other node2 via intermediary node when
there is no direct connection between nodes 1 and 2.

`<own node> → <connected, intermediary node> → <not connected node>`

When receiving `DhtRequest` own instance should check whether receiver PK
matches own PK, or PK of a known node.

- if it matches own PK, handle it.
- if it matches PK of a known node, send packet to that node

Serialized structure:

Length | Contents
-------|---------
1      | `0x20`
32     | receiver's DHT public key
32     | sender's DHT public key
24     | Nonce
?      | encrypted data

https://zetok.github.io/tox-spec/#dht-request-packets
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtRequestT {
    /// `PublicKey` of receiver.
    pub receiver: PublicKey,
    /// `PUblicKey` of sender.
    pub sender: PublicKey,
    nonce: Nonce,
    payload: Vec<u8>,
}

#[cfg(test)]
mod test {
    extern crate rand;
    extern crate rustc_serialize;

    use ::toxcore::dht_new::packet::*;
    use ::toxcore::packet_kind::PacketKind;

    use ::std::fmt::Debug;
    use ::byteorder::{ByteOrder, BigEndian, WriteBytesExt};

    use ::quickcheck::{Arbitrary, Gen, quickcheck};
    //use self::rand::chacha::ChaChaRng;

    // PingReq::

    impl Arbitrary for PingReq {
        fn arbitrary<G: Gen>(_g: &mut G) -> Self {
            PingReq::new()
        }
    }
    
    // PingResp::

    impl Arbitrary for PingResp {
        fn arbitrary<G: Gen>(_g: &mut G) -> Self {
            PingReq::new().into()
        }
    }

    impl PingReq {
        /// Create new ping request with a randomly generated `request id`.
        pub fn new() -> Self {
            trace!("Creating new Ping.");
            PingReq { id: random_u64() }
        }

        /// An ID of the request / response.
        pub fn id(&self) -> u64 {
            self.id
        }
    }

    impl PingResp {
        /// An ID of the request / response.
        pub fn id(&self) -> u64 {
            self.id
        }
    }

    impl From<PingReq> for PingResp {
        fn from(p: PingReq) -> Self {
            PingResp { id: p.id }
        }
    }

    impl DhtPacketT for PingReq {
        fn kind(&self) -> PacketKind {
            PacketKind::PingReq
        }
    }

    impl DhtPacketT for PingResp {
        fn kind(&self) -> PacketKind {
            PacketKind::PingResp
        }
    }

    /// Trait for types of DHT packets that can be put in [`DhtPacket`]
    /// (./struct.DhtPacket.html).
    pub trait DhtPacketT: ToBytes + FromBytes + Eq + PartialEq + Debug {
        /// Provide packet type number.
        ///
        /// To use for serialization: `.kind() as u8`.
        fn kind(&self) -> PacketKind;

        // / Create a payload for [`DhtPacket`](./struct.DhtPacket.html) from
        // / `self`.
        // TODO: better name?
        // fn into_dht_packet_payload(
        //     &self,
        //     symmetric_key: &PrecomputedKey,
        //     nonce: &Nonce) -> Vec<u8>
        // {
        //     seal_precomputed(&self.to_bytes(), nonce, symmetric_key)
        // }
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
    tests_for_pings!(PingReq
                        packet_ping_req_to_bytes_test
                        packet_ping_req_from_bytes_test
                    PingResp
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

            let v4: bool = match saddr {
                SocketAddr::V4(_) => true,
                SocketAddr::V6(_) => false,
            };

            let ip_type = match (udp, v4) {
                (true, true)   => IpType::U4,
                (true, false)  => IpType::U6,
                (false, true)  => IpType::T4,
                (false, false) => IpType::T6,
            };

            PackedNode {
                ip_type: ip_type,
                saddr: saddr,
                pk: *pk,
            }
        }

        /// Get an IP type from the `PackedNode`.
        pub fn ip_type(&self) -> IpType {
            trace!(target: "PackedNode", "Getting IP type from PackedNode.");
            trace!("With address: {:?}", self);
            self.ip_type
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

        /// Get an IP address from the `PackedNode`.
        pub fn pk(&self) -> &PublicKey {
            trace!(target: "PackedNode", "Getting PK from PackedNode.");
            trace!("With address: {:?}", self);
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
    
    macro_rules! impls_tests_for_nat_pings {
        ($($np:ident($p:ident) $b_t:ident $f_t:ident)+) => ($(
            impl Arbitrary for $np {
                fn arbitrary<G: Gen>(g: &mut G) -> Self {
                    $np(Arbitrary::arbitrary(g))
                }
            }

            #[test]
            fn $b_t() {
                fn with_np(p: $np) {
                    let mut _buf = [0; 1024];
                    let pb = p.to_bytes((&mut _buf, 0)).ok().unwrap();
                    let $np(x) = p;
                    assert_eq!(NAT_PING_SIZE, pb.1);
                    assert_eq!(NAT_PING_TYPE as u8, pb.0[0]);
                    assert_eq!(x.kind() as u8, pb.0[1]);
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
                        let $np(p) = $np::from_bytes(&bytes).unwrap().1;
                        // `id` should not differ
                        assert_eq!(p.id(), BigEndian::read_u64(&bytes[2..NAT_PING_SIZE]));
                    }
                }
                quickcheck(with_bytes as fn(Vec<u8>));

                // just in case
                let mut ping = vec![NAT_PING_TYPE, PacketKind::$p as u8 as u8];
                ping.write_u64::<BigEndian>(random_u64())
                    .unwrap();
                with_bytes(ping);
            }
        )+)
    }

    impls_tests_for_nat_pings!(
        NatPingReq(PingReq)
            packet_nat_ping_req_to_bytes_test
            packet_nat_ping_req_from_bytes_test
        NatPingResp(PingResp)
            packet_nat_ping_resp_to_bytes_test
            packet_nat_ping_resp_from_bytes_test
    );
}