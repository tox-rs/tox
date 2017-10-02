/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2016-2017 Zetok Zalbavar <zexavexxe@gmail.com>

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


use byteorder::{
    BigEndian,
    LittleEndian,
    NativeEndian,
    WriteBytesExt
};
use nom::{be_u16, le_u8, le_u16, rest};

use std::cmp::{Ord, Ordering};
use std::convert::From;
use std::fmt::Debug;
use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    SocketAddr,
    SocketAddrV4,
    SocketAddrV6
};
use std::ops::Deref;

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::packet_kind::PacketKind;



/// Length in bytes of [`PingReq`](./struct.PingReq.html) and
/// [`PingResp`](./struct.PingResp.html) when serialized into bytes.
pub const PING_SIZE: usize = 9;


macro_rules! impls_for_pings {
    ($($n:ident),+) => ($(
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
        `1`         | `u8` packet type
        `8`         | Ping ID

        Serialized form should be put in the encrypted part of DHT packet.

        # Creating new

        [`PingResp`](./struct.PingResp.html) can only be created as a response
        to [`PingReq`](./struct.PingReq.html).
        */
        #[derive(Copy, Clone, Debug, Eq, PartialEq)]
        pub struct $n {
            id: u64,
        }

        impl $n {
            /// An ID of the request / response.
            pub fn id(&self) -> u64 {
                self.id
            }
        }

        impl DhtPacketT for $n {
            fn kind(&self) -> PacketKind {
                PacketKind::$n
            }
        }

        /** De-seralize from bytes. Tries to parse first
        [`PING_SIZE`](./constant.PING_SIZE.html) bytes from supplied slice
        as `Ping`.
        */
        from_bytes!($n, do_parse!(
            packet_t: call!(PacketKind::parse_bytes) >>
            id: cond_reduce!(
                packet_t == PacketKind::$n,
                ne_u64
            ) >>
            ($n {
                id: id
            })
        ));

        /// Serialize to bytes.
        impl ToBytes for $n {
            fn to_bytes(&self) -> Vec<u8> {
                let pname = stringify!($n);
                debug!(target: pname, "Serializing {} into bytes.", pname);
                trace!(target: pname, "With {}: {:?}", pname, self);
                let mut res = Vec::with_capacity(PING_SIZE);
                // `PingType`
                res.push(self.kind() as u8);
                // And random ping_id as bytes
                res.write_u64::<NativeEndian>(self.id)
                    .expect("Failed to write Ping id!");
                trace!("Serialized Ping: {:?}", &res);
                res
            }
        }
    )+)
    // TODO: add To/From impls for both(↔)?
}
impls_for_pings!(PingReq, PingResp);

impl PingReq {
    /// Create new ping request with a randomly generated `request id`.
    pub fn new() -> Self {
        trace!("Creating new Ping.");
        PingReq { id: random_u64() }
    }
}

impl From<PingReq> for PingResp {
    fn from(p: PingReq) -> Self {
        PingResp { id: p.id }
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
/// return `None`.
from_bytes!(IpType, switch!(le_u8,
    2   => value!(IpType::U4) |
    10  => value!(IpType::U6) |
    130 => value!(IpType::T4) |
    138 => value!(IpType::T6)
));


// TODO: move it somewhere else
impl ToBytes for IpAddr {
    fn to_bytes(&self) -> Vec<u8> {
        debug!(target: "IpAddr", "Serializing IpAddr to bytes.");
        trace!(target: "IpAddr", "With IpAddr: {:?}", self);
        match self {
            &IpAddr::V4(a) => a.octets().iter().cloned().collect(),
            &IpAddr::V6(a) => {
                let mut result: Vec<u8> = vec![];
                for n in &a.segments() {
                    result.write_u16::<LittleEndian>(*n) // TODO: check if LittleEndian is correct here
                        .expect("Failed to write Ipv6Addr segments!");
                }
                result
            }
        }
    }
}

// TODO: move it somewhere else
/// Fail if there are less than 4 bytes supplied, otherwise parses first
/// 4 bytes as an `Ipv4Addr`.
from_bytes!(Ipv4Addr, map!(take!(4), |bytes| Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])));

// TODO: move it somewhere else
/// Fail if there are less than 16 bytes supplied, otherwise parses first
/// 16 bytes as an `Ipv6Addr`.
from_bytes!(Ipv6Addr, map!(count!(le_u16, 8), |v| Ipv6Addr::new(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7])));


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
    pk: PublicKey,
}

/// Size in bytes of serialized [`PackedNode`](./struct.PackedNode.html) with
/// IPv4.
pub const PACKED_NODE_IPV4_SIZE: usize = PUBLICKEYBYTES + 7;
/// Size in bytes of serialized [`PackedNode`](./struct.PackedNode.html) with
/// IPv6.
pub const PACKED_NODE_IPV6_SIZE: usize = PUBLICKEYBYTES + 19;

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

/** Serialize `PackedNode` into bytes.

Can be either [`PACKED_NODE_IPV4_SIZE`]
(./constant.PACKED_NODE_IPV4_SIZE.html) or [`PACKED_NODE_IPV6_SIZE`]
(./constant.PACKED_NODE_IPV6_SIZE.html) bytes long, depending on whether
IPv4 or IPv6 is being used.
*/
impl ToBytes for PackedNode {
    fn to_bytes(&self) -> Vec<u8> {
        debug!(target: "PackedNode", "Serializing PackedNode into bytes.");
        trace!(target: "PackedNode", "With PackedNode: {:?}", self);
        let mut result: Vec<u8> = Vec::with_capacity(PACKED_NODE_IPV6_SIZE);

        result.push(self.ip_type as u8);

        let addr: Vec<u8> = self.ip().to_bytes();
        result.extend_from_slice(&addr);
        // port
        result.write_u16::<BigEndian>(self.saddr.port())
            .expect("Failed to write PackedNode port!");

        let PublicKey(ref pk) = self.pk;
        result.extend_from_slice(pk);

        trace!("Result: {:?}", &result);
        result
    }
}

// Parse bytes as an IPv4 PackedNode.
named_args!(as_ipv4_packed_node(iptype: IpType) <PackedNode>, do_parse!(
    addr: call!(Ipv4Addr::parse_bytes) >>
    port: be_u16 >>
    saddr: value!(SocketAddrV4::new(addr, port)) >>
    pk: call!(PublicKey::parse_bytes) >>
    (PackedNode {
        ip_type: iptype,
        saddr: SocketAddr::V4(saddr),
        pk: pk
    })
));

// Parse bytes as an IPv6 PackedNode.
named_args!(as_ipv6_packed_node(iptype: IpType) <PackedNode>, do_parse!(
    addr: call!(Ipv6Addr::parse_bytes) >>
    port: be_u16 >>
    saddr: value!(SocketAddrV6::new(addr, port, 0, 0)) >>
    pk: call!(PublicKey::parse_bytes) >>
    (PackedNode {
        ip_type: iptype,
        saddr: SocketAddr::V6(saddr),
        pk: pk
    })
));

/** Deserialize bytes into `PackedNode`. Returns `None` if deseralizing
failed.

Can fail if:

 - length is too short for given [`IpType`](./enum.IpType.html)
 - PK can't be parsed

Blindly trusts that provided `IpType` matches - i.e. if there are provided
51 bytes (which is length of `PackedNode` that contains IPv6), and `IpType`
says that it's actually IPv4, bytes will be parsed as if that was an IPv4
address.
*/
from_bytes!(PackedNode, switch!(call!(IpType::parse_bytes),
    IpType::U4 => call!(as_ipv4_packed_node, IpType::U4) |
    IpType::T4 => call!(as_ipv4_packed_node, IpType::T4) |
    IpType::U6 => call!(as_ipv6_packed_node, IpType::U6) |
    IpType::T6 => call!(as_ipv6_packed_node, IpType::T6)
));


/** Request to get address of given DHT PK, or nodes that are closest in DHT
to the given PK.

Packet type [`PacketKind::GetN`](../packet_kind/enum.PacketKind.html).

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

impl GetNodes {
    /// Create new `GetNodes` with given PK.
    pub fn new(their_public_key: &PublicKey) -> Self {
        trace!(target: "GetNodes", "Creating new GetNodes request.");
        GetNodes { pk: *their_public_key, id: random_u64() }
    }


    /**
    Create response to `self` request with nodes provided from the `Kbucket`.

    Fails (returns `None`) if `Kbucket` is empty.
    */
    pub fn response(&self, kbucket: &Kbucket) -> Option<SendNodes> {
        let nodes = kbucket.get_closest(&self.pk);
        SendNodes::with_nodes(self, nodes)
    }
}

impl DhtPacketT for GetNodes {
    fn kind(&self) -> PacketKind {
        PacketKind::GetN
    }
}

/// Serialization of `GetNodes`. Resulting length should be
/// [`GET_NODES_SIZE`](./constant.GET_NODES_SIZE.html).
impl ToBytes for GetNodes {
    fn to_bytes(&self) -> Vec<u8> {
        debug!(target: "GetNodes", "Serializing GetNodes as bytes.");
        trace!(target: "GetNodes", "With GetNodes: {:?}", self);
        let mut result = Vec::with_capacity(GET_NODES_SIZE);
        let PublicKey(pk_bytes) = self.pk;
        result.extend_from_slice(&pk_bytes);
        result.write_u64::<NativeEndian>(self.id)
            .expect("Failed to write GetNodes id!");
        trace!("Resulting bytes: {:?}", &result);
        result
    }
}

/** De-serialization of bytes into `GetNodes`. If less than
[`GET_NODES_SIZE`](./constant.GET_NODES_SIZE.html) bytes are provided,
de-serialization will fail, returning `None`.
*/
from_bytes!(GetNodes, do_parse!(
    pk: call!(PublicKey::parse_bytes) >>
    id: ne_u64 >>
    (GetNodes { pk: pk, id: id })
));


/** Response to [`GetNodes`](./struct.GetNodes.html) request, containing up to
`4` nodes closest to the requested node.

Packet type `0x04`.

Serialized form:

Length      | Contents
----------- | --------
`1`         | Number of packed nodes (maximum 4)
`[39, 204]` | Nodes in packed format
`8`         | Ping ID

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
    /// Ping id that was received in [`GetNodes`](./struct.GetNodes.html)
    /// request.
    pub id: u64,
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

impl DhtPacketT for SendNodes {
    fn kind(&self) -> PacketKind {
        PacketKind::SendN
    }
}

/// Method assumes that supplied `SendNodes` has correct number of nodes
/// included – `[1, 4]`.
impl ToBytes for SendNodes {
    fn to_bytes(&self) -> Vec<u8> {
        debug!(target: "SendNodes", "Serializing SendNodes into bytes.");
        trace!(target: "SendNodes", "With SendNodes: {:?}", self);
        // first byte is number of nodes
        let mut result: Vec<u8> = vec![self.nodes.len() as u8];
        for node in &*self.nodes {
            result.extend_from_slice(&node.to_bytes());
        }
        result.write_u64::<NativeEndian>(self.id)
            .expect("Failed to write SendNodes id!");
        trace!("Resulting bytes: {:?}", &result);
        result
    }
}

/** Method to parse received bytes as `SendNodes`.

    Returns `None` if bytes can't be parsed into `SendNodes`.
*/
from_bytes!(SendNodes, do_parse!(
    nodes_number: le_u8 >>
    nodes: cond_reduce!(
        nodes_number > 0 && nodes_number <= 4,
        count!(PackedNode::parse_bytes, nodes_number as usize)
    ) >>
    id: ne_u64 >>
    (SendNodes {
        nodes: nodes,
        id: id
    })
));

/// Trait for types of DHT packets that can be put in [`DhtPacket`]
/// (./struct.DhtPacket.html).
pub trait DhtPacketT: ToBytes + FromBytes + Eq + PartialEq + Debug {
    /// Provide packet type number.
    ///
    /// To use for serialization: `.kind() as u8`.
    fn kind(&self) -> PacketKind;

    /// Create a payload for [`DhtPacket`](./struct.DhtPacket.html) from
    /// `self`.
    // TODO: better name?
    fn into_dht_packet_payload(
        &self,
        symmetric_key: &PrecomputedKey,
        nonce: &Nonce) -> Vec<u8>
    {
        seal_precomputed(&self.to_bytes(), nonce, symmetric_key)
    }
}


/** Standard DHT packet that encapsulates in the encrypted payload
[`DhtPacketT`](./trait.DhtPacketT.html).

Length      | Contents
----------- | --------
`1`         | `uint8_t` [`PacketKind`](../packet_kind/enum.PacketKind.html)
`32`        | Sender DHT Public Key
`24`        | Random nonce
variable    | Encrypted payload

`PacketKind` values for `DhtPacket` can be only `<= 4`.

https://zetok.github.io/tox-spec/#dht-packet
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtPacket {
    packet_type: PacketKind,
    /// Public key of sender.
    pub sender_pk: PublicKey,
    nonce: Nonce,
    payload: Vec<u8>,
}

// TODO: max dht_packet size?
/// Minimal size of [`DhtPacket`](./struct.DhtPacket.html) in bytes.
pub const DHT_PACKET_MIN_SIZE: usize = 1 // packet type, plain
                                     + PUBLICKEYBYTES
                                     + NONCEBYTES
                                     + MACBYTES
                                     + PING_SIZE; // smallest payload

impl DhtPacket {
    /// Create new `DhtPacket` with `bytes`.
    pub fn new<P>(symmetric_key: &PrecomputedKey,
               own_public_key: &PublicKey,
               nonce: &Nonce,
               dp: &P) -> Self
        where P: DhtPacketT
    {
        debug!(target: "DhtPacket", "Creating new DhtPacket.");
        trace!(target: "DhtPacket", "With args: symmetric_key: <secret>,
        own_public_key: {:?}, nonce: {:?}, packet: {:?}",
        own_public_key, nonce, &dp);


        let payload = dp.into_dht_packet_payload(symmetric_key, nonce);

        DhtPacket {
            packet_type: dp.kind(),
            sender_pk: *own_public_key,
            nonce: *nonce,
            payload: payload,
        }
    }

    /** Get [`PacketKind`](../packet_kind/enum.PacketKind.html) that
    `DhtPacket`'s payload is supposed to contain.
    */
    // TODO: write test(?)
    pub fn kind(&self) -> PacketKind {
        self.packet_type
    }

    /**
    Decrypt payload and try to parse it as packet type.

    To get info about it's packet type use
    [`.kind()`](./struct.DhtPacket.html#method.kind) method.

    Returns `None` in case of faliure:

    - fails to decrypt
    - fails to parse as given packet type
    */
    /* TODO: perhaps switch to using precomputed symmetric key?
              - given that computing shared key is apparently the most
                costly operation when it comes to crypto, using precomputed
                key might (would significantly?) lower resource usage

                Alternatively, another method `get_payloadnm()` which would use
                symmetric key.
    */
    pub fn get_payload<P>(&self, own_secret_key: &SecretKey) -> Option<P>
        where P: DhtPacketT
    {
        debug!(target: "DhtPacket", "Getting packet data from DhtPacket.");
        trace!(target: "DhtPacket", "With DhtPacket: {:?}", self);
        let decrypted = match open(&self.payload, &self.nonce, &self.sender_pk,
                            own_secret_key) {
            Ok(d) => d,
            Err(_) => {
                debug!("Decrypting DhtPacket failed!");
                return None
            },
        };

        trace!("Decrypted bytes: {:?}", &decrypted);

        P::from_bytes(&decrypted)
    }

    /**
    Create DHT Packet with [`Ping`](./struct.Ping.html) response to `Ping`
    request that packet contained.

    Nonce for the response is automatically generated.
    */
    pub fn ping_resp(&self,
                     secret_key: &SecretKey,
                     symmetric_key: &PrecomputedKey,
                     own_public_key: &PublicKey) -> Option<Self> {

        debug!(target: "DhtPacket", "Creating Ping response from Ping request
                                     that DHT packet contained.");
        trace!(target: "DhtPacket", "With args: DhtPacket: {:?}, own_pk: {:?}",
               self, own_public_key);

        if self.kind() != PacketKind::PingReq {
            return None
        }

        let payload: PingReq = match self.get_payload(secret_key) {
            Some(dpt) => dpt,
            None => return None,
        };

        let resp = PingResp::from(payload);
        let nonce = gen_nonce();

        Some(DhtPacket::new(symmetric_key, own_public_key, &nonce, &resp))
    }
}

/// Serialize `DhtPacket` into bytes.
impl ToBytes for DhtPacket {
    fn to_bytes(&self) -> Vec<u8> {
        debug!(target: "DhtPacket", "Serializing DhtPacket into bytes.");
        trace!(target: "DhtPacket", "With DhtPacket: {:?}", self);
        let mut result = Vec::with_capacity(DHT_PACKET_MIN_SIZE);
        result.push(self.packet_type as u8);

        let PublicKey(pk) = self.sender_pk;
        result.extend_from_slice(&pk);

        let Nonce(nonce) = self.nonce;
        result.extend_from_slice(&nonce);

        result.extend_from_slice(&self.payload);
        trace!("Resulting bytes: {:?}", &result);
        result
    }
}

/// De-serialize bytes into `DhtPacket`.
from_bytes!(DhtPacket, do_parse!(
    packet_type: verify!(call!(PacketKind::parse_bytes), |packet_type| match packet_type {
        PacketKind::PingReq | PacketKind::PingResp |
        PacketKind::GetN | PacketKind::SendN => true,
        _ => false
    }) >>
    sender_pk: call!(PublicKey::parse_bytes) >>
    nonce: call!(Nonce::parse_bytes) >>
    payload: map!(rest, |bytes| bytes.to_vec() ) >>
    (DhtPacket {
        packet_type: packet_type,
        sender_pk: sender_pk,
        nonce: nonce,
        payload: payload
    })
));


/// Trait for functionality related to distance between `PublicKey`s.
pub trait Distance {
    /// Check whether distance between PK1 and own PK is smaller than distance
    /// between PK2 and own PK.
    fn distance(&self, &PublicKey, &PublicKey) -> Ordering;
}

impl Distance for PublicKey {
    fn distance(&self,
                &PublicKey(ref pk1): &PublicKey,
                &PublicKey(ref pk2): &PublicKey) -> Ordering {

        trace!(target: "Distance", "Comparing distance between PKs.");
        let &PublicKey(own) = self;
        for i in 0..PUBLICKEYBYTES {
            if pk1[i] != pk2[i] {
                return Ord::cmp(&(own[i] ^ pk1[i]), &(own[i] ^ pk2[i]))
            }
        }
        Ordering::Equal
    }
}


/** Calculate the [`k-bucket`](./struct.Kbucket.html) index of a PK compared
to "own" PK.

According to the [spec](https://zetok.github.io/tox-spec#bucket-index).

Fails (returns `None`) if supplied keys are the same.
*/
pub fn kbucket_index(&PublicKey(ref own_pk): &PublicKey,
                     &PublicKey(ref other_pk): &PublicKey) -> Option<u8> {

    debug!(target: "KBucketIndex", "Calculating KBucketIndex for PKs.");
    trace!(target: "KBucketIndex", "With PK1: {:?}; PK2: {:?}", own_pk, other_pk);

    for byte in 0..PUBLICKEYBYTES {
        for bit in 0..8 {
            let shift = 7 - bit;
            if (own_pk[byte] >> shift) & 0b1 != (other_pk[byte] >> shift) & 0b1 {
                return Some((byte * 8 + bit) as u8)
            }
        }
    }
    None  // PKs are equal
}

/**
Structure for holding nodes.

Number of nodes it can contain is set during creation. If not set (aka `None`
is supplied), number of nodes defaults to [`BUCKET_DEFAULT_SIZE`]
(./constant.BUCKET_DEFAULT_SIZE.html).

Nodes stored in `Bucket` are in [`PackedNode`](./struct.PackedNode.html)
format.

Used in [`Kbucket`](./struct.Kbucket.html) for storing nodes close to given
PK; and additionally used to store nodes closest to friends.

[Spec definition](https://zetok.github.io/tox-spec#updating-k-buckets).
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bucket {
    /// Amount of nodes it can hold.
    capacity: u8,
    /// Nodes that bucket has, sorted by distance to PK.
    nodes: Vec<PackedNode>
}

/// Default number of nodes that bucket can hold.
pub const BUCKET_DEFAULT_SIZE: usize = 8;

impl Bucket {
    /** Create a new `Bucket` to store nodes close to the `pk`.

    Can hold up to `num` nodes if number is supplied. If `None` is
    supplied, holds up to [`BUCKET_DEFAULT_SIZE`]
    (./constant.BUCKET_DEFAULT_SIZE.html) nodes. If `Some(0)` is
    supplied, it is treated as `None`.
    */
    pub fn new(num: Option<u8>) -> Self {
        trace!(target: "Bucket", "Creating a new Bucket.");
        match num {
            None => {
                trace!("Creating a new Bucket with default capacity.");
                Bucket {
                    capacity: BUCKET_DEFAULT_SIZE as u8,
                    nodes: Vec::with_capacity(BUCKET_DEFAULT_SIZE)
                }
            },
            Some(0) => {
                error!("Treating Some(0) as None");
                Bucket::new(None)
            },
            Some(n) => {
                trace!("Creating a new Bucket with capacity: {}", n);
                Bucket { capacity: n, nodes: Vec::with_capacity(n as usize) }
            }
        }
    }

    /**
    Try to get position of [`PackedNode`] in the bucket by PK. Used in
    tests to check whether a `PackedNode` was added or removed.

    This method uses linear search as the simplest one.

    Returns Some(index) if it was found.
    Returns None if there is no a `PackedNode` with the given PK.

    [`PackedNode`]: ./struct.PackedNode.html
    */
    #[cfg(test)]
    fn find(&mut self, pk: &PublicKey) -> Option<usize> {
        for n in 0..self.nodes.len() {
            if pk == &self.nodes[n].pk {
                return Some(n)
            }
        }
        None
    }

    /**
    Try to add [`PackedNode`] to the bucket.

    - If the [`PackedNode`] with given `PublicKey` is already in the `Bucket`,
      the [`PackedNode`] is updated (since its `SocketAddr` can differ).
    - If bucket is not full, node is appended.
    - If bucket is full, node's closeness is compared to nodes already
      in bucket, and if it's closer than some node, it prepends that
      node, and last node is removed from the list.
    - If the node being added is farther away than the nodes in the bucket,
      it isn't added and `false` is returned.

    Note that you must pass the same `base_pk` each call or the internal
    state will be undefined.

    Returns `true` if node was added, `false` otherwise.

    [`PackedNode`]: ./struct.PackedNode.html
    */
    pub fn try_add(&mut self, base_pk: &PublicKey, new_node: &PackedNode)
        -> bool
    {
        debug!(target: "Bucket", "Trying to add PackedNode.");
        trace!(target: "Bucket", "With bucket: {:?}; PK: {:?} and new node: {:?}",
            self, base_pk, new_node);

        match self.nodes.binary_search_by(|n| base_pk.distance(n.pk(), new_node.pk()) ) {
            Ok(index) => {
                debug!("Updated: the node was already in the bucket.");
                self.nodes.remove(index);
                self.nodes.insert(index, *new_node);
                true
            },
            Err(index) if index == self.nodes.len() => {
                // index is pointing past the end
                if self.is_full() {
                    debug!("Node is too distant to add to the bucket.");
                    false
                } else {
                    // distance to the PK was bigger than the other keys, but
                    // there's still free space in the bucket for a node
                    debug!("Node inserted at the end of the bucket.");
                    self.nodes.push(*new_node);
                    true
                }
            },
            Err(index) => {
                // index is pointing inside the list
                if self.is_full() {
                    debug!("No free space left in the bucket, the last node removed.");
                    self.nodes.pop();
                }
                debug!("Node inserted inside the bucket.");
                self.nodes.insert(index, *new_node);
                true
            },
        }
    }

    /** Remove [`PackedNode`](./struct.PackedNode.html) with given PK from the
    `Bucket`.

    Note that you must pass the same `base_pk` each call or the internal
    state will be undefined. Also `base_pk` must be equal to `base_pk` you added
    a node with. Normally you don't call this function on your own but Kbucket does.

    If there's no `PackedNode` with given PK, nothing is being done.
    */
    pub fn remove(&mut self, base_pk: &PublicKey, node_pk: &PublicKey) {
        trace!(target: "Bucket", "Removing PackedNode with PK: {:?}", node_pk);
        match self.nodes.binary_search_by(|n| base_pk.distance(n.pk(), node_pk) ) {
            Ok(index) => {
                self.nodes.remove(index);
            },
            Err(_) => {
                trace!("No PackedNode to remove with PK: {:?}", node_pk);
            }
        }
    }

    /// Get the capacity of the Bucket.
    pub fn capacity(&self) -> usize {
        self.capacity as usize
    }

    /** Check if `Bucket` is empty.

    Returns `true` if there are no nodes in the `Bucket`, `false`
    otherwise.
    */
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /** Check if `Bucket` is full.

    Returns `true` if there is no free space in the `Bucket`, `false`
    otherwise.
    */
    pub fn is_full(&self) -> bool {
        self.nodes.len() == self.capacity()
    }

    /// Returns an iterator over [`PackedNode`](./struct.PackedNode.html)s.
    pub fn iter(&self) -> BucketIter {
        BucketIter { iter: self.nodes.iter() }
    }
}

/// Iterator over `Bucket`.
pub struct BucketIter<'a> {
    iter: ::std::slice::Iter<'a, PackedNode>,
}

impl<'a> Iterator for BucketIter<'a> {
    type Item = &'a PackedNode;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}


/** K-buckets structure to hold up to
[`KBUCKET_MAX_ENTRIES`](./constant.KBUCKET_MAX_ENTRIES.html) *
[`BUCKET_DEFAULT_SIZE`](./constant.BUCKET_DEFAULT_SIZE.html) nodes close to
own PK.

Nodes in bucket are sorted by closeness to the PK; closest node is the first,
while furthest is last.

Further reading: [Tox spec](https://zetok.github.io/tox-spec#k-buckets).
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kbucket {
    /// `PublicKey` for which `Kbucket` holds close nodes.
    pk: PublicKey,

    /// List of [`Bucket`](./struct.Bucket.html)s.
    buckets: Vec<Box<Bucket>>,
}

/** Maximum number of [`Bucket`](./struct.Bucket.html)s that [`Kbucket`]
(./struct.Kbucket.html) can hold.

Realistically, not even half of that will be ever used, given how
[index calculation](./fn.kbucket_index.html) works.
*/
pub const KBUCKET_MAX_ENTRIES: u8 = ::std::u8::MAX;

/** Default number of [`Bucket`](./struct.Bucket.html)s that [`Kbucket`]
(./struct.Kbucket.html) holds.
*/
pub const KBUCKET_BUCKETS: u8 = 128;

impl Kbucket {
    /// Create a new `Kbucket`.
    ///
    /// `n` – number of [`Bucket`](./struct.Bucket.html)s held.
    pub fn new(n: u8, pk: &PublicKey) -> Self {
        trace!(target: "Kbucket", "Creating new Kbucket with k: {:?} and PK:
               {:?}", n, pk);
        Kbucket {
            pk: *pk,
            buckets: vec![Box::new(Bucket::new(None)); n as usize]
        }
    }

    /// Number of [`Bucket`](./struct.Bucket.html)s held.
    pub fn size(&self) -> u8 {
        self.buckets.len() as u8
    }

    /// Get the PK of the Kbucket. Used in tests only
    #[cfg(test)]
    pub fn pk(&self) -> PublicKey {
        self.pk
    }

    /**
    Try to get position of [`PackedNode`] in the kbucket by PK. Used in
    tests to check whether a `PackedNode` was added or removed.

    This method uses quadratic search as the simplest one.

    Returns `Some(bucket_index, node_index)` if it was found.
    Returns `None` if there is no a [`PackedNode`] with the given PK.

    [`PackedNode`]: ./struct.PackedNode.html
    */
    #[cfg(test)]
    fn find(&mut self, pk: &PublicKey) -> Option<(usize, usize)> {
        for bucket_index in 0..self.buckets.len() {
            match self.buckets[bucket_index].find(pk) {
                None => {},
                Some(node_index) => return Some((bucket_index, node_index))
            }
        }
        None
    }


    /** Return the possible internal index of [`Bucket`](./struct.Bucket.html)
        where the key could be inserted/removed.

    Returns `Some(index)` if [`kbucket index`](./fn.kbucket_index.html) is defined
    and it is lower than the number of buckets.

    Returns `None` otherwise.
    */
    fn bucket_index(&self, pubkey: &PublicKey) -> Option<usize> {
        match kbucket_index(&self.pk, pubkey) {
            Some(index) if index < self.size() => Some(index as usize),
            _ => None
        }
    }

    /** Add [`PackedNode`](./struct.PackedNode.html) to `Kbucket`.

    Node can be added only if:

    * its [`kbucket index`](./fn.kbucket_index.html) is lower than the
      number of buckets.
    * [`Bucket`](./struct.Bucket.html) to which it is added has free space
      or added node is closer to the PK than other node in the bucket.

    Returns `true` if node was added successfully, `false` otherwise.
    */
    pub fn try_add(&mut self, node: &PackedNode) -> bool {
        debug!(target: "Kbucket", "Trying to add PackedNode.");
        trace!(target: "Kbucket", "With PN: {:?}; and self: {:?}", node, self);

        match self.bucket_index(node.pk()) {
            Some(index) => self.buckets[index].try_add(&self.pk, node),
            None => {
                trace!("Failed to add node: {:?}", node);
                false
            }
        }
    }

    /// Remove [`PackedNode`](./struct.PackedNode.html) with given PK from the
    /// `Kbucket`.
    pub fn remove(&mut self, node_pk: &PublicKey) {
        trace!(target: "Kbucket", "Removing PK: {:?} from Kbucket: {:?}", node_pk,
                self);

        match self.bucket_index(node_pk) {
            Some(index) => self.buckets[index].remove(&self.pk, node_pk),
            None => trace!("Failed to remove PK: {:?}", node_pk)
        }
    }

    /** Get (up to) 4 closest nodes to given PK.

    Functionality for [`SendNodes`](./struct.SendNodes.html).

    Returns less than 4 nodes only if `Kbucket` contains less than 4
    nodes.
    */
    pub fn get_closest(&self, pk: &PublicKey) -> Vec<PackedNode> {
        debug!(target: "Kbucket", "Getting closest nodes.");
        trace!(target: "Kbucket", "With PK: {:?} and self: {:?}", pk, self);
        // create a new Bucket with associated pk, and add nodes that are close
        // to the PK
        let mut bucket = Bucket::new(Some(4));
        for buc in &*self.buckets {
            for node in &*buc.nodes {
                bucket.try_add(pk, node);
            }
        }
        trace!("Returning nodes: {:?}", &bucket.nodes);
        bucket.nodes
    }

    /** Check if `Kbucket` is empty.

    Returns `true` if all `buckets` are empty, `false`
    otherwise.
    */
    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(|bucket| bucket.is_empty())
    }

    /// Create iterator over [`PackedNode`](./struct.PackedNode.html)s in
    /// `Kbucket`.
    pub fn iter(&self) -> KbucketIter {
        KbucketIter {
            pos_b: 0,
            pos_pn: 0,
            buckets: self.buckets.as_slice(),
        }
    }
}

/// Iterator over `PackedNode`s in `Kbucket`.
pub struct KbucketIter<'a> {
    pos_b: usize,
    pos_pn: usize,
    buckets: &'a [Box<Bucket>],
}

impl<'a> Iterator for KbucketIter<'a> {
    type Item = &'a PackedNode;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos_b < self.buckets.len() {
            match self.buckets[self.pos_b].iter().nth(self.pos_pn) {
                Some(s) => {
                    self.pos_pn += 1;
                    Some(s)
                },
                None => {
                    self.pos_b += 1;
                    self.pos_pn = 0;
                    self.next()
                },
            }
        } else {
            None
        }
    }
}


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

macro_rules! impls_for_nat_pings {
    ($($np:ident($p:ident)),+) => ($(
        /** NAT Ping; used to see if a friend we are not connected to directly
        is online and ready to do the hole punching.

        Basically a wrapper + customization of DHT [`PingReq`]/[`PingResp`].

        Added:
        `0xfe` prepended in serialized form.

        Used by [`DhtRequest`](./struct.DhtRequest.html).

        Serialized form:

        Length | Contents
        -------|---------
        1      | type (`0xfe`)
        9      | [`PingReq`]/[`PingResp`]

        Spec: https://zetok.github.io/tox-spec/#nat-ping-packets

        [`PingReq`]: ./struct.PingReq.html
        [`PingResp`]: ./struct.PingResp.html
        */
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $np(pub $p);

        impl $np {
            /// Return ID of the ping.
            pub fn id(&self) -> u64 {
                $p::id(self)
            }
        }

        impl DhtRequestT for $np {}

        from_bytes!($np, do_parse!(
            tag!(&[NAT_PING_TYPE][..]) >>
            p: call!($p::parse_bytes) >>
            ($np(p))
        ));

        /// Serializes into bytes.
        impl ToBytes for $np {
            fn to_bytes(&self) -> Vec<u8> {
                debug!(target: "NatPing", "Serializing NatPing into bytes.");
                let mut result = Vec::with_capacity(NAT_PING_SIZE);

                // special, "magic" type of NatPing, according to spec:
                // https://zetok.github.io/tox-spec/#nat-ping-request
                result.push(NAT_PING_TYPE);
                // and the rest of stuff inherited from `Ping`
                result.extend_from_slice($p::to_bytes(self).as_slice());
                trace!("Serialized {}: {:?}", stringify!($np), &result);
                result
            }
        }

        impl Deref for $np {
            type Target = $p;

            fn deref(&self) -> &$p {
                let $np(ref ping) = *self;
                ping
            }
        }
    )+)
}
impls_for_nat_pings!(NatPingReq(PingReq), NatPingResp(PingResp));

impl From<NatPingReq> for NatPingResp {
    fn from(p: NatPingReq) -> Self {
        NatPingResp(PingResp::from(p.0))
    }
}

impl NatPingReq {
    /// Create new `NatPingReq` request with a randomly generated `request id`.
    pub fn new() -> Self {
        trace!(target: "NatPingReq", "Creating new Ping.");
        NatPingReq(PingReq::new())
    }
}


/** Trait for types of DHT requests that can be put in [`DhtRequest`]
(./struct.DhtRequest.html).

*Currently only NatPings, in the future also onion-related stuff.* See
[Implementors](./trait.DhtRequestT.html#implementors).
*/
pub trait DhtRequestT: FromBytes + ToBytes + Eq + PartialEq + Debug {
    /// Create DHT request payload to use by `DhtRequest`.
    fn to_dht_request_payload(&self,
                             sender_secret_key: &SecretKey,
                             receiver_public_key: &PublicKey,
                             nonce: &Nonce)
        -> Vec<u8>
    {
        seal(&self.to_bytes(), nonce, receiver_public_key, sender_secret_key)
    }
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
1  | `32`
32 | receiver's DHT public key
32 | sender's DHT public key
24 | Nonce
?  | encrypted data

https://zetok.github.io/tox-spec/#dht-request-packets
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtRequest {
    /// `PublicKey` of receiver.
    pub receiver: PublicKey,
    /// `PUblicKey` of sender.
    pub sender: PublicKey,
    nonce: Nonce,
    payload: Vec<u8>,
}

impl DhtRequest {
    /// Create a new `DhtRequest`.
    pub fn new<P>(secret_key: &SecretKey,
                own_public_key: &PublicKey,
                receiver_public_key: &PublicKey,
                nonce: &Nonce,
                drt: &P) -> Self
        where P: DhtRequestT
    {

        debug!(target: "DhtRequest", "Creating new DhtRequest.");
        trace!(target: "DhtRequest", "With args: summetric_key: <secret>,
            own_public_key: {:?}, receiver_public_key: {:?} nonce: {:?},
            packet: {:?}",
            own_public_key, receiver_public_key, nonce, drt);

        let payload = drt.to_dht_request_payload(secret_key,
                                                receiver_public_key,
                                                nonce);

        DhtRequest {
            receiver: *receiver_public_key,
            sender: *own_public_key,
            nonce: *nonce,
            payload: payload,
        }
    }

    /** Get request data. This function decrypts payload and tries to parse it
    as request type.

    Returns `None` in case of failure.
    */
    pub fn get_request<P>(&self, secret_key: &SecretKey) -> Option<P>
        where P: DhtRequestT
    {
        debug!(target: "DhtRequest", "Getting request data from DhtRequest.");
        trace!(target: "DhtRequest", "With DhtRequest: {:?}", self);
        let decrypted = match open(&self.payload, &self.nonce, &self.sender,
                                   secret_key) {

            Ok(d) => d,
            Err(_) => {
                debug!("Decrypting DhtRequest failed!");
                return None
            },
        };

        trace!("Decrypted bytes: {:?}", &decrypted);

        P::from_bytes(&decrypted)
    }
}


#[cfg(test)]
mod test {
    use quickcheck::quickcheck;

    use toxcore::dht::*;


    // DhtPacket::

    // DhtPacket::new()

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
            assert_eq!(dpt.kind(), dhtp.packet_type);
            assert_eq!(nonce, dhtp.nonce);
        }
        quickcheck(with_dht_packet as fn(PingReq));
        quickcheck(with_dht_packet as fn(PingResp));
        quickcheck(with_dht_packet as fn(GetNodes));
        quickcheck(with_dht_packet as fn(SendNodes));
    }


    // Bucket::

    // Bucket::position()

    #[test]
    fn bucket_position_test() {
        fn with_data<F>(test_fn: F)
            where F: Fn(&mut Bucket, // bucket
                &PublicKey,  // base_pk
                &PackedNode, // n1
                &PackedNode, // n2
                &PackedNode) // n3
        {
            let mut bucket = Bucket::new(None);

            let base_pk = PublicKey([3; PUBLICKEYBYTES]);

            let addr = Ipv4Addr::new(0, 0, 0, 0);
            let saddr = SocketAddrV4::new(addr, 0);

            let pk1 = PublicKey([1; PUBLICKEYBYTES]);
            let n1 = PackedNode::new(false, SocketAddr::V4(saddr), &pk1);

            let pk2 = PublicKey([2; PUBLICKEYBYTES]);
            let n2 = PackedNode::new(false, SocketAddr::V4(saddr), &pk2);

            let pk3 = PublicKey([4; PUBLICKEYBYTES]);
            let n3 = PackedNode::new(false, SocketAddr::V4(saddr), &pk3);

            assert!(base_pk > pk1);
            assert!(base_pk > pk2);
            assert!(base_pk < pk3);

            assert!(pk1 < pk2);
            assert!(pk2 < pk3);
            assert!(pk1 < pk3);

            test_fn(&mut bucket, &base_pk, &n1, &n2, &n3);
        }
        // Check that insertion order does not affect
        // the result order in the bucket if the number nodes =
        // bucket size and nodes' pk are unique
        with_data(|bucket, base_pk, n1, n2, n3| {
            // insert order: n1 n2 n3 maps to position
            // n1 => 1, n2 => 0, n3 => 2
            bucket.try_add(base_pk, n1);
            bucket.try_add(base_pk, n2);
            bucket.try_add(base_pk, n3);
            assert_eq!(Some(1), bucket.find(n1.pk()));
            assert_eq!(Some(0), bucket.find(n2.pk()));
            assert_eq!(Some(2), bucket.find(n3.pk()));
        });
        with_data(|bucket, base_pk, n1, n2, n3| {
            // insert order: n3 n2 n1 maps to position
            // n1 => 1, n2 => 0, n3 => 2
            bucket.try_add(base_pk, n3);
            bucket.try_add(base_pk, n2);
            bucket.try_add(base_pk, n1);
            assert_eq!(Some(1), bucket.find(n1.pk()));
            assert_eq!(Some(0), bucket.find(n2.pk()));
            assert_eq!(Some(2), bucket.find(n3.pk()));
        });
        with_data(|bucket, base_pk, n1, n2, n3| {
            // insert order: n1 n2 n1 n2 n3 n2 maps to position
            // n1 => 1, n2 => 0, n3 => 2
            bucket.try_add(base_pk, n1);
            bucket.try_add(base_pk, n2);
            bucket.try_add(base_pk, n1);
            bucket.try_add(base_pk, n2);
            bucket.try_add(base_pk, n3);
            bucket.try_add(base_pk, n2);
            assert_eq!(Some(1), bucket.find(n1.pk()));
            assert_eq!(Some(0), bucket.find(n2.pk()));
            assert_eq!(Some(2), bucket.find(n3.pk()));
        });
        // Check that removing order does not affect
        // the order of nodes inside
        with_data(|bucket, base_pk, n1, n2, n3| {
            // prepare bucket
            bucket.try_add(base_pk, n1); // => 1
            bucket.try_add(base_pk, n2); // => 0
            bucket.try_add(base_pk, n3); // => 2
            // test removing from the beginning (n2 => 0)
            bucket.remove(base_pk, n2.pk());
            assert_eq!(Some(0), bucket.find(n1.pk()));
            assert_eq!(None,    bucket.find(n2.pk()));
            assert_eq!(Some(1), bucket.find(n3.pk()));
        });
        with_data(|bucket, base_pk, n1, n2, n3| {
            // prepare bucket
            bucket.try_add(base_pk, n1); // => 1
            bucket.try_add(base_pk, n2); // => 0
            bucket.try_add(base_pk, n3); // => 2
            // test removing from the middle (n1 => 1)
            bucket.remove(base_pk, n1.pk());
            assert_eq!(None,    bucket.find(n1.pk()));
            assert_eq!(Some(0), bucket.find(n2.pk()));
            assert_eq!(Some(1), bucket.find(n3.pk()));
        });
        with_data(|bucket, base_pk, n1, n2, n3| {
            // prepare bucket
            bucket.try_add(base_pk, n1); // => 1
            bucket.try_add(base_pk, n2); // => 0
            bucket.try_add(base_pk, n3); // => 2
            // test removing from the end (n3 => 2)
            bucket.remove(base_pk, n3.pk());
            assert_eq!(Some(1), bucket.find(n1.pk()));
            assert_eq!(Some(0), bucket.find(n2.pk()));
            assert_eq!(None,    bucket.find(n3.pk()));
        });
    }

    // BucketIter::next()

    quickcheck! {
        fn bucket_iter_next_test(n: u8, pns: Vec<PackedNode>) -> () {
            // can contain all nodes
            let mut bucket = Bucket::new(Some(n));
            // empty always returns None
            assert!(bucket.iter().next().is_none());

            let (pk, _) = gen_keypair();

            for node in &pns {
                bucket.try_add(&pk, &node);
            }

            let mut expect = Vec::new();
            for node in &bucket.nodes {
                expect.push(*node);
            }

            let mut e_iter = expect.iter();
            let mut b_iter = bucket.iter();
            loop {
                let enext = e_iter.next();
                let bnext = b_iter.next();
                assert_eq!(enext, bnext);
                if enext.is_none() {
                    break;
                }
            }
        }
    }


    // Kbucket::

    // Kbucket::position()

    #[test]
    fn kbucket_position_test() {
        fn with_data<F>(test_fn: F)
            where F: Fn(&mut Kbucket, // kbucket
                &PackedNode, // n1
                &PackedNode, // n2
                &PackedNode) // n3
        {
            let mut pk_bytes = [3; PUBLICKEYBYTES];

            pk_bytes[0] = 1;
            let base_pk = PublicKey(pk_bytes);

            let mut kbucket = Kbucket::new(KBUCKET_MAX_ENTRIES, &base_pk);

            let addr = Ipv4Addr::new(0, 0, 0, 0);
            let saddr = SocketAddrV4::new(addr, 0);

            let n0_base_pk = PackedNode::new(false, SocketAddr::V4(saddr), &base_pk);
            assert!(!kbucket.try_add(&n0_base_pk));
            kbucket.remove(&base_pk);

            pk_bytes[5] = 1;
            let pk1 = PublicKey(pk_bytes);
            let n1 = PackedNode::new(false, SocketAddr::V4(saddr), &pk1);

            pk_bytes[10] = 2;
            let pk2 = PublicKey(pk_bytes);
            let n2 = PackedNode::new(false, SocketAddr::V4(saddr), &pk2);

            pk_bytes[14] = 4;
            let pk3 = PublicKey(pk_bytes);
            let n3 = PackedNode::new(false, SocketAddr::V4(saddr), &pk3);

            assert!(pk1 > pk2);
            assert!(pk2 < pk3);
            assert!(pk1 > pk3);

            assert_eq!(Some(46), kbucket_index(&base_pk, &pk1));
            assert_eq!(Some(46), kbucket_index(&base_pk, &pk2));
            assert_eq!(Some(46), kbucket_index(&base_pk, &pk3));

            test_fn(&mut kbucket, &n1, &n2, &n3);
        }
        // Check that insertion order does not affect
        // the result order in the kbucket
        with_data(|kbucket, n1, n2, n3| {
            // insert order: n1 n2 n3 maps to position
            // n1 => 0, n2 => 1, n3 => 2
            kbucket.try_add(n1);
            kbucket.try_add(n2);
            kbucket.try_add(n3);
            assert_eq!(Some((46, 0)), kbucket.find(n1.pk()));
            assert_eq!(Some((46, 1)), kbucket.find(n2.pk()));
            assert_eq!(Some((46, 2)), kbucket.find(n3.pk()));
        });
        with_data(|kbucket, n1, n2, n3| {
            // insert order: n3 n2 n1 maps to position
            // n1 => 0, n2 => 1, n3 => 2
            kbucket.try_add(n3);
            kbucket.try_add(n2);
            kbucket.try_add(n1);
            assert_eq!(Some((46, 0)), kbucket.find(n1.pk()));
            assert_eq!(Some((46, 1)), kbucket.find(n2.pk()));
            assert_eq!(Some((46, 2)), kbucket.find(n3.pk()));
        });
        // Check that removing order does not affect
        // the order of nodes inside
        with_data(|kbucket, n1, n2, n3| {
            // prepare kbucket
            kbucket.try_add(n1); // => 0
            kbucket.try_add(n2); // => 1
            kbucket.try_add(n3); // => 2
            // test removing from the beginning (n1 => 0)
            kbucket.remove(n1.pk());
            assert_eq!(None,          kbucket.find(n1.pk()));
            assert_eq!(Some((46, 0)), kbucket.find(n2.pk()));
            assert_eq!(Some((46, 1)), kbucket.find(n3.pk()));
        });
        with_data(|kbucket, n1, n2, n3| {
            // prepare kbucket
            kbucket.try_add(n1); // => 0
            kbucket.try_add(n2); // => 1
            kbucket.try_add(n3); // => 2
            // test removing from the middle (n2 => 1)
            kbucket.remove(n2.pk());
            assert_eq!(Some((46, 0)), kbucket.find(n1.pk()));
            assert_eq!(None,          kbucket.find(n2.pk()));
            assert_eq!(Some((46, 1)), kbucket.find(n3.pk()));
        });
        with_data(|kbucket, n1, n2, n3| {
            // prepare kbucket
            kbucket.try_add(n1); // => 0
            kbucket.try_add(n2); // => 1
            kbucket.try_add(n3); // => 2
            // test removing from the end (n3 => 2)
            kbucket.remove(n3.pk());
            assert_eq!(Some((46, 0)), kbucket.find(n1.pk()));
            assert_eq!(Some((46, 1)), kbucket.find(n2.pk()));
            assert_eq!(None,          kbucket.find(n3.pk()));
        });
    }

    // KbucketIter::next()

    quickcheck! {
        fn kbucket_iter_next_test(n: u8, pns: Vec<PackedNode>) -> () {
            let (pk, _) = gen_keypair();
            let mut kbucket = Kbucket::new(n, &pk);
            // empty always returns None
            assert!(kbucket.iter().next().is_none());

            for node in &pns {
                kbucket.try_add(&node);
            }

            let mut expect = Vec::new();
            for bucket in &kbucket.buckets {
                for node in bucket.iter() {
                    expect.push(*node);
                }
            }

            let mut e_iter = expect.iter();
            let mut k_iter = kbucket.iter();
            loop {
                let enext = e_iter.next();
                let knext = k_iter.next();
                assert_eq!(enext, knext);
                if enext.is_none() {
                    break;
                }
            }
        }
    }
}
