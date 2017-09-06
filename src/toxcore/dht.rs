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


// ↓ FIXME expand doc
/*! DHT part of the toxcore.

    * takes care of the serializing and de-serializing DHT packets
    * ..
*/

use std::cmp::{Ord, Ordering};
use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    SocketAddr,
    SocketAddrV4,
    SocketAddrV6
};
use std::ops::Deref;
use byteorder::{ByteOrder, BigEndian, LittleEndian, NativeEndian, WriteBytesExt};

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::packet_kind::PacketKind;


/** Type of [`Ping`](./struct.Ping.html) packet. Either a request or response.

    * `0` – if ping is a request;
    * `1` – if ping is a response.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PingType {
    /// Request ping response. Wrapper over [`PacketKind::PingReq`]
    /// (../packet_kind/enum.PacketKind.html).
    Req  = PacketKind::PingReq as isize,
    /// Respond to ping request. Wrapper over [`PacketKind::PingResp`]
    /// (../packet_kind/enum.PacketKind.html).
    Resp = PacketKind::PingResp as isize,
}

/** Uses the first byte from the provided slice to de-serialize
[`PingType`](./enum.PingType.html). Returns `None` if first byte of slice
doesn't match `PingType` or slice has no elements.
*/
impl FromBytes for PingType {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        debug!(target: "PingType", "Creating PingType from bytes.");
        trace!(target: "PingType", "Bytes: {:?}", bytes);
        match try!(PacketKind::parse_bytes(bytes)) {
            Parsed(PacketKind::PingReq, rest)  => Ok(Parsed(PingType::Req, rest)),
            Parsed(PacketKind::PingResp, rest) => Ok(Parsed(PingType::Resp, rest)),
            Parsed(value, _) => parse_error!("Unexpected PacketKind '{:?}'", value)
        }
    }
}


/** Used to request/respond to ping. Use in an encrypted form.

Used in:

- [`DhtPacket`](./struct.DhtPacket.html)
- [`DhtRequest`](./struct.DhtRequest.html)

Serialized form:

Ping Packet (Request and response)

Packet type `0x00` for request, `0x01` for response.

Response ID must match ID of the request, otherwise ping is invalid.

Length      | Contents
----------- | --------
`1`         | `u8` packet type
`8`         | Ping ID

Serialized form should be put in the encrypted part of DHT packet.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ping {
    p_type: PingType,
    id: u64,
}

/// Length in bytes of [`Ping`](./struct.Ping.html) when serialized into bytes.
pub const PING_SIZE: usize = 9;

impl Ping {
    /// Create new ping request with a randomly generated `request id`.
    pub fn new() -> Self {
        trace!("Creating new Ping.");
        Ping { p_type: PingType::Req, id: random_u64(), }
    }

    /// An ID of the request / response.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Check whether given `Ping` is a request.
    pub fn is_request(&self) -> bool {
        trace!(target: "Ping",
               "Checking whether Ping is a request with Ping: {:?}", self);
        self.p_type == PingType::Req
    }

    /// Create answer to ping request. Returns `None` if supplied `Ping` is
    /// already a ping response.
    // TODO: make sure that checking whether `Ping` is not a response is needed
    //       here
    pub fn response(&self) -> Option<Self> {
        debug!(target: "Ping", "Creating a response to ping request.");
        trace!(target: "Ping", "With Ping: {:?}", self);
        if self.p_type == PingType::Resp {
            debug!("Ping is not a request, can't create response!");
            return None;
        }

        Some(Ping { p_type: PingType::Resp, id: self.id })
    }

    /// Encapsulate in `DhtPacketT` to use in [`DhtPacket`]
    /// (./struct.DhtPacket.html).
    // TODO: rename, since it's confusing with DhtPacket
    pub fn as_packet(&self) -> DhtPacketT {
        DhtPacketT::Ping(*self)
    }
}

/// Serializes [`Ping`](./struct.Ping.html) into bytes.
impl ToBytes for Ping {
    fn to_bytes(&self) -> Vec<u8> {
        debug!(target: "Ping", "Serializing Ping into bytes.");
        trace!(target: "Ping", "With Ping: {:?}", self);
        let mut res = Vec::with_capacity(PING_SIZE);
        // `PingType`
        res.push(self.p_type as u8);
        // And random ping_id as bytes
        res.write_u64::<NativeEndian>(self.id)
            .expect("Failed to write Ping id!");
        trace!("Serialized Ping: {:?}", &res);
        res
    }
}

/** De-seralize [`Ping`](./struct.Ping.html) from bytes. Tries to parse first
[`PING_SIZE`](./constant.PING_SIZE.html) bytes from supplied slice as
`Ping`.
*/
impl FromBytes for Ping {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        debug!(target: "Ping", "De-serializing Ping from bytes.");
        trace!(target: "Ping", "With bytes: {:?}", bytes);

        if bytes.len() < PING_SIZE {
            return parse_error!("There are less bytes than PING_SIZE!")
        }

        let Parsed(ping_type, bytes) = try!(PingType::parse_bytes(bytes));

        Ok(Parsed(Ping {
            p_type: ping_type,
            id: NativeEndian::read_u64(bytes),
        }, &bytes[8..]))
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
impl FromBytes for IpType {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        debug!(target: "IpType", "De-serializing IpType from bytes.");
        trace!(target: "IpType", "With bytes: {:?}", bytes);

        if bytes.is_empty() {
            return parse_error!("There are 0 bytes!")
        }

        let res = match bytes[0] {
            2   => IpType::U4,
            10  => IpType::U6,
            130 => IpType::T4,
            138 => IpType::T6,
            _   => {
                return parse_error!("Can't de-serialize bytes into IpType!")
            },
        };

        Ok(Parsed(res, &bytes[1..]))
    }
}


// TODO: move it somewhere else
impl ToBytes for IpAddr {
    fn to_bytes(&self) -> Vec<u8> {
        debug!(target: "IpAddr", "Serializing IpAddr to bytes.");
        trace!(target: "IpAddr", "With IpAddr: {:?}", self);
        match *self {
            IpAddr::V4(a) => a.octets().iter().cloned().collect(),
            IpAddr::V6(a) => {
                let mut result: Vec<u8> = vec![];
                for n in &a.segments() {
                    result.write_u16::<LittleEndian>(*n) // TODO: check if LittleEndian is correct here
                        .expect("Failed to write Ipv6Addr segments!");
                }
                result
            },
        }
    }
}

// TODO: move it somewhere else
/// Fail if there are less than 4 bytes supplied, otherwise parses first
/// 4 bytes as an `Ipv4Addr`.
impl FromBytes for Ipv4Addr {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        debug!(target: "Ipv4Addr", "De-serializing Ipv4Addr from bytes.");
        trace!(target: "Ipv4Addr", "With bytes: {:?}", bytes);

        if bytes.len() < 4 {
            return parse_error!("Not enough bytes for Ipv4Addr!")
        }

        Ok(Parsed(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
                                &bytes[4..]))
    }
}


// TODO: move it somewhere else
/// Fail if there are less than 16 bytes supplied, otherwise parses first
/// 16 bytes as an `Ipv6Addr`.
impl FromBytes for Ipv6Addr {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        debug!(target: "Ipv6Addr", "De-serializing Ipv6Addr from bytes.");
        trace!(target: "Ipv6Addr", "With bytes: {:?}", bytes);

        if bytes.len() < 16 {
            return parse_error!("Not enough bytes for Ipv6Addr!")
        }

        let mut v = Vec::with_capacity(8);
        for slice in bytes[..16].chunks(2) {
            v.push(LittleEndian::read_u16(slice));
        }
        Ok(Parsed(Ipv6Addr::new(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]), &bytes[16..]))
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
    pub ip_type: IpType,
    /// Socket addr of node.
    pub saddr: SocketAddr,
    /// Public Key of the node.
    pub pk: PublicKey,
}

/// Size in bytes of serialized [`PackedNode`](./struct.PackedNode.html) with
/// IPv4.
pub const PACKED_NODE_IPV4_SIZE: usize = PUBLICKEYBYTES + 7;
/// Size in bytes of serialized [`PackedNode`](./struct.PackedNode.html) with
/// IPv6.
pub const PACKED_NODE_IPV6_SIZE: usize = PUBLICKEYBYTES + 19;

impl PackedNode {
    /** New `PackedNode`.

    `udp` – whether UDP or TCP should be used. UDP is used for DHT nodes,
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

    /// Get an IP address from the `PackedNode`.
    pub fn ip(&self) -> IpAddr {
        trace!(target: "PackedNode", "Getting IP address from PackedNode.");
        trace!("With address: {:?}", self);
        match self.saddr {
            SocketAddr::V4(addr) => IpAddr::V4(*addr.ip()),
            SocketAddr::V6(addr) => IpAddr::V6(*addr.ip()),
        }
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
impl FromBytes for PackedNode {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        // TODO: move somewhere else, since it's likely that it will be needed
        //       in more places?
        fn parse_port(bytes: &[u8]) -> ParseResult<u16> {
            if bytes.len() < 2 {
                return parse_error!("Not enough bytes for port.")
            }

            let port = BigEndian::read_u16(bytes);
            Ok(Parsed(port, &bytes[2..]))
        }

        // parse bytes as IPv4
        fn as_ipv4(iptype: IpType, bytes: &[u8]) -> ParseResult<PackedNode> {
            debug!("Parsing bytes as IPv4.");
            trace!("Bytes: {:?}", bytes);

            let Parsed(addr, bytes) = try!(Ipv4Addr::parse_bytes(bytes));
            let Parsed(port, bytes) = try!(parse_port(bytes));
            let saddr = SocketAddrV4::new(addr, port);

            let Parsed(pk, bytes) = try!(PublicKey::parse_bytes(bytes));

            let result = PackedNode {
                ip_type: iptype,
                saddr: SocketAddr::V4(saddr),
                pk: pk
            };

            Ok(Parsed(result, bytes))
        }

        // parse bytes as IPv6
        fn as_ipv6(iptype: IpType, bytes: &[u8]) -> ParseResult<PackedNode> {
            trace!("Parsing bytes as IPv6.");
            trace!("Bytes: {:?}", bytes);

            let Parsed(addr, bytes) = try!(Ipv6Addr::parse_bytes(&bytes));
            let Parsed(port, bytes) = try!(parse_port(bytes));
            let saddr = SocketAddrV6::new(addr, port, 0, 0);

            let Parsed(pk, bytes) = try!(PublicKey::parse_bytes(bytes));

            let result = PackedNode {
                ip_type: iptype,
                saddr: SocketAddr::V6(saddr),
                pk: pk
            };

            Ok(Parsed(result, bytes))
        }


        debug!(target: "PackedNode", "De-serializing bytes into PackedNode.");
        trace!(target: "PackedNode", "With bytes: {:?}", bytes);

        match try!(IpType::parse_bytes(bytes)) {
            Parsed(IpType::U4, rest) => as_ipv4(IpType::U4, rest),
            Parsed(IpType::T4, rest) => as_ipv4(IpType::T4, rest),
            Parsed(IpType::U6, rest) => as_ipv6(IpType::U6, rest),
            Parsed(IpType::T6, rest) => as_ipv6(IpType::T6, rest),
        }
    }
}


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

    /// Encapsulate in `DhtPacketT` to use in [`DhtPacket`]
    /// (./struct.DhtPacket.html).
    // TODO: rename, since it's confusing with DhtPacket
    pub fn as_packet(&self) -> DhtPacketT {
        DhtPacketT::GetNodes(*self)
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
impl FromBytes for GetNodes {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        debug!(target: "GetNodes", "De-serializing bytes into GetNodes.");
        trace!(target: "GetNodes", "With bytes: {:?}", bytes);

        fn parse_id(b: &[u8]) -> ParseResult<u64> {
            if b.len() < 8 {
                return parse_error!("Not enough bytes to parse GetNodes id.")
            }

            let id = NativeEndian::read_u64(b);
            Ok(Parsed(id, &b[8..]))
        }

        let Parsed(pk, bytes) = try!(PublicKey::parse_bytes(bytes));
        let Parsed(id, bytes) = try!(parse_id(bytes));

        Ok(Parsed(GetNodes { pk: pk, id: id }, bytes))
    }
}


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
    /** Create new `SendNodes`. Returns `None` if 0 or more than 4 nodes are
    supplied.

    Created as an answer to `GetNodes` request.
    */
    pub fn from_request(request: &GetNodes, nodes: Vec<PackedNode>) -> Option<Self> {
        debug!(target: "SendNodes", "Creating SendNodes from GetNodes.");
        trace!(target: "SendNodes", "With GetNodes: {:?}", request);
        trace!("With nodes: {:?}", &nodes);

        if nodes.is_empty() || nodes.len() > 4 {
            warn!(target: "SendNodes", "Wrong number of nodes supplied!");
            return None
        }

        Some(SendNodes { nodes: nodes, id: request.id })
    }

    /// Encapsulate in `DhtPacketT` to easily use in [`DhtPacket`]
    /// (./struct.DhtPacket.html).
    // TODO: rename, since it's confusing with DhtPacket
    pub fn into_packet(self) -> DhtPacketT {
        DhtPacketT::SendNodes(self)
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
impl FromBytes for SendNodes {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        debug!(target: "SendNodes", "De-serializing bytes into SendNodes.");
        trace!(target: "SendNodes", "With bytes: {:?}", bytes);

        let nodes_number = bytes[0] as usize;

        // first byte should say how many `PackedNode`s `SendNodes` has.
        // There has to be at least 1 node, and no more than 4.
        if nodes_number < 1 || nodes_number > 4 {
            return parse_error!(target: "SendNodes", "Wrong number of nodes: {}", bytes[0])
        }

        let Parsed(nodes, rest) = try!(PackedNode::parse_bytes_multiple_n(nodes_number, &bytes[1..]));

        Ok(Parsed(SendNodes { nodes: nodes, id: NativeEndian::read_u64(rest) }, &rest[8..]))
    }
}

/// Types of DHT packets that can be put in [`DhtPacket`]
/// (./struct.DhtPacket.html).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DhtPacketT {
    /// `Ping` packet type.
    Ping(Ping),
    /// `GetNodes` packet type. Used to request nodes.
    // TODO: rename to `GetN()` ? – consistency with PacketKind
    GetNodes(GetNodes),
    /// `SendNodes` response to `GetNodes` request.
    // TODO: rename to `SendN()` ? – consistency with PacketKind
    SendNodes(SendNodes),
}

impl DhtPacketT {
    /// Provide packet type number.
    ///
    /// To use for serialization: `.kind() as u8`.
    pub fn kind(&self) -> PacketKind {
        match *self {
            DhtPacketT::GetNodes(_) => PacketKind::GetN,
            DhtPacketT::SendNodes(_) => PacketKind::SendN,
            DhtPacketT::Ping(p) => {
                if p.is_request() {
                    PacketKind::PingReq
                } else {
                    PacketKind::PingResp
                }
            },
        }
    }

    /** Create [`Ping`](./struct.Ping.html) response if `DhtPacketT` is a
    `Ping` request.

    Returns `None` if `DhtPacketT` is not a ping request, and thus `Ping`
    response could not be created.
    */
    pub fn ping_resp(&self) -> Option<Self> {
        debug!(target: "Ping", "Creating Ping response from a Ping.");
        trace!(target: "Ping", "With Ping: {:?}", self);
        if let DhtPacketT::Ping(ping) = *self {
            if let Some(ping_resp) = ping.response() {
                return Some(DhtPacketT::Ping(ping_resp))
            }
        }
        debug!("Ping was already a response!");
        None
    }
}

impl ToBytes for DhtPacketT {
    fn to_bytes(&self) -> Vec<u8> {
        match *self {
            DhtPacketT::Ping(ref d)      => d.to_bytes(),
            DhtPacketT::GetNodes(ref d)  => d.to_bytes(),
            DhtPacketT::SendNodes(ref d) => d.to_bytes(),
        }
    }
}


/** Standard DHT packet that encapsulates in the encrypted payload
[`DhtPacketT`](./enum.DhtPacketT.html).

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

// TODO: max dht packet size?
/// Minimal size of [`DhtPacket`](./struct.DhtPacket.html) in bytes.
pub const DHT_PACKET_MIN_SIZE: usize = 1 // packet type, plain
                                     + PUBLICKEYBYTES
                                     + NONCEBYTES
                                     + MACBYTES
                                     + PING_SIZE; // smallest payload

impl DhtPacket {
    /// Create new `DhtPacket`.
    pub fn new(symmetric_key: &PrecomputedKey,
               own_public_key: &PublicKey,
               nonce: &Nonce,
               packet: DhtPacketT) -> Self {

        debug!(target: "DhtPacket", "Creating new DhtPacket.");
        trace!(target: "DhtPacket", "With args: symmetric_key: <secret>,
        own_public_key: {:?}, nonce: {:?}, packet: {:?}",
        own_public_key, nonce, &packet);

        let payload = seal_precomputed(&packet.to_bytes(), nonce, symmetric_key);

        DhtPacket {
            packet_type: packet.kind(),
            sender_pk: *own_public_key,
            nonce: *nonce,
            payload: payload,
        }
    }

    /** Add [`PackedNode`](./struct.PackedNode.html) to `Kbucket`.
    Get packet data. This function decrypts payload and tries to parse it
    as packet type.

    Returns `None` in case of faliure.
    */
    /* TODO: perhaps switch to using precomputed symmetric key?
              - given that computing shared key is apparently the most
                costly operation when it comes to crypto, using precomputed
                key might (would significantly?) lower resource usage

                Alternatively, another method `get_packetnm()` which would use
                symmetric key.
    */
    // TODO: rename to `get_payload` ?
    pub fn get_packet(&self, own_secret_key: &SecretKey) -> Option<DhtPacketT> {
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

        match self.packet_type {
            PacketKind::PingReq | PacketKind::PingResp => {
                if let Some(p) = Ping::from_bytes(&decrypted) {
                    return Some(DhtPacketT::Ping(p))
                }
            },
            PacketKind::GetN => {
                if let Some(n) = GetNodes::from_bytes(&decrypted) {
                    return Some(DhtPacketT::GetNodes(n))
                }
            },
            PacketKind::SendN => {
                if let Some(n) = SendNodes::from_bytes(&decrypted) {
                    return Some(DhtPacketT::SendNodes(n))
                }
            },
            _ => {},  // not a DHT packet
        }
        debug!("De-serializing decrypted bytes into a DHT packet failed!");
        None  // parsing failed
    }

    /** Add [`PackedNode`](./struct.PackedNode.html) to `Kbucket`.
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

        let payload = match self.get_packet(secret_key) {
            Some(dpt) => dpt,
            None => return None,
        };

        let resp = match payload.ping_resp() {
            Some(pr) => pr,
            None => return None,
        };

        let nonce = gen_nonce();

        Some(DhtPacket::new(symmetric_key, own_public_key, &nonce, resp))
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
impl FromBytes for DhtPacket {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        debug!(target: "DhtPacket", "De-serializing bytes into DhtPacket.");
        trace!(target: "DhtPacket", "With bytes: {:?}", bytes);

        if bytes.len() < DHT_PACKET_MIN_SIZE {
            return parse_error!("Failed; less bytes than DHT_PACKET_MIN_SIZE!")
        }

        let Parsed(packet_type, bytes) = try!(PacketKind::parse_bytes(bytes));

        match packet_type {
            PacketKind::PingReq | PacketKind::PingResp |
            PacketKind::GetN | PacketKind::SendN => {},
            p => {
                return parse_error!("Failed: not a DHT packet! Packet: {:?}", p)
            },
        }

        let Parsed(sender_pk, bytes) = try!(PublicKey::parse_bytes(bytes));

        let Parsed(nonce, bytes) = try!(Nonce::parse_bytes(bytes));

        Ok(Parsed(DhtPacket {
            packet_type: packet_type,
            sender_pk: sender_pk,
            nonce: nonce,
            payload: bytes.to_vec(),
        }, &bytes[..0]))
    }
}


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


/// DHT Node and its associated info.
// TODO: move it up ↑
// TODO: is it even needed?
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Node {
    /** Add [`PackedNode`](./struct.PackedNode.html) to `Kbucket`.
    Time when node will reach it's timeout - value consists of `seconds
    since UNIX epoch + timeout`. If value equals or is lower than current
    time since UNIX epoch, node is timed out.

    Timeout value should be updated every time a valid packet from given
    node is received.
    */
    pub timeout: u64,
    /// Ping ID of last sent [`Ping`](./struct.Ping.html) request.
    pub id: u64,
    /// [`PackedNode`](./struct.PackedNode.html) contained by [`Node`]
    /// (./struct.Node.html).
    pub node: PackedNode,
}

impl Node {
    /// Create a new `Node`. New node has `req`, `resp` and `id` values set to
    /// `0`.
    pub fn new(pn: &PackedNode, timeout: u64) -> Self {
        Node { timeout: timeout, id: 0, node: *pn }
    }

    /// Set the ID of last [`Ping`](./struct.Ping.html) request sent.
    pub fn id(&mut self, id: u64) {
        self.id = id;
    }

    /// Get the PK of the node.
    pub fn pk(&self) -> &PublicKey {
        &self.node.pk
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
    let mut index = 0;

    for byte in 0..PUBLICKEYBYTES {
        for bit in 0..8 {
            let shift = 7 - bit;
            if (own_pk[byte] >> shift) & 0b1 != (other_pk[byte] >> shift) & 0b1 {
                return Some(index)
            } else {
                index = match index.checked_add(1) {
                    Some(n) => n,
                    None => return None,
                };
            }
        }
    }
    None  // PKs are equal
}

/** Structure for holding nodes.

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
    pub nodes: Vec<PackedNode>
}

/// Default number of nodes that bucket can hold.
pub const BUCKET_DEFAULT_SIZE: usize = 8;

impl Bucket {
    /** Create a new `Bucket` to store nodes close to the `pk`.

    Can hold up to `num` nodes if number is supplied. If `None` is
    supplied, holds up to [`BUCKET_DEFAULT_SIZE`]
    (./constant.BUCKET_DEFAULT_SIZE.html) nodes.
    */
    pub fn new(num: Option<u8>) -> Self {
        trace!(target: "Bucket", "Creating a new Bucket.");
        if let Some(n) = num {
            trace!("Creating a new Bucket with capacity: {}", n);
            Bucket { capacity: n, nodes: Vec::with_capacity(n as usize) }
        } else {
            trace!("Creating a new Bucket with default capacity.");
            Bucket {
                capacity: BUCKET_DEFAULT_SIZE as u8,
                nodes: Vec::with_capacity(BUCKET_DEFAULT_SIZE)
            }
        }
    }

    /** Try to add [`PackedNode`](./struct.PackedNode.html) to the bucket.

    If bucket doesn't have [`BUCKET_DEFAULT_SIZE`]
    (./constant.BUCKET_DEFAULT_SIZE.html) nodes, node is appended.

    If bucket has `capacity` nodes already, node's closeness is compared to
    nodes already in bucket, and if it's closer than some node, it prepends
    that node, and last node is removed from the list.

    If the node being added is farther away than the nodes in the bucket,
    it isn't added and `false` is returned.

    Returns `true` if node was added, `false` otherwise.
    */
    pub fn try_add(&mut self, pk: &PublicKey, pn: &PackedNode) -> bool {
        debug!(target: "Bucket", "Trying to add PackedNode.");
        trace!(target: "Bucket", "With bucket: {:?}; PK: {:?} and pn: {:?}",
            self, pk, pn);

        if self.nodes.is_empty() {
            self.nodes.push(*pn);
            debug!("Bucket was empty, node added.");
            return true
        }

        for n in 0..self.nodes.len() {
            match pk.distance(&pn.pk, &self.nodes[n].pk) {
                Ordering::Less => {
                    if self.nodes.len() == self.capacity as usize {
                        drop(self.nodes.pop());
                    }

                    self.nodes.insert(n, *pn);
                    return true
                },
                Ordering::Equal => {
                    trace!("Updated: PN was already in the bucket.");
                    drop(self.nodes.remove(n));
                    self.nodes.insert(n, *pn);
                    return true
                },
                _ => {},
            }
        }
        // distance to the PK was bigger than the other keys, but there's still
        // "free" space in the bucket for a node, so append at the end
        if self.nodes.len() < self.capacity as usize {
            self.nodes.push(*pn);
            return true
        }

        debug!("Node is too distant to add to bucket.");
        false
    }

    /** Remove [`PackedNode`](./struct.PackedNode.html) with given PK from the
    `Bucket`.

    If there's no `PackedNode` with given PK, nothing is being done.
    */
    // TODO: write test
    pub fn remove(&mut self, pubkey: &PublicKey) {
        trace!(target: "Bucket", "Removing PackedNode with PK: {:?}", pubkey);
        for n in 0..self.nodes.len() {
            if pubkey == &self.nodes[n].pk {
                drop(self.nodes.remove(n));
                return
            }
        }
        trace!("Failed to remove PackedNode with PK: {:?}", pubkey);
    }

    /** Check if `Bucket` is empty.

    Returns `true` if there are no nodes in the `Bucket`, `false`
    otherwise.
    */
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
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
    pub pk: PublicKey,

    /// Number of [`Bucket`](./struct.Bucket.html)s held.
    // TODO: check if `n` even needs to be stored, considering that
    //       `buckets.len()` could(?) be used
    pub n: u8,
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
            n: n,
            buckets: vec![Box::new(Bucket::new(None)); n as usize]
        }
    }

    /** Add [`PackedNode`](./struct.PackedNode.html) to `Kbucket`.

    Node can be added only if:

    * its [`kbucket index`](./fn.kbucket_index.html) is lower or equal to
      `n` (number of buckets).
    * [`Bucket`](./struct.Bucket.html) to which it is added has free space
      or added node is closer to the PK than other node in the bucket.

    Returns `true` if node was added successfully, `false` otherwise.
    */
    pub fn try_add(&mut self, node: &PackedNode) -> bool {
        debug!(target: "Kbucket", "Trying to add PackedNode.");
        trace!(target: "Kbucket", "With PN: {:?}; and self: {:?}", node, self);

        if let Some(index) = kbucket_index(&self.pk, &node.pk) {
            if index >= self.n {
                debug!("Failed, index is bigger than what Kbucket can hold.");
                return false
            }
            return self.buckets[index as usize].try_add(&self.pk, node)
        }
        trace!("Failed to add node: {:?}", node);
        false
    }

    /// Remove [`PackedNode`](./struct.PackedNode.html) with given PK from the
    /// `Kbucket`.
    pub fn remove(&mut self, pk: &PublicKey) {
        trace!(target: "Kbucket", "Removing PK: {:?} from Kbucket: {:?}", pk,
                self);
        // TODO: optimize using `kbucket_index()` ?
        for i in 0..self.buckets.len() {
            self.buckets[i].remove(pk);
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
                drop(bucket.try_add(pk, node));
            }
        }
        trace!("Returning nodes: {:?}", &bucket.nodes);
        bucket.nodes
    }
}


/** NAT Ping; used to see if a friend we are not connected to directly is
online and ready to do the hole punching.

Basically a wrapper + customization of [`Ping`](./struct.Ping.html). Added:
`0xfe` prepended in serialized form.

Used by [`DhtRequest`](./struct.DhtRequest.html).

Can be either a:

 - request
 - response

Serialized form:

Length | Contents
-------|---------
1      | type (`0xfe`)
9      | [`Ping`](./struct.Ping.html)

Spec: https://zetok.github.io/tox-spec/#nat-ping-packets
*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NatPing(pub Ping);

/// [`NatPing](./struct.NatPing.html) type byte;
/// https://zetok.github.io/tox-spec/#nat-ping-request
pub const NAT_PING_TYPE: u8 = 0xfe;

/// Length in bytes of [`NatPing`](./struct.NatPing.html) when serialized into
/// bytes.
pub const NAT_PING_SIZE: usize = PING_SIZE + 1;

impl NatPing {
    /// Create new `NatPing` request with a randomly generated `request id`.
    pub fn new() -> Self {
        trace!(target: "NatPing", "Creating new Ping.");
        NatPing(Ping::new())
    }

    /// Return `NatPing` ID.
    pub fn id(&self) -> u64 {
        Ping::id(self)
    }

    /// Check whether given `NatPing` is a request.
    pub fn is_request(&self) -> bool {
        Ping::is_request(self)
    }

    /// Create answer to ping request. Returns `None` if supplied `Ping` is
    /// already a ping response.
    #[inline]
    pub fn response(&self) -> Option<Self> {
        Ping::response(self).and_then(|p: Ping| Some(NatPing(p)))
    }
}

/// Serializes [`NatPing`](./struct.NatPing.html) into bytes.
impl ToBytes for NatPing {
    fn to_bytes(&self) -> Vec<u8> {
        debug!(target: "NatPing", "Serializing NatPing into bytes.");
        let mut result = Vec::with_capacity(NAT_PING_SIZE);

        // special, "magic" type of NatPing, according to spec:
        // https://zetok.github.io/tox-spec/#nat-ping-request
        result.push(NAT_PING_TYPE);
        // and the rest of stuff inherited from `Ping`
        result.extend_from_slice(Ping::to_bytes(self).as_slice());
        trace!("Serialized NatPing: {:?}", &result);
        result
    }
}

impl FromBytes for NatPing {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        if bytes.len() < NAT_PING_SIZE {
            return parse_error!("Not enough bytes for NatPing.")
        }

        if bytes[0] != NAT_PING_TYPE {
            return parse_error!("Not a NatPing.")
        }

        let Parsed(p, rest) = try!(Ping::parse_bytes(&bytes[1..]));
        Ok(Parsed(NatPing(p), rest))
    }
}

impl Deref for NatPing {
    type Target = Ping;

    fn deref(&self) -> &Ping {
        let NatPing(ref ping) = *self;
        ping
    }
}


/** Types of DHT request that can be put in [`DhtRequest`]
(./struct.DhtRequest.html).

*Currently only [`NatPing`](./struct.NatPing.html), in the future also
onion-related stuff.*
*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DhtRequestT {
    /// `NatPing` request type.
    NatPing(NatPing),
}

impl ToBytes for DhtRequestT {
    fn to_bytes(&self) -> Vec<u8> {
        let DhtRequestT::NatPing(ping) = *self;
        ping.to_bytes()
    }
}

impl FromBytes for DhtRequestT {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        let Parsed(p, rest) = try!(NatPing::parse_bytes(bytes));
        Ok(Parsed(DhtRequestT::NatPing(p), rest))
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
    pub fn new(secret_key: &SecretKey,
               own_public_key: &PublicKey,
               receiver_public_key: &PublicKey,
               nonce: &Nonce,
               packet: DhtRequestT) -> Self {

        debug!(target: "DhtRequest", "Creating new DhtRequest.");
        trace!(target: "DhtRequest", "With args: summetric_key: <secret>,
            own_public_key: {:?}, receiver_public_key: {:?} nonce: {:?},
            packet: {:?}",
            own_public_key, receiver_public_key, nonce, &packet);

        let payload = seal(&packet.to_bytes(), nonce, receiver_public_key,
                           secret_key);

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
    pub fn get_request(&self, secret_key: &SecretKey) -> Option<DhtRequestT> {
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

        DhtRequestT::from_bytes(&decrypted)
    }
}
