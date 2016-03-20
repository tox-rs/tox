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
//! DHT part of the toxcore.
//!
//! * takes care of the serializing and de-serializing DHT packets
//! * ..

use ip::*; // ← won't be needed with Rust 1.7, since it finally got stabilized
use std::cmp::{Ord, Ordering};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use toxcore::binary_io::*;
use toxcore::crypto_core::*;


/// Top-level packet kind names and their associated numbers.
///
/// According to https://toktok.github.io/spec.html#packet-kind.
// TODO: move it somewhere else
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketKind {
    /// [`Ping`](./struct.Ping.html) request number.
    PingReq       = 0,
    /// [`Ping`](./struct.Ping.html) response number.
    PingResp      = 1,
    /// [`GetNodes`](./struct.GetNodes.html) packet number.
    GetN          = 2,
    /// [`SendNodes`](./struct.SendNodes.html) packet number.
    SendN         = 4,
    /// Cookie Request.
    CookieReq     = 24,
    /// Cookie Response.
    CookieResp    = 25,
    /// Crypto Handshake.
    CryptoHs      = 26,
    /// Crypto Data (general purpose packet for transporting encrypted data).
    CryptoData    = 27,
    /// DHT Request.
    DhtReq        = 32,
    /// LAN Discovery.
    LanDisc       = 33,
    /// Onion Reuqest 0.
    OnionReq0     = 128,
    /// Onion Request 1.
    OnionReq1     = 129,
    /// Onion Request 2.
    OnionReq2     = 130,
    /// Announce Request.
    AnnReq        = 131,
    /// Announce Response.
    AnnResp       = 132,
    /// Onion Data Request.
    OnionDataReq  = 133,
    /// Onion Data Response.
    OnionDataResp = 134,
    /// Onion Response 3.
    OnionResp3    = 140,
    /// Onion Response 2.
    OnionResp2    = 141,
    /// Onion Response 1.
    OnionResp1    = 142,
}

/// Parse first byte from provided `bytes` as `PacketKind`.
///
/// Returns `None` if no bytes provided, or first byte doesn't match.
impl FromBytes<PacketKind> for PacketKind {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        debug!(target: "PacketKind", "Creating PacketKind from bytes.");
        trace!(target: "PacketKind", "Bytes: {:?}", bytes);
        if bytes.is_empty() {
            debug!("There are 0 bytes!");
            return None
        }

        match bytes[0] {
            0   => Some(PacketKind::PingReq),
            1   => Some(PacketKind::PingResp),
            2   => Some(PacketKind::GetN),
            4   => Some(PacketKind::SendN),
            24  => Some(PacketKind::CookieReq),
            25  => Some(PacketKind::CookieResp),
            26  => Some(PacketKind::CryptoHs),
            27  => Some(PacketKind::CryptoData),
            32  => Some(PacketKind::DhtReq),
            33  => Some(PacketKind::LanDisc),
            128 => Some(PacketKind::OnionReq0),
            129 => Some(PacketKind::OnionReq1),
            130 => Some(PacketKind::OnionReq2),
            131 => Some(PacketKind::AnnReq),
            132 => Some(PacketKind::AnnResp),
            133 => Some(PacketKind::OnionDataReq),
            134 => Some(PacketKind::OnionDataResp),
            140 => Some(PacketKind::OnionResp3),
            141 => Some(PacketKind::OnionResp2),
            142 => Some(PacketKind::OnionResp1),
            _   => {
                debug!("Byte can't be parsed as PacketKind!");
                None
            },
        }
    }
}


/// Type of [`Ping`](./struct.Ping.html) packet. Either a request or response.
///
/// * `0` – if ping is a request;
/// * `1` – if ping is a response.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PingType {
    /// Request ping response. Wrapper over [`PacketKind::PingReq`]
    /// (./enum.PacketKind.html).
    Req  = PacketKind::PingReq as isize,
    /// Respond to ping request. Wrapper over [`PacketKind::PingResp`]
    /// (./enum.PacketKind.html).
    Resp = PacketKind::PingResp as isize,
}

/// Uses the first byte from the provided slice to de-serialize
/// [`PingType`](./enum.PingType.html). Returns `None` if first byte of slice
/// doesn't match `PingType` or slice has no elements.
impl FromBytes<PingType> for PingType {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        debug!(target: "PingType", "Creating PingType from bytes.");
        trace!(target: "PingType", "Bytes: {:?}", bytes);
        match PacketKind::from_bytes(bytes) {
            Some(PacketKind::PingReq)  => Some(PingType::Req),
            Some(PacketKind::PingResp) => Some(PingType::Resp),
            _ => {
                debug!("Creating PingType from bytes failed!");
                None
            },
        }
    }
}


/// Used to request/respond to ping. Use in an encrypted form in DHT packets.
///
/// Serialized form:
///
/// Ping Packet (Request and response)
///
/// Packet type `0x00` for request, `0x01` for response.
///
/// Length      | Contents
/// ----------- | --------
/// `1`         | `u8` packet type
/// `8`         | Ping ID
///
/// Serialized form should be put in the encrypted part of DHT packet.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ping {
    p_type: PingType,
    /// An ID of the request. Response ID must match ID of the request,
    /// otherwise ping is invalid.
    pub id: u64,
}

/// Length in bytes of [`Ping`](./struct.Ping.html) when serialized into bytes.
pub const PING_SIZE: usize = 9;

impl Ping {
    /// Create new ping request with a randomly generated `id`.
    pub fn new() -> Self {
        trace!("Creating new Ping.");
        Ping { p_type: PingType::Req, id: random_u64(), }
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

    /// Encapsulate in `DPacketT` to use in [`DhtPacket`]
    /// (./struct.DhtPacket.html).
    pub fn as_packet(&self) -> DPacketT {
        DPacketT::Ping(*self)
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
        res.extend_from_slice(&u64_to_array(self.id));
        trace!("Serialized Ping: {:?}", &res);
        res
    }
}

/// De-seralize [`Ping`](./struct.Ping.html) from bytes. Tries to parse first
/// [`PING_SIZE`](./constant.PING_SIZE.html) bytes from supplied slice as
/// `Ping`.
impl FromBytes<Ping> for Ping {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        debug!(target: "Ping", "De-serializing Ping from bytes.");
        trace!(target: "Ping", "With bytes: {:?}", bytes);

        if bytes.len() < PING_SIZE {
            debug!("There are less bytes than PING_SIZE!");
            return None;
        }

        if let Some(ping_type) = PingType::from_bytes(bytes) {
            return Some(Ping {
                p_type: ping_type,
                id: array_to_u64(&[bytes[1], bytes[2], bytes[3], bytes[4],
                                   bytes[5], bytes[6], bytes[7], bytes[8]]),
            })
        }
        debug!("De-serializing Ping failed!");
        None
    }
}


/// Used by [`PackedNode`](./struct.PackedNode.html).
///
/// * 1st bit – protocol
/// * 3 bits – `0`
/// * 4th bit – address family
///
/// Values:
///
/// * `2` – UDP IPv4
/// * `10` – UDP IPv6
/// * `130` – TCP IPv4
/// * `138` – TCP IPv6
///
/// DHT module *should* use only UDP variants of `IpType`, given that DHT runs
/// solely over the UDP.
///
/// TCP variants are to be used for sending/receiving info about TCP relays.
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
impl FromBytes<IpType> for IpType {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        debug!(target: "IpType", "De-serializing IpType from bytes.");
        trace!(target: "IpType", "With bytes: {:?}", bytes);

        if bytes.is_empty() {
            debug!("There are 0 bytes!");
            return None
        }

        match bytes[0] {
            2   => Some(IpType::U4),
            10  => Some(IpType::U6),
            130 => Some(IpType::T4),
            138 => Some(IpType::T6),
            _   => {
                debug!("Can't de-serialize bytes into IpType!");
                None
            },
        }
    }
}


// TODO: move it somewhere else
impl ToBytes for IpAddr {
    fn to_bytes(&self) -> Vec<u8> {
        debug!(target: "IpAddr", "Serializing IpAddr to bytes.");
        trace!(target: "IpAddr", "With IpAddr: {:?}", self);
        match *self {
            IpAddr::V4(a) => a.octets().iter().map(|b| *b).collect(),
            IpAddr::V6(a) => {
                let mut result: Vec<u8> = vec![];
                for n in a.segments().iter() {
                    result.extend_from_slice(&u16_to_array(*n));
                }
                result
            },
        }
    }
}


// TODO: move it somewhere else
/// Can fail if there are less than 16 bytes supplied, otherwise parses first
/// 16 bytes as an `Ipv6Addr`.
impl FromBytes<Ipv6Addr> for Ipv6Addr {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        debug!(target: "Ipv6Addr", "De-serializing Ipv6Addr from bytes.");
        trace!(target: "Ipv6Addr", "With bytes: {:?}", bytes);

        if bytes.len() < 16 {
            debug!("Not enough bytes for Ipv6Addr!");
            return None
        }

        let (a, b, c, d, e, f, g, h) = {
            let mut v: Vec<u16> = Vec::with_capacity(8);
            for slice in bytes[..16].chunks(2) {
                v.push(array_to_u16(&[slice[0], slice[1]]));
            }
            (v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7])
        };
        Some(Ipv6Addr::new(a, b, c, d, e, f, g, h))
    }
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
///                          (39 bytes for IPv4, 51 for IPv6)
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
/// DHT module *should* use only UDP variants of `IpType`, given that DHT runs
/// solely on the UDP.
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
    /// New `PackedNode`.
    ///
    /// `udp` – whether UDP or TCP should be used. UDP is used for DHT nodes,
    /// whereas TCP is used for TCP relays.
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

    /// Parse bytes into multiple `PackedNode`s.
    ///
    /// If provided bytes are smaller than [`PACKED_NODE_IPV4_SIZE`]
    /// (./constant.PACKED_NODE_IPV4_SIZE.html) or can't be parsed, returns
    /// `None`.
    ///
    /// Parses nodes until first error is encountered.
    pub fn from_bytes_multiple(bytes: &[u8]) -> Option<Vec<PackedNode>> {
        debug!(target: "PackedNode", "De-serializing multiple PackedNode.");
        trace!(target: "PackedNode", "With bytes: {:?}", bytes);

        if bytes.len() < PACKED_NODE_IPV4_SIZE {
            debug!("There are less bytes than PACKED_NODE_IPV4_SIZE!");
            return None
        }

        let mut cur_pos = 0;
        let mut result = Vec::new();

        // TODO: add `trace!()` logging?
        while let Some(node) = PackedNode::from_bytes(&bytes[cur_pos..]) {
            cur_pos += {
                match node.ip_type {
                    IpType::U4 | IpType::T4 => PACKED_NODE_IPV4_SIZE,
                    IpType::U6 | IpType::T6 => PACKED_NODE_IPV6_SIZE,
                }
            };
            result.push(node);
        }

        trace!("Result: {:?}", &result);
        if result.is_empty() {
            debug!("There is no successfully de-serialized PackedNodes!");
            return None
        } else {
            return Some(result)
        }
    }
}

/// Serialize `PackedNode` into bytes.
///
/// Can be either [`PACKED_NODE_IPV4_SIZE`]
/// (./constant.PACKED_NODE_IPV4_SIZE.html) or [`PACKED_NODE_IPV6_SIZE`]
/// (./constant.PACKED_NODE_IPV6_SIZE.html) bytes long, depending on whether
/// IPv4 or IPv6 is being used.
impl ToBytes for PackedNode {
    fn to_bytes(&self) -> Vec<u8> {
        debug!(target: "PackedNode", "Serializing PackedNode into bytes.");
        trace!(target: "PackedNode", "With PackedNode: {:?}", self);
        let mut result: Vec<u8> = Vec::with_capacity(PACKED_NODE_IPV6_SIZE);

        result.push(self.ip_type as u8);

        let addr: Vec<u8> = self.ip().to_bytes();
        result.extend_from_slice(&addr);
        // port
        result.extend_from_slice(&u16_to_array(self.saddr.port().to_be()));

        let PublicKey(ref pk) = self.pk;
        result.extend_from_slice(pk);

        trace!("Result: {:?}", &result);
        result
    }
}

/// Deserialize bytes into `PackedNode`. Returns `None` if deseralizing
/// failed.
///
/// Can fail if:
///
///  - length is too short for given [`IpType`](./enum.IpType.html)
///  - PK can't be parsed
///
/// Blindly trusts that provided `IpType` matches - i.e. if there are provided
/// 51 bytes (which is lenght of `PackedNode` that contains IPv6), and `IpType`
/// says that it's actually IPv4, bytes will be parsed as if that was an IPv4
/// address.
impl FromBytes<PackedNode> for PackedNode {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        debug!(target: "PackedNode", "De-serializing bytes into PackedNode.");
        trace!(target: "PackedNode", "With bytes: {:?}", bytes);

        // parse bytes as IPv4
        fn as_ipv4(bytes: &[u8]) -> Option<(SocketAddr, PublicKey)> {
            debug!("Parsing bytes as IPv4.");
            trace!("Bytes: {:?}", bytes);
            let addr = Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4]);
            let port = u16::from_be(array_to_u16(&[bytes[5], bytes[6]]));
            let saddr = SocketAddrV4::new(addr, port);

            let pk = match PublicKey::from_slice(&bytes[7..PACKED_NODE_IPV4_SIZE]) {
                Some(pk) => pk,
                None => {
                    trace!("Not enough bytes to parse as PK after IPv4.");
                    return None
                },
            };

            Some((SocketAddr::V4(saddr), pk))
        }

        // parse bytes as IPv4
        fn as_ipv6(bytes: &[u8]) -> Option<(SocketAddr, PublicKey)> {
            trace!("Parsing bytes as IPv6.");
            trace!("Bytes: {:?}", bytes);
            if bytes.len() < PACKED_NODE_IPV6_SIZE {
                debug!("Less bytes than PACKED_NODE_IPV6_SIZE!");
                return None
            }

            let addr = match Ipv6Addr::from_bytes(&bytes[1..]) {
                Some(a) => a,
                None    => return None,
            };
            let port = u16::from_be(array_to_u16(&[bytes[17], bytes[18]]));
            let saddr = SocketAddrV6::new(addr, port, 0, 0);

            let pk = match PublicKey::from_slice(&bytes[19..PACKED_NODE_IPV6_SIZE]) {
                Some(p) => p,
                None    => {
                    trace!("Not enough bytes to parse as PK after IPv6.");
                    return None
                },
            };

            Some((SocketAddr::V6(saddr), pk))
        }


        if bytes.len() >= PACKED_NODE_IPV4_SIZE {
            let (iptype, saddr_and_pk) = match IpType::from_bytes(bytes) {
                Some(IpType::U4) => (IpType::U4, as_ipv4(bytes)),
                Some(IpType::T4) => (IpType::T4, as_ipv4(bytes)),
                Some(IpType::U6) => (IpType::U6, as_ipv6(bytes)),
                Some(IpType::T6) => (IpType::T6, as_ipv6(bytes)),
                None => return None,
            };

            let (saddr, pk) = match saddr_and_pk {
                Some(v) => v,
                None => {
                    debug!("Parsing failed, no saddr & PK.");
                    return None
                },
            };

            return Some(PackedNode {
                ip_type: iptype,
                saddr: saddr,
                pk: pk,
            });
        }
        // `if` not triggered
        debug!("Not enough bytes; less than PACKED_NODE_IPV4_SIZE");
        None
    }
}


// TODO: make sure ↓ it's correct
/// Request to get address of given DHT PK, or nodes that are closest in DHT
/// to the given PK.
///
/// Packet type `2`.
///
/// Serialized form:
///
/// ```text
/// +-----------------------------------+
/// | DHT PUBKEY             (32 bytes) |
/// | ping_id                ( 8 bytes) |
/// +-----------------------------------+
/// ```
///
/// Serialized form should be put in the encrypted part of DHT packet.
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

    /// Encapsulate in `DPacketT` to use in [`DhtPacket`]
    /// (./struct.DhtPacket.html).
    pub fn as_packet(&self) -> DPacketT {
        DPacketT::GetNodes(*self)
    }
}

/// Serialization of `GetNodes`. Resulting lenght should be
/// [`GET_NODES_SIZE`](./constant.GET_NODES_SIZE.html).
impl ToBytes for GetNodes {
    fn to_bytes(&self) -> Vec<u8> {
        debug!(target: "GetNodes", "Serializing GetNodes as bytes.");
        trace!(target: "GetNodes", "With GetNodes: {:?}", self);
        let mut result = Vec::with_capacity(GET_NODES_SIZE);
        let PublicKey(pk_bytes) = self.pk;
        result.extend_from_slice(&pk_bytes);
        result.extend_from_slice(&u64_to_array(self.id));
        trace!("Resulting bytes: {:?}", &result);
        result
    }
}

/// De-serialization of bytes into `GetNodes`. If less than
/// [`GET_NODES_SIZE`](./constant.GET_NODES_SIZE.html) bytes are provided,
/// de-serialization will fail, returning `None`.
impl FromBytes<GetNodes> for GetNodes {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        debug!(target: "GetNodes", "De-serializing bytes into GetNodes.");
        trace!(target: "GetNodes", "With bytes: {:?}", bytes);

        if bytes.len() < GET_NODES_SIZE {
            debug!("Amount of bytes is less than GET_NODES_SIZE!");
            return None
        }

        if let Some(pk) = PublicKey::from_slice(&bytes[..PUBLICKEYBYTES]) {
            // need shorter name for ID bytes
            let b = &bytes[PUBLICKEYBYTES..GET_NODES_SIZE];
            let id = array_to_u64(&[b[0], b[1], b[2], b[3],
                                    b[4], b[5], b[6], b[7]]);
            return Some(GetNodes { pk: pk, id: id })
        }
        debug!("Failed to de-serialize bytes into GetNodes!");
        None  // de-serialization failed
    }
}


/// Response to [`GetNodes`](./struct.GetNodes.html) request, containing up to
/// `4` nodes closest to the requested node.
///
/// Packet type `0x04`.
///
/// Serialized form:
///
/// Length      | Contents
/// ----------- | --------
/// `1`         | Number of packed nodes (maximum 4)
/// `[39, 204]` | Nodes in packed format
/// `8`         | Ping ID
///
/// An IPv4 node is 39 bytes, an IPv6 node is 51 bytes, so the maximum size is
/// `51 * 4 = 204` bytes.
///
/// Serialized form should be put in the encrypted part of DHT packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendNodes {
    /// Nodes sent in response to [`GetNodes`](./struct.GetNodes.html) request.
    ///
    /// There can be only 1 to 4 nodes in `SendNodes`.
    pub nodes: Vec<PackedNode>,
    /// Ping id that was received in [`GetNodes`](./struct.GetNodes.html)
    /// request.
    pub id: u64,
}

impl SendNodes {
    /// Create new `SendNodes`. Returns `None` if 0 or more than 4 nodes are
    /// supplied.
    ///
    /// Created as an answer to `GetNodes` request.
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

    /// Encapsulate in `DPacketT` to easily use in [`DhtPacket`]
    /// (./struct.DhtPacket.html).
    pub fn as_packet(self) -> DPacketT {
        DPacketT::SendNodes(self)
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
        result.extend_from_slice(&u64_to_array(self.id));
        trace!("Resulting bytes: {:?}", &result);
        result
    }
}

/// Method to parse received bytes as `SendNodes`.
///
/// Returns `None` if bytes can't be parsed into `SendNodes`.
impl FromBytes<SendNodes> for SendNodes {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        debug!(target: "SendNodes", "De-serializing bytes into SendNodes.");
        trace!(target: "SendNodes", "With bytes: {:?}", bytes);

        // first byte should say how many `PackedNode`s `SendNodes` has.
        // There has to be at least 1 node, and no more than 4.
        if bytes[0] < 1 || bytes[0] > 4 {
            warn!(target: "SendNodes", "Wrong number of nodes: {}", bytes[0]);
            return None
        }

        if let Some(nodes) = PackedNode::from_bytes_multiple(&bytes[1..]) {
            if nodes.len() != bytes[0] as usize {
                warn!(target: "SendNodes", "Wrong number of nodes; Expected:
                      {}; Has: {}", bytes[0], nodes.len());
                return None
            }

            // since 1st byte is a number of nodes
            let mut nodes_bytes_len = 1;
            // TODO: ↓ most likely can be done more efficiently
            for node in &nodes {
                nodes_bytes_len += node.to_bytes().len();
            }

            // need u64 from bytes
            let mut ping_id: [u8; 8] = [0; 8];
            for pos in 0..ping_id.len() {
                ping_id[pos] = bytes[nodes_bytes_len + pos];
            }

            return Some(SendNodes { nodes: nodes, id: array_to_u64(&ping_id) })
        }
        debug!("De-serializing from bytes into SendNodes failed!");
        None  // parsing failed
    }
}

/// Types of DHT packets that can be put in `DHT Packet`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DPacketT {
    /// `Ping` packet type.
    Ping(Ping),
    /// `GetNodes` packet type. Used to request nodes.
    // TODO: rename to `GetN()` ? – consistency with PacketKind
    GetNodes(GetNodes),
    /// `SendNodes` response to `GetNodes` request.
    // TODO: rename to `SendN()` ? – consistency with PacketKind
    SendNodes(SendNodes),
}

impl DPacketT {
    /// Provide packet type number.
    ///
    /// To use for serialization: `.kind() as u8`.
    pub fn kind(&self) -> PacketKind {
        match *self {
            DPacketT::GetNodes(_) => PacketKind::GetN,
            DPacketT::SendNodes(_) => PacketKind::SendN,
            DPacketT::Ping(p) => {
                if p.is_request() {
                    PacketKind::PingReq
                } else {
                    PacketKind::PingResp
                }
            },
        }
    }

    /// Create [`Ping`](./struct.Ping.html) response if `DPacketT` is a `Ping`
    /// request.
    ///
    /// Returns `None` if `DPacketT` is not a ping request, and thus `Ping`
    /// response could not be created.
    pub fn ping_resp(&self) -> Option<Self> {
        debug!(target: "Ping", "Creating Ping response from a Ping.");
        trace!(target: "Ping", "With Ping: {:?}", self);
        if let &DPacketT::Ping(ping) = self {
            if let Some(ping_resp) = ping.response() {
                return Some(DPacketT::Ping(ping_resp))
            }
        }
        debug!("Ping was already a response!");
        None
    }
}

impl ToBytes for DPacketT {
    fn to_bytes(&self) -> Vec<u8> {
        match *self {
            DPacketT::Ping(ref d)      => d.to_bytes(),
            DPacketT::GetNodes(ref d)  => d.to_bytes(),
            DPacketT::SendNodes(ref d) => d.to_bytes(),
        }
    }
}


/// Standard DHT packet that encapsulates in the encrypted payload
/// [`DhtPacketT`](./enum.DhtPacketT.html).
///
/// Length      | Contents
/// ----------- | --------
/// `1`         | `uint8_t` [`PacketKind`](./enum.PacketKind.html)
/// `32`        | Sender DHT Public Key
/// `24`        | Random nonce
/// variable    | Encrypted payload
///
/// `PacketKind` values for `DhtPacket` can be only `<= 4`.
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
    pub fn new(symmetric_key: &PrecomputedKey, own_public_key: &PublicKey,
               nonce: &Nonce, packet: DPacketT) -> Self {

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

    /// Get packet data. This functino decrypts payload and tries to parse it
    /// as packet type.
    ///
    /// Returns `None` in case of faliure.
    // TODO: perhaps switch to using precomputed symmetric key?
    //        - given that computing shared key is apparently the most
    //          costly operation when it comes to crypto, using precomputed
    //          key might (would significantly?) lower resource usage
    //
    //          Alternatively, another method `get_packetnm()` which would use
    //          symmetric key.
    pub fn get_packet(&self, own_secret_key: &SecretKey) -> Option<DPacketT> {
        debug!(target: "DhtPacket", "Getting packet data from DhtPacket.");
        trace!(target: "DhtPacket", "With DhtPacket: {:?}", self);
        let decrypted = match open(&self.payload, &self.nonce, &self.sender_pk,
                            own_secret_key) {
            Ok(d) => d,
            // TODO: ↓ logging
            Err(_) => {
                debug!("Decrypting DhtPacket failed!");
                return None
            },
        };

        trace!("Decrypted bytes: {:?}", &decrypted);

        match self.packet_type {
            PacketKind::PingReq | PacketKind::PingResp => {
                if let Some(p) = Ping::from_bytes(&decrypted) {
                    return Some(DPacketT::Ping(p))
                }
            },
            PacketKind::GetN => {
                if let Some(n) = GetNodes::from_bytes(&decrypted) {
                    return Some(DPacketT::GetNodes(n))
                }
            },
            PacketKind::SendN => {
                if let Some(n) = SendNodes::from_bytes(&decrypted) {
                    return Some(DPacketT::SendNodes(n))
                }
            },
            _ => {},  // not a DHT packet
        }
        debug!("De-serializing decrypted bytes into a DHT packet failed!");
        None  // parsing failed
    }

    /// Create DHT Packet with [`Ping`](./struct.Ping.html) response to `Ping`
    /// request that packet contained.
    ///
    /// Nonce for the response is automatically generated.
    pub fn ping_resp(&self, secret_key: &SecretKey,
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
impl FromBytes<DhtPacket> for DhtPacket {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        debug!(target: "DhtPacket", "De-serializing bytes into DhtPacket.");
        trace!(target: "DhtPacket", "With bytes: {:?}", bytes);

        if bytes.len() < DHT_PACKET_MIN_SIZE {
            debug!("Failed; less bytes than DHT_PACKET_MIN_SIZE!");
            return None
        }

        let packet_type = match PacketKind::from_bytes(bytes) {
            Some(b) => {
                match b {
                    PacketKind::PingReq | PacketKind::PingResp |
                    PacketKind::GetN | PacketKind::SendN => b,
                    p => {
                        debug!("Failed: not a DHT packet!");
                        trace!("Packet: {:?}", p);
                        return None  // not a DHT packet
                    },
                }
            },
            None => {
                debug!("Failed: not a recognisable PacketKind!");
                return None
            },
        };

        const NONCE_POS: usize = 1 + PUBLICKEYBYTES;
        let sender_pk = match PublicKey::from_slice(&bytes[1..NONCE_POS]) {
            Some(pk) => pk,
            None => {
                debug!("Failed; de-serializing sender's PK!");
                trace!("With bytes for PK: {:?}", &bytes[1..NONCE_POS]);
                return None
            },
        };

        const PAYLOAD_POS: usize = NONCE_POS + NONCEBYTES;
        let nonce = match Nonce::from_slice(&bytes[NONCE_POS..PAYLOAD_POS]) {
            Some(n) => n,
            None => {
                debug!("Failed; de-serializing nonce!");
                trace!("With bytes for nonce: {:?}", &bytes[NONCE_POS..PAYLOAD_POS]);
                return None
            },
        };

        Some(DhtPacket {
            packet_type: packet_type,
            sender_pk: sender_pk,
            nonce: nonce,
            payload: bytes[PAYLOAD_POS..].to_vec(),
        })
    }
}


/// Trait for functionality related to distance between `PublicKey`s.
pub trait Distance {
    /// Check whether distance between PK1 and own PK is smaller than distance
    /// between PK2 and own PK.
    // TODO: perhaps simple bool would suffice?
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
// TODO: perhaps merge functionality with the `PackedNode` ?
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Node {
    /// Time when node will reach it's timeout - value consists of `seconds
    /// since UNIX epoch + timeout`. If value equals or is lower than current
    /// time since UNIX epoch, node is timed out.
    ///
    /// Timeout value should be updated every time a valid packet from given
    /// node is received.
    pub timeout: u64,
    /// Ping ID of last sent [`Ping`](./struct.Ping.html) request.
    pub id: u64,
    /// Packed Node that Node contains.
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


/// Calculate the `k-bucket` index of a PK compared to "own" PK.
///
/// Falis (returns `None`) if supplied keys are the same.
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

/// Structure for holding up to [`BUCKET_SIZE`](./constant.BUCKET_SIZE.html)
/// nodes.
///
/// Nodes in bucket are sorted by closeness to the PK; closes node is the
/// first, while furthest is last.
///
/// Used in [`Kbucket`](./struct.Kbucket.html) for storing nodes close to own
/// PK; and additionally used to store nodes closest to friends.
// TODO: rename..?
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bucket<'a> {
    /// PK that nodes in the bucket are close to.
    pub pk: &'a PublicKey,
    /// Index in the [`Kbucket`](./struct.Kbucket.html).
    index: u8,
    nodes: Vec<Node>,
}

/// Maximum of nodes that [`Bucket`](./struct.Bucket.html) can hold.
pub const BUCKET_SIZE: usize = 8;

impl<'a> Bucket<'a> {
    /// Create a new `Bucket` to store nodes close to the `pk`.
    pub fn new(pk: &'a PublicKey, i: u8) -> Self {
        trace!("Creating new Bucket; index: {}; PK: {:?}", i, pk);
        Bucket { pk: pk, index: i, nodes: Vec::with_capacity(BUCKET_SIZE) }
    }

    /// Try to add node to the bucket.
    ///
    /// If bucket doesn't have [`BUCKET_SIZE`](./constant.BUCKET_SIZE.html)
    /// nodes, node is appended.
    ///
    /// If bucket has `BUCKET_SIZE` already, node's closeness is compared to
    /// nodes already in bucket, and if it's closer than some node, it prepends
    /// that node, and last node is removed from the list.
    ///
    /// Returns `true` is node was added, `false` otherwise.
    pub fn try_add(&mut self, node: &Node) -> bool {
        debug!(target: "Bucket", "Trying to add node to bucket.");
        trace!(target: "Bucket", "With bucket: {:?}; and node: {:?}", self, node);

        if self.nodes.is_empty() {
            self.nodes.push(*node);
            debug!("Bucket was empty, node added.");
            return true
        }

        for n in 0..self.nodes.len() {
            match self.pk.distance(node.pk(), self.nodes[n].pk()) {
                Ordering::Less => {
                    if self.nodes.len() == BUCKET_SIZE {
                        drop(self.nodes.pop());
                    }

                    self.nodes.insert(n, *node);
                    return true
                },
                Ordering::Equal => {
                    debug!("Failed to add; Node is already in the bucket!");
                    return false
                },
                _ => {},
            }
        }
        if self.nodes.len() < BUCKET_SIZE {
            self.nodes.push(*node);
            return true
        }

        debug!("Node is too distant to add to bucket.");
        false
    }
}


/// K-bucket structure to hold up to
/// [`KBUCKET_MAX_ENTRIES`](./constant.KBUCKET_MAX_ENTRIES.html) *
/// [`BUCKET_SIZE`](./constant.BUCKET_SIZE.html) nodes close to own PK.
///
/// Further reading:
///
/// * [Kademilia implementation, on which Tox was based on]
///   (https://en.wikipedia.org/wiki/Kademlia#Routing_tables)
/// * [Tox spec](https://en.wikipedia.org/wiki/Kademlia#Routing_tables)
#[derive(Clone, Debug, Eq, PartialEq)]
// TODO: rename?
pub struct Kbucket<'a> {
    /// Number of buckets held.
    pub k: u8,
    pk: PublicKey,
    list: Vec<Bucket<'a>>,
}

/// Maximum number of buckets that Kbucket can hold.
///
/// Realistically, not even half of that will be ever used.
// TODO: ↓ perhaps s/usize/u8/ ?
pub const KBUCKET_MAX_ENTRIES: usize = ::std::u8::MAX as usize;

// TODO: k-bucket methods
//        * creating new kbucket without any buckets (is it needed?)
//        * creating new kbucket from nodes, automatically creating buckets
//          - with a switch to decide whether only 1 bucket should be used
//            (for friend's close nodes) or many (for own close nodes)
