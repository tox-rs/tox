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
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use toxcore::binary_io::*;
use toxcore::crypto_core::*;


/// Type of [`Ping`](./struct.Ping.html) packet. Either a request or response.
///
/// * `0` – if ping is a request;
/// * `1` – if ping is a response.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PingType {
    /// Request ping response.
    Req  = 0,
    /// Respond to ping request.
    Resp = 1,
}

/// Uses the first byte from the provided slice to de-serialize
/// [`PingType`](./enum.PingType.html). Returns `None` if first byte of slice
/// doesn't match `PingType` or slice has no elements.
impl FromBytes<PingType> for PingType {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 0 { return None }
        match bytes[0] {
            0 => Some(PingType::Req),
            1 => Some(PingType::Resp),
            _ => None,
        }
    }
}


/// Used to request/respond to ping. Use in an encrypted form in DHT packets.
///
/// ```text
///                 (9 bytes)
/// +-------------------------+
/// | Ping type     (1 byte ) |
/// | ping_id       (8 bytes) |
/// +-------------------------+
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ping {
    p_type: PingType,
    /// An ID of the request. Response ID must match ID of the request,
    /// otherwise ping is invalid.
    pub id: u64,
}

/// Length in bytes of [`Ping`](./struct.Ping) when serialized into bytes.
pub const PING_SIZE: usize = 9;

impl Ping {
    /// Create new ping request with a randomly generated `id`.
    pub fn new() -> Self {
        Ping { p_type: PingType::Req, id: random_u64(), }
    }

    /// Check whether given `Ping` is a request.
    pub fn is_request(&self) -> bool {
        self.p_type == PingType::Req
    }

    /// Create answer to ping request. Returns `None` if supplied `Ping` is
    /// already a ping response.
    // TODO: make sure that checking whether `Ping` is not a response is needed
    //       here
    pub fn response(&self) -> Option<Self> {
        if self.p_type == PingType::Resp {
            return None;
        }

        Some(Ping { p_type: PingType::Resp, id: self.id })
    }
}

/// Serializes [`Ping`](./struct.Ping.html) into bytes.
impl AsBytes for Ping {
    fn as_bytes(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(PING_SIZE);
        // `PingType`
        res.push(self.p_type as u8);
        // And random ping_id as bytes
        res.extend_from_slice(&u64_to_array(self.id));
        res
    }
}

/// De-seralize [`Ping`](./struct.Ping.html) from bytes. Tries to parse first
/// [`PING_SIZE`](./const.PING_SIZE.html) bytes from supplied slice as `Ping`.
impl FromBytes<Ping> for Ping {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < PING_SIZE { return None; }
        if let Some(ping_type) = PingType::from_bytes(bytes) {
            return Some(Ping {
                p_type: ping_type,
                id: array_to_u64(&[bytes[1], bytes[2], bytes[3], bytes[4],
                                   bytes[5], bytes[6], bytes[7], bytes[8]]),
            })
        }
        // parsing failed
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
        if bytes.len() == 0 { return None }
        match bytes[0] {
            2   => Some(IpType::U4),
            10  => Some(IpType::U6),
            130 => Some(IpType::T4),
            138 => Some(IpType::T6),
            _   => None,
        }
    }
}


// TODO: not sure if this is the best place for it..
impl AsBytes for IpAddr {
    fn as_bytes(&self) -> Vec<u8> {
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
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PackedNode {
    /// IP type, includes also info about protocol used.
    pub ip_type: IpType,
    socketaddr: SocketAddr,
    node_id: PublicKey,
}

// TODO: ↓ add a method for printing either Ipv{4,6} .. maybe?
impl PackedNode {
    /// New `PackedNode`.
    //
    // TODO: Should fail if type of IP address supplied in
    // `socketaddr` doesn't match `IpType`..?
    pub fn new(ip_type: IpType,
               socketaddr: SocketAddr,
               node_id: &PublicKey) -> Self {
        PackedNode {
            ip_type: ip_type,
            socketaddr: socketaddr,
            node_id: *node_id,
        }
    }

    /// Get an IP address from the `PackedNode`.
    pub fn ip(&self) -> IpAddr {
        match self.socketaddr {
            SocketAddr::V4(addr) => IpAddr::V4(*addr.ip()),
            SocketAddr::V6(addr) => IpAddr::V6(*addr.ip()),
        }
    }
}

/// Size in bytes of serialized [`PackedNode`](./struct.PackedNode.html) with
/// IPv4.
pub const PACKED_NODE_IPV4_SIZE: usize = 39;
/// Size in bytes of serialized [`PackedNode`](./struct.PackedNode.html) with
/// IPv6.
pub const PACKED_NODE_IPV6_SIZE: usize = 51;


/// Serialize `PackedNode` into bytes.
///
/// Can be either `39` or `51` bytes long, depending on whether IPv4 or
/// IPv6 is being used.
impl AsBytes for PackedNode {
    fn as_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::with_capacity(39);

        result.push(self.ip_type as u8);

        let addr: Vec<u8> = self.ip().as_bytes();
        result.extend_from_slice(&addr);
        // port
        result.extend_from_slice(&u16_to_array(self.socketaddr.port()));

        let PublicKey(ref pk) = self.node_id;
        result.extend_from_slice(pk);

        result
    }
}

/// Deserialize bytes into `PackedNode`. Returns `None` if deseralizing
/// failed.
///
/// Can fail if:
///
///  - length and [`IpType`](./enum.IpType.html) don't match
///  - PK can't be parsed
impl FromBytes<PackedNode> for PackedNode {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == PACKED_NODE_IPV4_SIZE {
            let iptype = match bytes[0] {
                2   => IpType::U4,
                130 => IpType::T4,
                _ => return None,
            };

            let addr = Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4]);
            let port = array_to_u16(&[bytes[5], bytes[6]]);
            let saddr = SocketAddrV4::new(addr, port);

            let pk = match PublicKey::from_slice(&bytes[7..]) {
                Some(pk) => pk,
                None => return None,
            };

            return Some(PackedNode {
                ip_type: iptype,
                socketaddr: SocketAddr::V4(saddr),
                node_id: pk,
            });
        } else if bytes.len() == PACKED_NODE_IPV6_SIZE {
            let iptype = match bytes[0] {
                10  => IpType::U6,
                138 => IpType::T6,
                _ => return None,
            };

            // get `u16`s from &[u8], so that it could be used to make IPv6
            let (a, b, c, d, e, f, g, h) = {
                let mut v: Vec<u16> = Vec::with_capacity(8);
                for slice in bytes[1..17].chunks(2) {
                    v.push(array_to_u16(&[slice[0], slice[1]]));
                }
                (v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7])
            };
            let addr = Ipv6Addr::new(a, b, c, d, e, f, g, h);
            let port = array_to_u16(&[bytes[17], bytes[18]]);
            let saddr = SocketAddrV6::new(addr, port, 0, 0);

            let pk = match PublicKey::from_slice(&bytes[19..]) {
                Some(p) => p,
                None => return None,
            };

            return Some(PackedNode {
                ip_type: iptype,
                socketaddr: SocketAddr::V6(saddr),
                node_id: pk,
            });
        }
        // `if` not triggered, make sure to return `None`
        None
    }
}
