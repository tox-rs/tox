/*! A pair of SocketAddr & PublicKey.
*/
use super::*;

use cookie_factory::gen_if_else;
use nom::combinator::flat_map;
use nom::error::{make_error, ErrorKind};
use nom::number::complete::{be_u16, le_u8};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

use tox_binary_io::*;
use tox_crypto::*;

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedNode {
    /// Socket addr of node.
    pub saddr: SocketAddr,
    /// Public Key of the node.
    pub pk: PublicKey,
}

impl ToBytes for PackedNode {
    #[rustfmt::skip]
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
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, addr) = flat_map(le_u8, |b| {
            move |input| match b {
                2 => map(Ipv4Addr::from_bytes, IpAddr::V4)(input),
                10 => map(Ipv6Addr::from_bytes, IpAddr::V6)(input),
                _ => Err(nom::Err::Error(make_error(input, ErrorKind::Switch))),
            }
        })(input)?;
        let (input, port) = be_u16(input)?;
        let saddr = SocketAddr::new(addr, port);
        let (input, pk) = PublicKey::from_bytes(input)?;
        Ok((input, PackedNode::new(saddr, pk)))
    }
}

impl PackedNode {
    /// Create new `PackedNode`. The IPv6 address will be converted to IPv4 if
    /// it's IPv4-compatible or IPv4-mapped.
    pub fn new(saddr: SocketAddr, pk: PublicKey) -> Self {
        PackedNode {
            saddr: PackedNode::ipv6_to_ipv4(saddr),
            pk,
        }
    }

    /// Convert IPv6 address to IPv4 if it's IPv4-compatible or IPv4-mapped.
    /// Otherwise return original address.
    fn ipv6_to_ipv4(saddr: SocketAddr) -> SocketAddr {
        match saddr {
            SocketAddr::V4(v4) => SocketAddr::V4(v4),
            SocketAddr::V6(v6) => {
                if let Some(converted_ip4) = v6.ip().to_ipv4() {
                    SocketAddr::V4(SocketAddrV4::new(converted_ip4, v6.port()))
                } else {
                    SocketAddr::V6(v6)
                }
            }
        }
    }

    /// to_bytes for TCP
    #[allow(clippy::wrong_self_convention)]
    #[rustfmt::skip]
    pub fn to_tcp_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_if_else!(self.saddr.is_ipv4(), gen_be_u8!(130), gen_be_u8!(138)) >>
            gen_call!(|buf, addr| IpAddr::to_bytes(addr, buf), &self.saddr.ip()) >>
            gen_be_u16!(self.saddr.port()) >>
            gen_slice!(self.pk.as_ref())
        )
    }

    /// from_bytes for TCP
    pub fn from_tcp_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, addr) = flat_map(le_u8, |b| {
            move |input| match b {
                130 => map(Ipv4Addr::from_bytes, IpAddr::V4)(input),
                138 => map(Ipv6Addr::from_bytes, IpAddr::V6)(input),
                _ => Err(nom::Err::Error(make_error(input, ErrorKind::Switch))),
            }
        })(input)?;
        let (input, port) = be_u16(input)?;
        let saddr = SocketAddr::new(addr, port);
        let (input, pk) = PublicKey::from_bytes(input)?;
        Ok((input, PackedNode::new(saddr, pk)))
    }

    /// Get an IP type from the `PackedNode`.
    pub fn ip_type(&self) -> u8 {
        if self.saddr.is_ipv4() {
            2
        } else {
            10
        }
    }

    /// Get an IP address from the `PackedNode`.
    pub fn ip(&self) -> IpAddr {
        self.saddr.ip()
    }

    /// Get a Socket address from the `PackedNode`.
    pub fn socket_addr(&self) -> SocketAddr {
        self.saddr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn packed_node_new() {
        let pk = SecretKey::generate(&mut thread_rng()).public_key();
        let saddr = "1.2.3.4:12345".parse().unwrap();

        let a = PackedNode::new(saddr, pk.clone());
        let b = PackedNode { saddr, pk };
        assert_eq!(a, b);
    }

    #[test]
    fn packed_node_new_ipv4_mapped() {
        let pk = SecretKey::generate(&mut thread_rng()).public_key();
        let saddr_v6 = "[::ffff:1.2.3.4]:12345".parse().unwrap();
        let saddr_v4 = "1.2.3.4:12345".parse().unwrap();

        let a = PackedNode::new(saddr_v6, pk.clone());
        let b = PackedNode { saddr: saddr_v4, pk };
        assert_eq!(a, b);
    }

    #[test]
    fn packed_node_ip_type_2() {
        let pk = SecretKey::generate(&mut thread_rng()).public_key();
        let saddr = "1.2.3.4:12345".parse().unwrap();

        let node = PackedNode::new(saddr, pk);

        assert_eq!(node.ip_type(), 2);
    }

    #[test]
    fn packed_node_ip_type_10() {
        let pk = SecretKey::generate(&mut thread_rng()).public_key();
        let saddr = "[::1234:4321]:12345".parse().unwrap();

        let node = PackedNode::new(saddr, pk);

        assert_eq!(node.ip_type(), 2);
    }

    #[test]
    fn packed_node_ip() {
        let pk = SecretKey::generate(&mut thread_rng()).public_key();
        let saddr = "1.2.3.4:12345".parse().unwrap();

        let node = PackedNode::new(saddr, pk);

        assert_eq!(node.ip(), saddr.ip());
    }

    #[test]
    fn packed_node_socket_addr() {
        let pk = SecretKey::generate(&mut thread_rng()).public_key();
        let saddr = "1.2.3.4:12345".parse().unwrap();

        let node = PackedNode::new(saddr, pk);

        assert_eq!(node.socket_addr(), saddr);
    }
}
