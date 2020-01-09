//! `IpAddr` with a port number.

use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    SocketAddr,
};

use nom::{
    IResult,
    number::complete::{be_u16, le_u8},
};

use crate::toxcore::binary_io::*;

/// Size of serialized `IpPort` struct.
pub const SIZE_IPPORT: usize = 19;

/// IPv4 can be padded with 12 bytes of zeros so that both IPv4 and IPv6 have
/// the same stored size.
pub const IPV4_PADDING_SIZE: usize = 12;

/// Defines whether 12 bytes padding should be inserted after IPv4 address to
/// align it with IPv6 address.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IpPortPadding {
    /// Padding should be inserted.
    WithPadding,
    /// Padding should not be inserted.
    NoPadding,
}

/** Transport protocol type: `UDP` or `TCP`.

The binary representation of `ProtocolType` is a single bit: 0 for `UDP`, 1 for
`TCP`. If encoded as standalone value, the bit is stored in the least
significant bit of a byte.

*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProtocolType {
    /// `UDP` type if the least significant bit is 0.
    UDP,
    /// `TCP` type if the least significant bit is 1.
    TCP
}

/** `IpAddr` with a port number. IPv4 can be padded with 12 bytes of zeros
so that both IPv4 and IPv6 have the same stored size.

Serialized form:

Length      | Content
----------- | ------
`1`         | IpType
`4` or `16` | IPv4 or IPv6 address
`0` or `12` | Padding for IPv4 (if needed)
`2`         | Port

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpPort {
    /// Type of protocol
    pub protocol: ProtocolType,
    /// IP address
    pub ip_addr: IpAddr,
    /// Port number
    pub port: u16
}

impl IpPort {
    /** Get IP Type byte.

    * 1st bit - protocol
    * 4th bit - address family

    Value | Type
    ----- | ----
    `2`   | UDP IPv4
    `10`  | UDP IPv6
    `130` | TCP IPv4
    `138` | TCP IPv6

    */
    fn ip_type(&self) -> u8 {
        if self.ip_addr.is_ipv4() {
            match self.protocol {
                ProtocolType::UDP => 2,
                ProtocolType::TCP => 130,
            }
        } else {
            match self.protocol {
                ProtocolType::UDP => 10,
                ProtocolType::TCP => 138,
            }
        }
    }

    /// Parse `IpPort` with UDP protocol type with optional padding.
    pub fn from_udp_bytes(input: &[u8], padding: IpPortPadding) -> IResult<&[u8], IpPort> {
        do_parse!(input,
            ip_addr: switch!(le_u8,
                2 => terminated!(
                    map!(Ipv4Addr::from_bytes, IpAddr::V4),
                    cond!(padding == IpPortPadding::WithPadding, take!(IPV4_PADDING_SIZE))
                ) |
                10 => map!(Ipv6Addr::from_bytes, IpAddr::V6)
            ) >>
            port: be_u16 >>
            (IpPort { protocol: ProtocolType::UDP, ip_addr, port })
        )
    }

    /// Parse `IpPort` with TCP protocol type with optional padding.
    pub fn from_tcp_bytes(input: &[u8], padding: IpPortPadding) -> IResult<&[u8], IpPort> {
        do_parse!(input,
            ip_addr: switch!(le_u8,
                130 => terminated!(
                    map!(Ipv4Addr::from_bytes, IpAddr::V4),
                    cond!(padding == IpPortPadding::WithPadding, take!(IPV4_PADDING_SIZE))
                ) |
                138 => map!(Ipv6Addr::from_bytes, IpAddr::V6)
            ) >>
            port: be_u16 >>
            (IpPort { protocol: ProtocolType::TCP, ip_addr, port })
        )
    }

    /// Parse `IpPort` with optional padding.
    pub fn from_bytes(input: &[u8], padding: IpPortPadding) -> IResult<&[u8], IpPort> {
        alt!(input, call!(IpPort::from_udp_bytes, padding) | call!(IpPort::from_tcp_bytes, padding))
    }

    /// Write `IpPort` with UDP protocol type with optional padding.
    pub fn to_udp_bytes<'a>(&self, buf: (&'a mut [u8], usize), padding: IpPortPadding) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_cond!(self.protocol == ProtocolType::TCP, |buf| gen_error(buf, 0)) >>
            gen_call!(|buf, ip_port| IpPort::to_bytes(ip_port, buf, padding), self)
        )
    }

    /// Write `IpPort` with TCP protocol type with optional padding.
    pub fn to_tcp_bytes<'a>(&self, buf: (&'a mut [u8], usize), padding: IpPortPadding) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_cond!(self.protocol == ProtocolType::UDP, |buf| gen_error(buf, 0)) >>
            gen_call!(|buf, ip_port| IpPort::to_bytes(ip_port, buf, padding), self)
        )
    }

    /// Write `IpPort` with optional padding.
    pub fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize), padding: IpPortPadding) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(self.ip_type()) >>
            gen_call!(|buf, ip_addr| IpAddr::to_bytes(ip_addr, buf), &self.ip_addr) >>
            gen_cond!(padding == IpPortPadding::WithPadding && self.ip_addr.is_ipv4(), gen_slice!(&[0; IPV4_PADDING_SIZE])) >>
            gen_be_u16!(self.port)
        )
    }

    /// Create new `IpPort` from `SocketAddr` with UDP type.
    pub fn from_udp_saddr(saddr: SocketAddr) -> IpPort {
        IpPort {
            protocol: ProtocolType::UDP,
            ip_addr: saddr.ip(),
            port: saddr.port()
        }
    }

    /// Create new `IpPort` from `SocketAddr` with TCP type.
    pub fn from_tcp_saddr(saddr: SocketAddr) -> IpPort {
        IpPort {
            protocol: ProtocolType::TCP,
            ip_addr: saddr.ip(),
            port: saddr.port()
        }
    }

    /// Convert `IpPort` to `SocketAddr`.
    pub fn to_saddr(&self) -> SocketAddr {
        SocketAddr::new(self.ip_addr, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! ip_port_with_padding_encode_decode_test (
        ($test:ident, $protocol:expr) => (
            #[test]
            fn $test() {
                let value = IpPort {
                    protocol: $protocol,
                    ip_addr: "5.6.7.8".parse().unwrap(),
                    port: 12345
                };
                let mut buf = [0; SIZE_IPPORT];
                let (_, size) = value.to_bytes((&mut buf, 0), IpPortPadding::WithPadding).unwrap();
                assert_eq!(size, SIZE_IPPORT);
                let (rest, decoded_value) = IpPort::from_bytes(&buf[..size], IpPortPadding::WithPadding).unwrap();
                assert!(rest.is_empty());
                assert_eq!(decoded_value, value);
            }
        )
    );

    ip_port_with_padding_encode_decode_test!(ip_port_udp_with_padding_encode_decode, ProtocolType::UDP);
    ip_port_with_padding_encode_decode_test!(ip_port_tcp_with_padding_encode_decode, ProtocolType::TCP);

    macro_rules! ip_port_without_padding_encode_decode_test (
        ($test:ident, $protocol:expr) => (
            #[test]
            fn $test() {
                let value = IpPort {
                    protocol: $protocol,
                    ip_addr: "5.6.7.8".parse().unwrap(),
                    port: 12345
                };
                let mut buf = [0; SIZE_IPPORT - IPV4_PADDING_SIZE];
                let (_, size) = value.to_bytes((&mut buf, 0), IpPortPadding::NoPadding).unwrap();
                assert_eq!(size, SIZE_IPPORT - IPV4_PADDING_SIZE);
                let (rest, decoded_value) = IpPort::from_bytes(&buf[..size], IpPortPadding::NoPadding).unwrap();
                assert!(rest.is_empty());
                assert_eq!(decoded_value, value);
            }
        )
    );

    ip_port_without_padding_encode_decode_test!(ip_port_udp_without_padding_encode_decode, ProtocolType::UDP);
    ip_port_without_padding_encode_decode_test!(ip_port_tcp_without_padding_encode_decode, ProtocolType::TCP);

    #[test]
    fn ip_port_from_to_udp_saddr() {
        let ip_port_1 = IpPort {
            protocol: ProtocolType::UDP,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let ip_port_2 = IpPort::from_udp_saddr(ip_port_1.to_saddr());
        assert_eq!(ip_port_2, ip_port_1);
    }

    #[test]
    fn ip_port_from_to_tcp_saddr() {
        let ip_port_1 = IpPort {
            protocol: ProtocolType::TCP,
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let ip_port_2 = IpPort::from_tcp_saddr(ip_port_1.to_saddr());
        assert_eq!(ip_port_2, ip_port_1);
    }
}
