/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2018 Evgeny Kurnevsky <kurnevsky@gmail.com>

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

/*! Onion UDP Packets
*/

mod announce_request;
mod announce_response;
mod onion_data_request;
mod onion_data_response;
mod onion_request_0;
mod onion_request_1;
mod onion_request_2;
mod onion_response_1;
mod onion_response_2;
mod onion_response_3;

pub use self::announce_request::*;
pub use self::announce_response::*;
pub use self::onion_data_request::*;
pub use self::onion_data_response::*;
pub use self::onion_request_0::*;
pub use self::onion_request_1::*;
pub use self::onion_request_2::*;
pub use self::onion_response_1::*;
pub use self::onion_response_2::*;
pub use self::onion_response_3::*;

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::dht::packed_node::PackedNode;

use nom::{be_u16, le_u8, rest};
use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
};
use std::io::{Error, ErrorKind};

/// IPv4 is padded with 12 bytes of zeroes so that both IPv4 and
/// IPv6 have the same stored size.
pub const IPV4_PADDING_SIZE: usize = 12;

/// Size of serialized `IpPort` struct.
pub const SIZE_IPPORT: usize = 19;

/// Size of first `OnionReturn` struct with no inner `OnionReturn`s.
pub const ONION_RETURN_1_SIZE: usize = NONCEBYTES + SIZE_IPPORT + MACBYTES; // 59
/// Size of second `OnionReturn` struct with one inner `OnionReturn`.
pub const ONION_RETURN_2_SIZE: usize = NONCEBYTES + SIZE_IPPORT + MACBYTES + ONION_RETURN_1_SIZE; // 118
/// Size of third `OnionReturn` struct with two inner `OnionReturn`s.
pub const ONION_RETURN_3_SIZE: usize = NONCEBYTES + SIZE_IPPORT + MACBYTES + ONION_RETURN_2_SIZE; // 177

/// The minimum size of onion encrypted payload together with temporary public key.
pub const ONION_SEND_BASE_SIZE: usize = PUBLICKEYBYTES + SIZE_IPPORT + MACBYTES; // 67

/// The maximum size of onion packet including public key, nonce, packet kind
/// byte, onion return.
pub const ONION_MAX_PACKET_SIZE: usize = 1400;

/// Parser that returns the length of the remaining input.
pub fn rest_len(input: &[u8]) -> IResult<&[u8], usize> {
    IResult::Done(input, input.len())
}

/** `IpAddr` with a port number. IPv4 is padded with 12 bytes of zeros
so that both IPv4 and IPv6 have the same stored size.

Serialized form:

Length      | Content
----------- | ------
`1`         | IpType
`4` or `16` | IPv4 or IPv6 address
`0` or `12` | Padding for IPv4
`2`         | Port

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpPort {
    /// IP address
    ip_addr: IpAddr,
    /// Port number
    port: u16
}

impl FromBytes for IpPort {
    named!(from_bytes<IpPort>, do_parse!(
        ip_addr: switch!(le_u8,
            2 => terminated!(
                map!(Ipv4Addr::from_bytes, IpAddr::V4),
                take!(IPV4_PADDING_SIZE)
            ) |
            10 => map!(Ipv6Addr::from_bytes, IpAddr::V6)
        ) >>
        port: be_u16 >>
        (IpPort { ip_addr, port })
    ));
}

impl ToBytes for IpPort {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_if_else!(self.ip_addr.is_ipv4(), gen_be_u8!(2), gen_be_u8!(10)) >>
            gen_call!(|buf, ip_addr| IpAddr::to_bytes(ip_addr, buf), &self.ip_addr) >>
            gen_cond!(self.ip_addr.is_ipv4(), gen_slice!(&[0; IPV4_PADDING_SIZE])) >>
            gen_be_u16!(self.port)
        )
    }
}

/** Encrypted onion return addresses. Payload contains encrypted with symmetric
key `IpPort` and possibly inner `OnionReturn`.

When DHT node receives OnionRequest packet it appends `OnionReturn` to the end
of the next request packet it will send. So when DHT node receives OnionResponse
packet it will know where to send the next response packet by decrypting
`OnionReturn` from received packet. If node can't decrypt `OnionReturn` that
means that onion path is expired and packet should be dropped.

Serialized form:

Length                | Content
--------              | ------
`24`                  | `Nonce`
`35` or `94` or `153` | Payload

where payload is encrypted inner `OnionReturn`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionReturn {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for OnionReturn {
    named!(from_bytes<OnionReturn>, do_parse!(
        nonce: call!(Nonce::from_bytes) >>
        payload: rest >>
        (OnionReturn { nonce, payload: payload.to_vec() })
    ));
}

impl ToBytes for OnionReturn {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload)
        )
    }
}

impl OnionReturn {
    fn inner_to_bytes<'a>(ip_port: &IpPort, inner: Option<&OnionReturn>, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, ip_port| IpPort::to_bytes(ip_port, buf), ip_port) >>
            gen_call!(|buf, inner| match inner {
                Some(inner) => OnionReturn::to_bytes(inner, buf),
                None => Ok(buf)
            }, inner)
        )
    }

    named!(inner_from_bytes<(IpPort, Option<OnionReturn>)>, do_parse!(
        ip_port: call!(IpPort::from_bytes) >>
        rest_len: rest_len >>
        inner: cond!(rest_len > 0, OnionReturn::from_bytes) >>
        (ip_port, inner)
    ));

    /// Create new `OnionReturn` object using symmetric key for encryption.
    pub fn new(symmetric_key: &PrecomputedKey, ip_port: &IpPort, inner: Option<&OnionReturn>) -> OnionReturn {
        let nonce = gen_nonce();
        let mut buf = [0; ONION_RETURN_2_SIZE + SIZE_IPPORT];
        let (_, size) = OnionReturn::inner_to_bytes(ip_port, inner, (&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, symmetric_key);

        OnionReturn { nonce, payload }
    }

    /** Decrypt payload with symmetric key and try to parse it as `IpPort` with possibly inner `OnionReturn`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `IpPort` with possibly inner `OnionReturn`
    */
    pub fn get_payload(&self, symmetric_key: &PrecomputedKey) -> Result<(IpPort, Option<OnionReturn>), Error> {
        let decrypted = open_precomputed(&self.payload, &self.nonce, symmetric_key)
            .map_err(|e| {
                debug!("Decrypting OnionReturn failed!");
                Error::new(ErrorKind::Other,
                    format!("OnionReturn decrypt error: {:?}", e))
            })?;
        match OnionReturn::inner_from_bytes(&decrypted) {
            IResult::Incomplete(e) => {
                error!(target: "Onion", "Inner onion return deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("Inner onion return deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                error!(target: "Onion", "Inner onion return deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("Inner onion return deserialize error: {:?}", e)))
            },
            IResult::Done(_, inner) => {
                Ok(inner)
            }
        }
    }
}

/// Represents the result of sent `AnnounceRequest`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsStored {
    /// Failed to announce ourselves or find requested node
    Failed = 0,
    /// Requested node is found by its long term `PublicKey`
    Found = 1,
    /// We successfully announced ourselves
    Announced = 2
}

impl FromBytes for IsStored {
    named!(from_bytes<IsStored>, switch!(le_u8,
        0 => value!(IsStored::Failed) |
        1 => value!(IsStored::Found) |
        2 => value!(IsStored::Announced)
    ));
}

impl ToBytes for IsStored {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        gen_be_u8!(buf, *self as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION_RETURN_1_PAYLOAD_SIZE: usize = ONION_RETURN_1_SIZE - NONCEBYTES;

    encode_decode_test!(
        ip_port_encode_decode,
        IpPort {
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        }
    );

    encode_decode_test!(
        onion_return_encode_decode,
        OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
        }
    );

    encode_decode_test!(is_stored_failed, IsStored::Failed);

    encode_decode_test!(is_stored_found, IsStored::Found);

    encode_decode_test!(is_stored_accounced, IsStored::Announced);

    #[test]
    fn onion_return_encrypt_decrypt() {
        let alice_symmetric_key = new_symmetric_key();
        let bob_symmetric_key = new_symmetric_key();
        // alice encrypt
        let ip_port_1 = IpPort {
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let onion_return_1 = OnionReturn::new(&alice_symmetric_key, &ip_port_1, None);
        // bob encrypt
        let ip_port_2 = IpPort {
            ip_addr: "7.8.5.6".parse().unwrap(),
            port: 54321
        };
        let onion_return_2 = OnionReturn::new(&bob_symmetric_key, &ip_port_2, Some(&onion_return_1));
        // bob can decrypt it's return address
        let (decrypted_ip_port_2, decrypted_onion_return_1) = onion_return_2.get_payload(&bob_symmetric_key).unwrap();
        assert_eq!(decrypted_ip_port_2, ip_port_2);
        assert_eq!(decrypted_onion_return_1.unwrap(), onion_return_1);
        // alice can decrypt it's return address
        let (decrypted_ip_port_1, none) = onion_return_1.get_payload(&alice_symmetric_key).unwrap();
        assert_eq!(decrypted_ip_port_1, ip_port_1);
        assert!(none.is_none());
    }

    #[test]
    fn onion_return_encrypt_decrypt_invalid_key() {
        let alice_symmetric_key = new_symmetric_key();
        let bob_symmetric_key = new_symmetric_key();
        let eve_symmetric_key = new_symmetric_key();
        // alice encrypt
        let ip_port_1 = IpPort {
            ip_addr: "5.6.7.8".parse().unwrap(),
            port: 12345
        };
        let onion_return_1 = OnionReturn::new(&alice_symmetric_key, &ip_port_1, None);
        // bob encrypt
        let ip_port_2 = IpPort {
            ip_addr: "7.8.5.6".parse().unwrap(),
            port: 54321
        };
        let onion_return_2 = OnionReturn::new(&bob_symmetric_key, &ip_port_2, Some(&onion_return_1));
        // eve can't decrypt return addresses
        assert!(onion_return_1.get_payload(&eve_symmetric_key).is_err());
        assert!(onion_return_2.get_payload(&eve_symmetric_key).is_err());
    }

    #[test]
    fn onion_return_decrypt_invalid() {
        let symmetric_key = new_symmetric_key();
        let nonce = gen_nonce();
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_onion_return = OnionReturn {
            nonce,
            payload: invalid_payload_encoded
        };
        assert!(invalid_onion_return.get_payload(&symmetric_key).is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_onion_return = OnionReturn {
            nonce,
            payload: invalid_payload_encoded
        };
        assert!(invalid_onion_return.get_payload(&symmetric_key).is_err());
    }
}
