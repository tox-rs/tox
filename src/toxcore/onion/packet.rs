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

use toxcore::binary_io_new::*;
use toxcore::crypto_core::*;

use nom::{be_u16, le_u8, le_u64, rest};
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

Serialized form:

Length                | Content
--------              | ------
`24`                  | `Nonce`
`35` or `94` or `153` | Payload

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

/** First onion request packet. It's sent from DHT node to the first node from
onion chain. Payload can be encrypted with either temporary generated
`SecretKey` or DHT `SecretKey` of sender and with DHT `PublicKey` of receiver.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x80`
`24`     | `Nonce`
`32`     | `PublicKey` of sender
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionRequest0 {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for OnionRequest0 {
    named!(from_bytes<OnionRequest0>, do_parse!(
        tag!(&[0x80][..]) >>
        nonce: call!(Nonce::from_bytes) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        payload: rest >>
        (OnionRequest0 {
            nonce,
            temporary_pk,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for OnionRequest0 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x80) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.payload)
        )
    }
}

/** Second onion request packet. It's sent from the first to the second node from
onion chain. Payload should be encrypted with temporary generated `SecretKey` and
with DHT `PublicKey` of receiver.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x81`
`24`     | `Nonce`
`32`     | Temporary `PublicKey`
variable | Payload
`59`     | `OnionReturn`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionRequest1 {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>,
    /// Return address encrypted by the first node from onion chain
    pub onion_return: OnionReturn
}

impl FromBytes for OnionRequest1 {
    named!(from_bytes<OnionRequest1>, do_parse!(
        tag!(&[0x81][..]) >>
        nonce: call!(Nonce::from_bytes) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        rest_len: rest_len >>
        payload: cond_reduce!(
            rest_len >= ONION_RETURN_1_SIZE,
            take!(rest_len - ONION_RETURN_1_SIZE)
        ) >>
        onion_return: call!(OnionReturn::from_bytes) >>
        (OnionRequest1 {
            nonce,
            temporary_pk,
            payload: payload.to_vec(),
            onion_return
        })
    ));
}

impl ToBytes for OnionRequest1 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x81) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.payload) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return)
        )
    }
}

/** Third onion request packet. It's sent from the second to the third node from
onion chain. Payload should be encrypted with temporary generated `SecretKey` and
with DHT `PublicKey` of receiver.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x82`
`24`     | `Nonce`
`32`     | Temporary `PublicKey`
variable | Payload
`118`    | `OnionReturn`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionRequest2 {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>,
    /// Return address encrypted by the second node from onion chain
    pub onion_return: OnionReturn
}

impl FromBytes for OnionRequest2 {
    named!(from_bytes<OnionRequest2>, do_parse!(
        tag!(&[0x82][..]) >>
        nonce: call!(Nonce::from_bytes) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        rest_len: rest_len >>
        payload: cond_reduce!(
            rest_len >= ONION_RETURN_2_SIZE,
            take!(rest_len - ONION_RETURN_2_SIZE)
        ) >>
        onion_return: call!(OnionReturn::from_bytes) >>
        (OnionRequest2 {
            nonce,
            temporary_pk,
            payload: payload.to_vec(),
            onion_return
        })
    ));
}

impl ToBytes for OnionRequest2 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x82) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.payload) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return)
        )
    }
}

/** Serialized form:

Length   | Content
-------- | ------
`1`      | `0x83`
`24`     | `Nonce`
`32`     | Temporary or real `PublicKey`
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InnerAnnounceRequest {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary or real `PublicKey` for the current encrypted payload
    pub pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for InnerAnnounceRequest {
    named!(from_bytes<InnerAnnounceRequest>, do_parse!(
        tag!(&[0x83][..]) >>
        nonce: call!(Nonce::from_bytes) >>
        pk: call!(PublicKey::from_bytes) >>
        payload: rest >>
        (InnerAnnounceRequest {
            nonce,
            pk,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for InnerAnnounceRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x83) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.payload)
        )
    }
}

/** Same as `InnerAnnounceRequest` but with `OnionReturn` addresses. It's sent
from the third node from onion chain to the destination node.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x83`
`24`     | `Nonce`
`32`     | Temporary or real `PublicKey`
variable | Payload
`177`    | `OnionReturn`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnounceRequest {
    /// Inner announce request that was enclosed in onion packets
    pub inner: InnerAnnounceRequest,
    /// Return address encrypted by the third node from onion chain
    pub onion_return: OnionReturn
}

impl FromBytes for AnnounceRequest {
    named!(from_bytes<AnnounceRequest>, do_parse!(
        rest_len: rest_len >>
        inner: cond_reduce!(
            rest_len >= ONION_RETURN_3_SIZE,
            flat_map!(take!(rest_len - ONION_RETURN_3_SIZE), InnerAnnounceRequest::from_bytes)
        ) >>
        onion_return: call!(OnionReturn::from_bytes) >>
        (AnnounceRequest { inner, onion_return })
    ));
}

impl ToBytes for AnnounceRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, inner| InnerAnnounceRequest::to_bytes(inner, buf), &self.inner) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return)
        )
    }
}

/** Serialized form:

Length   | Content
-------- | ------
`1`      | `0x85`
`32`     | `PublicKey` of destination node
`24`     | `Nonce`
`32`     | Temporary `PublicKey`
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InnerOnionDataRequest {
    /// `PublicKey` of destination node
    pub destination_pk: PublicKey,
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for InnerOnionDataRequest {
    named!(from_bytes<InnerOnionDataRequest>, do_parse!(
        tag!(&[0x85][..]) >>
        destination_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        payload: rest >>
        (InnerOnionDataRequest {
            destination_pk,
            nonce,
            temporary_pk,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for InnerOnionDataRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x85) >>
            gen_slice!(self.destination_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.payload)
        )
    }
}

/** Same as `InnerOnionDataRequest` but with `OnionReturn` addresses. It's sent
from the third node from onion chain to the destination node.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x85`
`32`     | `PublicKey` of destination node
`24`     | `Nonce`
`32`     | Temporary `PublicKey`
variable | Payload
`177`    | `OnionReturn`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionDataRequest {
    /// Inner onion data request that was enclosed in onion packets
    pub inner: InnerOnionDataRequest,
    /// Return address encrypted by the third node from onion chain
    pub onion_return: OnionReturn
}

impl FromBytes for OnionDataRequest {
    named!(from_bytes<OnionDataRequest>, do_parse!(
        rest_len: rest_len >>
        inner: cond_reduce!(
            rest_len >= ONION_RETURN_3_SIZE,
            flat_map!(take!(rest_len - ONION_RETURN_3_SIZE), InnerOnionDataRequest::from_bytes)
        ) >>
        onion_return: call!(OnionReturn::from_bytes) >>
        (OnionDataRequest { inner, onion_return })
    ));
}

impl ToBytes for OnionDataRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, inner| InnerOnionDataRequest::to_bytes(inner, buf), &self.inner) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return)
        )
    }
}

/** Serialized form:

Length   | Content
-------- | ------
`1`      | `0x86`
`24`     | `Nonce`
`32`     | Temporary `PublicKey`
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionDataResponse {
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for OnionDataResponse {
    named!(from_bytes<OnionDataResponse>, do_parse!(
        tag!(&[0x86][..]) >>
        nonce: call!(Nonce::from_bytes) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        payload: rest >>
        (OnionDataResponse {
            nonce,
            temporary_pk,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for OnionDataResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x86) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.payload)
        )
    }
}

/** Serialized form:

Length   | Content
-------- | ------
`1`      | `0x84`
`8`      | Data to send back in response
`24`     | `Nonce`
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnounceResponse {
    /// Data to send back in response
    pub sendback_data: u64,
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for AnnounceResponse {
    named!(from_bytes<AnnounceResponse>, do_parse!(
        tag!(&[0x84][..]) >>
        sendback_data: le_u64 >>
        nonce: call!(Nonce::from_bytes) >>
        payload: rest >>
        (AnnounceResponse {
            sendback_data,
            nonce,
            payload: payload.to_vec()
        })
    ));
}

impl ToBytes for AnnounceResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x84) >>
            gen_le_u64!(self.sendback_data) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload)
        )
    }
}

/** Third onion response packet. It's sent back from the destination node to the
third node from onion chain.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x8c`
`177`    | `OnionReturn`
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionResponse3 {
    /// Return address encrypted by the third node from onion chain
    pub onion_return: OnionReturn,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for OnionResponse3 {
    named!(from_bytes<OnionResponse3>, do_parse!(
        tag!(&[0x8c][..]) >>
        onion_return: flat_map!(take!(ONION_RETURN_3_SIZE), OnionReturn::from_bytes) >>
        payload: rest >>
        (OnionResponse3 { onion_return, payload: payload.to_vec() })
    ));
}

impl ToBytes for OnionResponse3 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x8c) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return) >>
            gen_slice!(self.payload)
        )
    }
}

/** Second onion response packet. It's sent back from the third to the second node
from onion chain.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x8d`
`118`    | `OnionReturn`
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionResponse2 {
    /// Return address encrypted by the second node from onion chain
    pub onion_return: OnionReturn,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for OnionResponse2 {
    named!(from_bytes<OnionResponse2>, do_parse!(
        tag!(&[0x8d][..]) >>
        onion_return: flat_map!(take!(ONION_RETURN_2_SIZE), OnionReturn::from_bytes) >>
        payload: rest >>
        (OnionResponse2 { onion_return, payload: payload.to_vec() })
    ));
}

impl ToBytes for OnionResponse2 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x8d) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return) >>
            gen_slice!(self.payload)
        )
    }
}

/** First onion response packet. It's sent back from the second to the first node
from onion chain.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x8e`
`59`     | `OnionReturn`
variable | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionResponse1 {
    /// Return address encrypted by the first node from onion chain
    pub onion_return: OnionReturn,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for OnionResponse1 {
    named!(from_bytes<OnionResponse1>, do_parse!(
        tag!(&[0x8e][..]) >>
        onion_return: flat_map!(take!(ONION_RETURN_1_SIZE), OnionReturn::from_bytes) >>
        payload: rest >>
        (OnionResponse1 { onion_return, payload: payload.to_vec() })
    ));
}

impl ToBytes for OnionResponse1 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x8e) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return) >>
            gen_slice!(self.payload)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION_RETURN_1_PAYLOAD_SIZE: usize = ONION_RETURN_1_SIZE - NONCEBYTES;
    const ONION_RETURN_2_PAYLOAD_SIZE: usize = ONION_RETURN_2_SIZE - NONCEBYTES;
    const ONION_RETURN_3_PAYLOAD_SIZE: usize = ONION_RETURN_3_SIZE - NONCEBYTES;

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

    encode_decode_test!(
        onion_request_0_encode_decode,
        OnionRequest0 {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42, 123]
        }
    );

    encode_decode_test!(
        onion_request_1_encode_decode,
        OnionRequest1 {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42, 123],
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
            }
        }
    );

    encode_decode_test!(
        onion_request_2_encode_decode,
        OnionRequest2 {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42, 123],
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
            }
        }
    );

    encode_decode_test!(
        inner_announce_request_encode_decode,
        InnerAnnounceRequest {
            nonce: gen_nonce(),
            pk: gen_keypair().0,
            payload: vec![42, 123]
        }
    );

    encode_decode_test!(
        announce_request_encode_decode,
        AnnounceRequest {
            inner: InnerAnnounceRequest {
                nonce: gen_nonce(),
                pk: gen_keypair().0,
                payload: vec![42, 123]
            },
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
            }
        }
    );

    encode_decode_test!(
        inner_onion_data_request_encode_decode,
        InnerOnionDataRequest {
            destination_pk: gen_keypair().0,
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42, 123]
        }
    );

    encode_decode_test!(
        onion_data_request_encode_decode,
        OnionDataRequest {
            inner: InnerOnionDataRequest {
                destination_pk: gen_keypair().0,
                nonce: gen_nonce(),
                temporary_pk: gen_keypair().0,
                payload: vec![42, 123]
            },
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
            }
        }
    );

    encode_decode_test!(
        onion_data_response_encode_decode,
        OnionDataResponse {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42, 123]
        }
    );

    encode_decode_test!(
        announce_response_encode_decode,
        AnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42, 123]
        }
    );

    encode_decode_test!(
        onion_response_3_encode_decode,
        OnionResponse3 {
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
            },
            payload: vec![42, 123]
        }
    );

    encode_decode_test!(
        onion_response_2_encode_decode,
        OnionResponse2 {
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
            },
            payload: vec![42, 123]
        }
    );

    encode_decode_test!(
        onion_response_1_encode_decode,
        OnionResponse1 {
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
            },
            payload: vec![42, 123]
        }
    );

    #[test]
    fn onion_return_encrypt_decrypt() {
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
    fn onion_return_decrypt_invalid() {
        let symmetric_key = new_symmetric_key();
        let nonce = gen_nonce();
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_onion_return = OnionReturn {
            nonce: nonce,
            payload: invalid_payload_encoded
        };
        assert!(invalid_onion_return.get_payload(&symmetric_key).is_err());
        // Try short incomplete
        let invalid_payload = [2];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_onion_return = OnionReturn {
            nonce: nonce,
            payload: invalid_payload_encoded
        };
        assert!(invalid_onion_return.get_payload(&symmetric_key).is_err());
    }
}
