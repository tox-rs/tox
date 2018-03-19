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

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::dht::packed_node::PackedNode;

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

where payload is encrypted [`OnionRequest0Payload`](./struct.OnionRequest0Payload.html)

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

impl OnionRequest0 {
    /// Create new `OnionRequest0` object.
    pub fn new(shared_secret: &PrecomputedKey, temporary_pk: &PublicKey, payload: OnionRequest0Payload) -> OnionRequest0 {
        let nonce = gen_nonce();
        let mut buf = [0; ONION_MAX_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        OnionRequest0 { nonce, temporary_pk: *temporary_pk, payload }
    }

    /** Decrypt payload and try to parse it as `OnionRequest0Payload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `OnionRequest0Payload`
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<OnionRequest0Payload, Error> {
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|e| {
                debug!("Decrypting OnionRequest0 failed!");
                Error::new(ErrorKind::Other,
                    format!("OnionRequest0 decrypt error: {:?}", e))
            })?;
        match OnionRequest0Payload::from_bytes(&decrypted) {
            IResult::Incomplete(e) => {
                error!(target: "Onion", "OnionRequest0Payload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("OnionRequest0Payload deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                error!(target: "Onion", "OnionRequest0Payload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("OnionRequest0Payload deserialize error: {:?}", e)))
            },
            IResult::Done(_, inner) => {
                Ok(inner)
            }
        }
    }
}

/** Unencrypted payload of `OnionRequest0` packet.

Inner payload should be sent to the next node with address from `ip_port` field.

Serialized form:

Length   | Content
-------- | ------
`19`     | `IpPort` of the next node
`32`     | Temporary `PublicKey`
variable | Payload

where payload is encrypted [`OnionRequest1Payload`](./struct.OnionRequest1Payload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionRequest0Payload {
    /// Address of the next node in the onion path
    pub ip_port: IpPort,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Inner onion payload
    pub inner: Vec<u8>
}

impl FromBytes for OnionRequest0Payload{
    named!(from_bytes<OnionRequest0Payload>, do_parse!(
        ip_port: call!(IpPort::from_bytes) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        inner: rest >>
        (OnionRequest0Payload {
            ip_port,
            temporary_pk,
            inner: inner.to_vec()
        })
    ));
}

impl ToBytes for OnionRequest0Payload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, ip_port| IpPort::to_bytes(ip_port, buf), &self.ip_port) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.inner)
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

where payload is encrypted [`OnionRequest1Payload`](./struct.OnionRequest1Payload.html)

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

impl OnionRequest1 {
    /// Create new `OnionRequest1` object.
    pub fn new(shared_secret: &PrecomputedKey, temporary_pk: &PublicKey, payload: OnionRequest1Payload, onion_return: OnionReturn) -> OnionRequest1 {
        let nonce = gen_nonce();
        let mut buf = [0; ONION_MAX_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        OnionRequest1 { nonce, temporary_pk: *temporary_pk, payload, onion_return }
    }

    /** Decrypt payload and try to parse it as `OnionRequest1Payload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `OnionRequest1Payload`
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<OnionRequest1Payload, Error> {
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|e| {
                debug!("Decrypting OnionRequest1 failed!");
                Error::new(ErrorKind::Other,
                    format!("OnionRequest1 decrypt error: {:?}", e))
            })?;
        match OnionRequest1Payload::from_bytes(&decrypted) {
            IResult::Incomplete(e) => {
                error!(target: "Onion", "OnionRequest1Payload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("OnionRequest1Payload deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                error!(target: "Onion", "OnionRequest1Payload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("OnionRequest1Payload deserialize error: {:?}", e)))
            },
            IResult::Done(_, inner) => {
                Ok(inner)
            }
        }
    }
}

/** Unencrypted payload of `OnionRequest1` packet.

Inner payload should be sent to the next node with address from `ip_port` field.

Serialized form:

Length   | Content
-------- | ------
`19`     | `IpPort` of the next node
`32`     | Temporary `PublicKey`
variable | Payload

where payload is encrypted [`OnionRequest2Payload`](./struct.OnionRequest2Payload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionRequest1Payload {
    /// Address of the next node in the onion path
    pub ip_port: IpPort,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Inner onion payload
    pub inner: Vec<u8>
}

impl FromBytes for OnionRequest1Payload {
    named!(from_bytes<OnionRequest1Payload>, do_parse!(
        ip_port: call!(IpPort::from_bytes) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        inner: rest >>
        (OnionRequest1Payload {
            ip_port,
            temporary_pk,
            inner: inner.to_vec()
        })
    ));
}

impl ToBytes for OnionRequest1Payload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, ip_port| IpPort::to_bytes(ip_port, buf), &self.ip_port) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.inner)
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

where payload is encrypted [`OnionRequest2Payload`](./struct.OnionRequest2Payload.html)

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

impl OnionRequest2 {
    /// Create new `OnionRequest2` object.
    pub fn new(shared_secret: &PrecomputedKey, temporary_pk: &PublicKey, payload: OnionRequest2Payload, onion_return: OnionReturn) -> OnionRequest2 {
        let nonce = gen_nonce();
        let mut buf = [0; ONION_MAX_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        OnionRequest2 { nonce, temporary_pk: *temporary_pk, payload, onion_return }
    }

    /** Decrypt payload and try to parse it as `OnionRequest2Payload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `OnionRequest2Payload`
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<OnionRequest2Payload, Error> {
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|e| {
                debug!("Decrypting OnionRequest2 failed!");
                Error::new(ErrorKind::Other,
                    format!("OnionRequest2 decrypt error: {:?}", e))
            })?;
        match OnionRequest2Payload::from_bytes(&decrypted) {
            IResult::Incomplete(e) => {
                error!(target: "Onion", "OnionRequest2Payload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("OnionRequest2Payload deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                error!(target: "Onion", "OnionRequest2Payload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("OnionRequest2Payload deserialize error: {:?}", e)))
            },
            IResult::Done(_, inner) => {
                Ok(inner)
            }
        }
    }
}

/** Unencrypted payload of `OnionRequest1` packet.

Inner payload should be sent as DHT packet to the next node with address from
`ip_port` field.

Serialized form:

Length   | Content
-------- | ------
`19`     | `IpPort` of the next node
`32`     | Temporary `PublicKey`
variable | Payload

where payload is encrypted [`InnerOnionRequest`](./struct.InnerOnionRequest.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionRequest2Payload {
    /// Address of the next node in the onion path
    pub ip_port: IpPort,
    /// Inner onion request
    pub inner: InnerOnionRequest
}

impl FromBytes for OnionRequest2Payload {
    named!(from_bytes<OnionRequest2Payload>, do_parse!(
        ip_port: call!(IpPort::from_bytes) >>
        inner: call!(InnerOnionRequest::from_bytes) >>
        eof!() >>
        (OnionRequest2Payload {
            ip_port,
            inner
        })
    ));
}

impl ToBytes for OnionRequest2Payload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, ip_port| IpPort::to_bytes(ip_port, buf), &self.ip_port) >>
            gen_call!(|buf, inner| InnerOnionRequest::to_bytes(inner, buf), &self.inner)
        )
    }
}

/** Onion requests that can be enclosed in onion packets and sent through onion
path.

Onion allows only two types of packets to be sent as a request through onion
paths: `AnnounceRequest` and `OnionDataRequest`.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InnerOnionRequest {
    /// [`InnerAnnounceRequest`](./struct.InnerAnnounceRequest.html) structure.
    InnerAnnounceRequest(InnerAnnounceRequest),
    /// [`InnerOnionDataRequest`](./struct.InnerOnionDataRequest.html) structure.
    InnerOnionDataRequest(InnerOnionDataRequest)
}

impl ToBytes for InnerOnionRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            InnerOnionRequest::InnerAnnounceRequest(ref inner) => inner.to_bytes(buf),
            InnerOnionRequest::InnerOnionDataRequest(ref inner) => inner.to_bytes(buf),
        }
    }
}

impl FromBytes for InnerOnionRequest {
    named!(from_bytes<InnerOnionRequest>, alt!(
        map!(InnerAnnounceRequest::from_bytes, InnerOnionRequest::InnerAnnounceRequest) |
        map!(InnerOnionDataRequest::from_bytes, InnerOnionRequest::InnerOnionDataRequest)
    ));
}

/** It's used for announcing ourselves to onion node and for looking for other
announced nodes.

If we want to announce ourselves we should send one `AnnounceRequest` packet with
PingId set to 0 to acquire correct PingId of onion node. Then using this PingId
we can send another `AnnounceRequest` to be added to onion nodes list. If
`AnnounceRequest` succeed we will get `AnnounceResponse` with is_stored set to 2.
Otherwise is_stored will be set to 0.

If we are looking for another node we should send `AnnounceRequest` packet with
PingId set to 0 and with `PublicKey` of this node. If node is found we will get
`AnnounceResponse` with is_stored set to 1. Otherwise is_stored will be set to 0.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x83`
`24`     | `Nonce`
`32`     | Temporary or real `PublicKey`
variable | Payload

where payload is encrypted [`AnnounceRequestPayload`](./struct.AnnounceRequestPayload.html)

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

impl InnerAnnounceRequest {
    /// Create new `InnerAnnounceRequest` object.
    pub fn new(shared_secret: &PrecomputedKey, pk: &PublicKey, payload: AnnounceRequestPayload) -> InnerAnnounceRequest {
        let nonce = gen_nonce();
        let mut buf = [0; ONION_MAX_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        InnerAnnounceRequest { nonce, pk: *pk, payload }
    }

    /** Decrypt payload and try to parse it as `AnnounceRequestPayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `AnnounceRequestPayload`
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<AnnounceRequestPayload, Error> {
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|e| {
                debug!("Decrypting AnnounceRequest failed!");
                Error::new(ErrorKind::Other,
                    format!("AnnounceRequest decrypt error: {:?}", e))
            })?;
        match AnnounceRequestPayload::from_bytes(&decrypted) {
            IResult::Incomplete(e) => {
                error!(target: "Onion", "AnnounceRequestPayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("AnnounceRequestPayload deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                error!(target: "Onion", "AnnounceRequestPayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("AnnounceRequestPayload deserialize error: {:?}", e)))
            },
            IResult::Done(_, inner) => {
                Ok(inner)
            }
        }
    }
}

/** Same as `InnerAnnounceRequest` but with `OnionReturn` addresses. It's sent
from the third node from onion chain to the destination node.

See [`InnerAnnounceRequest`](./struct.InnerAnnounceRequest.html) for additional docs.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x83`
`24`     | `Nonce`
`32`     | Temporary or real `PublicKey`
variable | Payload
`177`    | `OnionReturn`

where payload is encrypted [`AnnounceRequestPayload`](./struct.AnnounceRequestPayload.html)

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

/** Unencrypted payload of `AnnounceRequest` packet.

Serialized form:

Length   | Content
-------- | ------
`32`     | Onion ping id
`32`     | `PublicKey` we are searching for
`32`     | `PublicKey` that should be used for sending data packets
`8`      | Data to send back in the response

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnounceRequestPayload {
    /// Onion ping id
    pub ping_id: Digest,
    /// `PublicKey` we are searching for
    pub search_pk: PublicKey,
    /// `PublicKey` that should be used for sending data packets
    pub data_pk: PublicKey,
    /// Data to send back in the response
    pub sendback_data: u64
}

impl FromBytes for AnnounceRequestPayload {
    named!(from_bytes<AnnounceRequestPayload>, do_parse!(
        ping_id: call!(Digest::from_bytes) >>
        search_pk: call!(PublicKey::from_bytes) >>
        data_pk: call!(PublicKey::from_bytes) >>
        sendback_data: le_u64 >>
        eof!() >>
        (AnnounceRequestPayload { ping_id, search_pk, data_pk, sendback_data })
    ));
}

impl ToBytes for AnnounceRequestPayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.ping_id.as_ref()) >>
            gen_slice!(self.search_pk.as_ref()) >>
            gen_slice!(self.data_pk.as_ref()) >>
            gen_le_u64!(self.sendback_data)
        )
    }
}

/** It's used to send data requests to dht node using onion paths.

When DHT node receives `OnionDataRequest` it sends `OnionDataResponse` to
destination node for which data request is intended. Thus, data request will
go through 7 intermediate nodes until destination node gets it - 3 nodes with
OnionRequests, onion node that handles `OnionDataRequest` and 3 nodes with
OnionResponses.

Serialized form:

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

See [`InnerOnionDataRequest`](./struct.InnerOnionDataRequest.html) for additional docs.

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

/** When onion node receives `OnionDataRequest` packet it converts it to
`OnionDataResponse` and sends to destination node if it announced itself
and is contained in onion nodes list.

Serialized form:

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

/** It's used to respond to AnnounceRequest packet.

sendback_data is the data from `AnnounceRequest` that should be sent in the
response as is. It's used in onion client to match onion response with sent
request.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x84`
`8`      | Data to send back in response
`24`     | `Nonce`
variable | Payload

where payload is encrypted [`AnnounceResponsePayload`](./struct.AnnounceResponsePayload.html)

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

impl AnnounceResponse {
    /// Create new `AnnounceResponse` object.
    pub fn new(shared_secret: &PrecomputedKey, sendback_data: u64, payload: AnnounceResponsePayload) -> AnnounceResponse {
        let nonce = gen_nonce();
        let mut buf = [0; ONION_MAX_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        AnnounceResponse { sendback_data, nonce, payload }
    }

    /** Decrypt payload and try to parse it as `AnnounceResponsePayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `AnnounceResponsePayload`
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<AnnounceResponsePayload, Error> {
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|e| {
                debug!("Decrypting AnnounceResponse failed!");
                Error::new(ErrorKind::Other,
                    format!("AnnounceResponse decrypt error: {:?}", e))
            })?;
        match AnnounceResponsePayload::from_bytes(&decrypted) {
            IResult::Incomplete(e) => {
                error!(target: "Onion", "AnnounceResponsePayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("AnnounceResponsePayload deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                error!(target: "Onion", "AnnounceResponsePayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("AnnounceResponsePayload deserialize error: {:?}", e)))
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

/** Unencrypted payload of `AnnounceResponse` packet.

is_stored variable contains the result of sent request. It might have values:

* 0: failed to announce ourselves or find requested node
* 1: requested node is found by its long term `PublicKey`
* 2: we successfully announced ourselves

In case of is_stored is equal to 1 ping_id will contain `PublicKey` that
should be used to send data packets to the requested node. In other cases it
will contain ping id that should be used for announcing ourselves.

Serialized form:

Length   | Content
-------- | ------
`1`      | `is_stored`
`32`     | Onion ping id or `PublicKey`
`[0, 204]` | Nodes in packed format

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnounceResponsePayload {
    /// Variable that represents result of sent `AnnounceRequest`
    pub is_stored: IsStored,
    /// Onion ping id or PublicKey that should be used to send data packets
    pub ping_id_or_pk: Digest,
    /// Up to 4 closest to the requested PublicKey DHT nodes
    pub nodes: Vec<PackedNode>
}

#[allow(unused_comparisons)]
impl FromBytes for AnnounceResponsePayload {
    named!(from_bytes<AnnounceResponsePayload>, do_parse!(
        is_stored: call!(IsStored::from_bytes) >>
        ping_id_or_pk: call!(Digest::from_bytes) >>
        nodes: many_m_n!(0, 4, PackedNode::from_bytes) >>
        eof!() >>
        (AnnounceResponsePayload {
            is_stored,
            ping_id_or_pk,
            nodes
        })
    ));
}

impl ToBytes for AnnounceResponsePayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, is_stored| IsStored::to_bytes(is_stored, buf), &self.is_stored) >>
            gen_slice!(self.ping_id_or_pk.as_ref()) >>
            gen_cond!(
                self.nodes.len() <= 4,
                gen_many_ref!(&self.nodes, |buf, node| PackedNode::to_bytes(node, buf))
            )
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

where payload is encrypted [`AnnounceResponse`](./struct.AnnounceResponse.html) or
[`OnionDataResponse`](./struct.OnionDataResponse.html)

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

where payload is encrypted [`AnnounceResponse`](./struct.AnnounceResponse.html) or
[`OnionDataResponse`](./struct.OnionDataResponse.html)

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

where payload is encrypted [`AnnounceResponse`](./struct.AnnounceResponse.html) or
[`OnionDataResponse`](./struct.OnionDataResponse.html)

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

    use std::net::SocketAddr;

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
        onion_request_0_payload_encode_decode,
        OnionRequest0Payload {
            ip_port: IpPort {
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            temporary_pk: gen_keypair().0,
            inner: vec![42, 123]
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
        onion_request_1_payload_encode_decode,
        OnionRequest1Payload {
            ip_port: IpPort {
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            temporary_pk: gen_keypair().0,
            inner: vec![42, 123]
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
        onion_request_2_payload_encode_decode,
        OnionRequest2Payload {
            ip_port: IpPort {
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            inner: InnerOnionRequest::InnerOnionDataRequest(InnerOnionDataRequest {
                destination_pk: gen_keypair().0,
                nonce: gen_nonce(),
                temporary_pk: gen_keypair().0,
                payload: vec![42, 123]
            })
        }
    );

    encode_decode_test!(
        inner_announce_request_encode_decode,
        InnerOnionRequest::InnerAnnounceRequest(InnerAnnounceRequest {
            nonce: gen_nonce(),
            pk: gen_keypair().0,
            payload: vec![42, 123]
        })
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
        announce_request_payload_encode_decode,
        AnnounceRequestPayload {
            ping_id: hash(&[1, 2, 3]),
            search_pk: gen_keypair().0,
            data_pk: gen_keypair().0,
            sendback_data: 12345
        }
    );

    encode_decode_test!(
        inner_onion_data_request_encode_decode,
        InnerOnionRequest::InnerOnionDataRequest(InnerOnionDataRequest {
            destination_pk: gen_keypair().0,
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42, 123]
        })
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
        announce_response_payload_encode_decode,
        AnnounceResponsePayload {
            is_stored: IsStored::Found,
            ping_id_or_pk: hash(&[1, 2, 3]),
            nodes: vec![
                PackedNode::new(false, SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &gen_keypair().0)
            ]
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
    fn onion_request_0_payload_encrypt_decrypt() {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = OnionRequest0Payload {
            ip_port: IpPort {
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            temporary_pk: gen_keypair().0,
            inner: vec![42, 123]
        };
        // encode payload with shared secret
        let onion_packet = OnionRequest0::new(&shared_secret, &alice_pk, payload.clone());
        // decode payload with bob's secret key
        let decoded_payload = onion_packet.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn onion_request_1_payload_encrypt_decrypt() {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = OnionRequest1Payload {
            ip_port: IpPort {
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            temporary_pk: gen_keypair().0,
            inner: vec![42, 123]
        };
        let onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
        };
        // encode payload with shared secret
        let onion_packet = OnionRequest1::new(&shared_secret, &alice_pk, payload.clone(), onion_return);
        // decode payload with bob's secret key
        let decoded_payload = onion_packet.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn onion_request_2_payload_encrypt_decrypt() {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = OnionRequest2Payload {
            ip_port: IpPort {
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            inner: InnerOnionRequest::InnerOnionDataRequest(InnerOnionDataRequest {
                destination_pk: gen_keypair().0,
                nonce: gen_nonce(),
                temporary_pk: gen_keypair().0,
                payload: vec![42, 123]
            })
        };
        let onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
        };
        // encode payload with shared secret
        let onion_packet = OnionRequest2::new(&shared_secret, &alice_pk, payload.clone(), onion_return);
        // decode payload with bob's secret key
        let decoded_payload = onion_packet.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn announce_request_payload_encrypt_decrypt() {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = AnnounceRequestPayload {
            ping_id: hash(&[1, 2, 3]),
            search_pk: gen_keypair().0,
            data_pk: gen_keypair().0,
            sendback_data: 12345
        };
        // encode payload with shared secret
        let onion_packet = InnerAnnounceRequest::new(&shared_secret, &alice_pk, payload.clone());
        // decode payload with bob's secret key
        let decoded_payload = onion_packet.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn announce_response_payload_encrypt_decrypt() {
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = AnnounceResponsePayload {
            is_stored: IsStored::Found,
            ping_id_or_pk: hash(&[1, 2, 3]),
            nodes: vec![
                PackedNode::new(false, SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &gen_keypair().0)
            ]
        };
        // encode payload with shared secret
        let onion_packet = AnnounceResponse::new(&shared_secret, 12345, payload.clone());
        // decode payload with bob's secret key
        let decoded_payload = onion_packet.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
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
    fn onion_request_0_payload_encrypt_decrypt_invalid_key() {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = OnionRequest0Payload {
            ip_port: IpPort {
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            temporary_pk: gen_keypair().0,
            inner: vec![42, 123]
        };
        // encode payload with shared secret
        let onion_packet = OnionRequest0::new(&shared_secret, &alice_pk, payload.clone());
        // try to decode payload with eve's secret key
        let eve_shared_secret = encrypt_precompute(&bob_pk, &eve_sk);
        let decoded_payload = onion_packet.get_payload(&eve_shared_secret);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn onion_request_1_payload_encrypt_decrypt_invalid_key() {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = OnionRequest1Payload {
            ip_port: IpPort {
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            temporary_pk: gen_keypair().0,
            inner: vec![42, 123]
        };
        let onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
        };
        // encode payload with shared secret
        let onion_packet = OnionRequest1::new(&shared_secret, &alice_pk, payload.clone(), onion_return);
        // try to decode payload with eve's secret key
        let eve_shared_secret = encrypt_precompute(&bob_pk, &eve_sk);
        let decoded_payload = onion_packet.get_payload(&eve_shared_secret);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn onion_request_2_payload_encrypt_decrypt_invalid_key() {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = OnionRequest2Payload {
            ip_port: IpPort {
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345
            },
            inner: InnerOnionRequest::InnerOnionDataRequest(InnerOnionDataRequest {
                destination_pk: gen_keypair().0,
                nonce: gen_nonce(),
                temporary_pk: gen_keypair().0,
                payload: vec![42, 123]
            })
        };
        let onion_return = OnionReturn {
            nonce: gen_nonce(),
            payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
        };
        // encode payload with shared secret
        let onion_packet = OnionRequest2::new(&shared_secret, &alice_pk, payload.clone(), onion_return);
        // try to decode payload with eve's secret key
        let eve_shared_secret = encrypt_precompute(&bob_pk, &eve_sk);
        let decoded_payload = onion_packet.get_payload(&eve_shared_secret);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn announce_request_payload_encrypt_decrypt_invalid_key() {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = AnnounceRequestPayload {
            ping_id: hash(&[1, 2, 3]),
            search_pk: gen_keypair().0,
            data_pk: gen_keypair().0,
            sendback_data: 12345
        };
        // encode payload with shared secret
        let onion_packet = InnerAnnounceRequest::new(&shared_secret, &alice_pk, payload.clone());
        // try to decode payload with eve's secret key
        let eve_shared_secret = encrypt_precompute(&bob_pk, &eve_sk);
        let decoded_payload = onion_packet.get_payload(&eve_shared_secret);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn announce_response_payload_encrypt_decrypt_invalid_key() {
        let (_alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let payload = AnnounceResponsePayload {
            is_stored: IsStored::Found,
            ping_id_or_pk: hash(&[1, 2, 3]),
            nodes: vec![
                PackedNode::new(false, SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &gen_keypair().0)
            ]
        };
        // encode payload with shared secret
        let onion_packet = AnnounceResponse::new(&shared_secret, 12345, payload.clone());
        // try to decode payload with eve's secret key
        let eve_shared_secret = encrypt_precompute(&bob_pk, &eve_sk);
        let decoded_payload = onion_packet.get_payload(&eve_shared_secret);
        assert!(decoded_payload.is_err());
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

    #[test]
    fn onion_request_0_decrypt_invalid() {
        let symmetric_key = new_symmetric_key();
        let nonce = gen_nonce();
        let temporary_pk = gen_keypair().0;
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_onion_request_0 = OnionRequest0 {
            nonce,
            temporary_pk,
            payload: invalid_payload_encoded
        };
        assert!(invalid_onion_request_0.get_payload(&symmetric_key).is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_onion_request_0 = OnionRequest0 {
            nonce,
            temporary_pk,
            payload: invalid_payload_encoded
        };
        assert!(invalid_onion_request_0.get_payload(&symmetric_key).is_err());
    }

    #[test]
    fn onion_request_1_decrypt_invalid() {
        let symmetric_key = new_symmetric_key();
        let nonce = gen_nonce();
        let temporary_pk = gen_keypair().0;
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_onion_request_1 = OnionRequest1 {
            nonce,
            temporary_pk,
            payload: invalid_payload_encoded,
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
            }
        };
        assert!(invalid_onion_request_1.get_payload(&symmetric_key).is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_onion_request_1 = OnionRequest1 {
            nonce,
            temporary_pk,
            payload: invalid_payload_encoded,
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
            }
        };
        assert!(invalid_onion_request_1.get_payload(&symmetric_key).is_err());
    }

    #[test]
    fn onion_request_2_decrypt_invalid() {
        let symmetric_key = new_symmetric_key();
        let nonce = gen_nonce();
        let temporary_pk = gen_keypair().0;
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_onion_request_2 = OnionRequest2 {
            nonce,
            temporary_pk,
            payload: invalid_payload_encoded,
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
            }
        };
        assert!(invalid_onion_request_2.get_payload(&symmetric_key).is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_onion_request_2 = OnionRequest2 {
            nonce,
            temporary_pk,
            payload: invalid_payload_encoded,
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
            }
        };
        assert!(invalid_onion_request_2.get_payload(&symmetric_key).is_err());
    }

    #[test]
    fn announce_request_decrypt_invalid() {
        let symmetric_key = new_symmetric_key();
        let nonce = gen_nonce();
        let pk = gen_keypair().0;
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_announce_request = InnerAnnounceRequest {
            nonce,
            pk,
            payload: invalid_payload_encoded
        };
        assert!(invalid_announce_request.get_payload(&symmetric_key).is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_announce_request = InnerAnnounceRequest {
            nonce,
            pk,
            payload: invalid_payload_encoded
        };
        assert!(invalid_announce_request.get_payload(&symmetric_key).is_err());
    }

    #[test]
    fn announce_response_decrypt_invalid() {
        let symmetric_key = new_symmetric_key();
        let nonce = gen_nonce();
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_announce_response = AnnounceResponse {
            sendback_data: 12345,
            nonce,
            payload: invalid_payload_encoded
        };
        assert!(invalid_announce_response.get_payload(&symmetric_key).is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &symmetric_key);
        let invalid_announce_response = AnnounceResponse {
            sendback_data: 12345,
            nonce,
            payload: invalid_payload_encoded
        };
        assert!(invalid_announce_response.get_payload(&symmetric_key).is_err());
    }
}
