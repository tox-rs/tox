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

/*! DHT packet part of the toxcore.
    * takes care of the serializing and de-serializing DHT packets
*/

use nom::{le_u8, be_u64, rest};

use std::io::{Error, ErrorKind};

use toxcore::binary_io_new::*;
use toxcore::crypto_core::*;
use toxcore::dht_new::packed_node::PackedNode;
use toxcore::onion::packet::*;

/// Length in bytes of [`PingRequest`](./struct.PingRequest.html) and
/// [`PingResponse`](./struct.PingResponse.html) when serialized into bytes.
pub const PING_SIZE: usize = 9;

/** DHT packet enum that encapsulates all types of DHT packets.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DhtPacket {
    /// [`PingRequest`](./struct.PingRequest.html) structure.
    PingRequest(PingRequest),
    /// [`PingResponse`](./struct.PingResponse.html) structure.
    PingResponse(PingResponse),
    /// [`NodesRequest`](./struct.NodesRequest.html) structure.
    NodesRequest(NodesRequest),
    /// [`NodesResponse`](./struct.NodesResponse.html) structure.
    NodesResponse(NodesResponse),
    // TODO: CookieRequest
    // TODO: CookieResponse
    // TODO: CryptoHandshake
    // TODO: CryptoData
    /// [`DhtRequest`](./struct.DhtRequest.html) structure.
    DhtRequest(DhtRequest),
    // TODO: LanDiscovery
    /// [`OnionRequest0`](../onion/struct.OnionRequest0.html) structure.
    OnionRequest0(OnionRequest0),
    /// [`OnionRequest1`](../onion/struct.OnionRequest1.html) structure.
    OnionRequest1(OnionRequest1),
    /// [`OnionRequest2`](../onion/struct.OnionRequest2.html) structure.
    OnionRequest2(OnionRequest2),
    /// [`AnnounceRequest`](../onion/struct.AnnounceRequest.html) structure.
    AnnounceRequest(AnnounceRequest),
    /// [`AnnounceResponse`](../onion/struct.AnnounceResponse.html) structure.
    AnnounceResponse(AnnounceResponse),
    /// [`OnionDataRequest`](../onion/struct.OnionDataRequest.html) structure.
    OnionDataRequest(OnionDataRequest),
    /// [`OnionDataResponse`](../onion/struct.OnionDataResponse.html) structure.
    OnionDataResponse(OnionDataResponse),
    /// [`OnionResponse3`](../onion/struct.OnionResponse3.html) structure.
    OnionResponse3(OnionResponse3),
    /// [`OnionResponse2`](../onion/struct.OnionResponse2.html) structure.
    OnionResponse2(OnionResponse2),
    /// [`OnionResponse1`](../onion/struct.OnionResponse1.html) structure.
    OnionResponse1(OnionResponse1),
    // TODO: BootstrapInfo
}

impl ToBytes for DhtPacket {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            DhtPacket::PingRequest(ref p) => p.to_bytes(buf),
            DhtPacket::PingResponse(ref p) => p.to_bytes(buf),
            DhtPacket::NodesRequest(ref p) => p.to_bytes(buf),
            DhtPacket::NodesResponse(ref p) => p.to_bytes(buf),
            DhtPacket::DhtRequest(ref p) => p.to_bytes(buf),
            DhtPacket::OnionRequest0(ref p) => p.to_bytes(buf),
            DhtPacket::OnionRequest1(ref p) => p.to_bytes(buf),
            DhtPacket::OnionRequest2(ref p) => p.to_bytes(buf),
            DhtPacket::AnnounceRequest(ref p) => p.to_bytes(buf),
            DhtPacket::AnnounceResponse(ref p) => p.to_bytes(buf),
            DhtPacket::OnionDataRequest(ref p) => p.to_bytes(buf),
            DhtPacket::OnionDataResponse(ref p) => p.to_bytes(buf),
            DhtPacket::OnionResponse3(ref p) => p.to_bytes(buf),
            DhtPacket::OnionResponse2(ref p) => p.to_bytes(buf),
            DhtPacket::OnionResponse1(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for DhtPacket {
    named!(from_bytes<DhtPacket>, alt!(
        map!(PingRequest::from_bytes, DhtPacket::PingRequest) |
        map!(PingResponse::from_bytes, DhtPacket::PingResponse) |
        map!(NodesRequest::from_bytes, DhtPacket::NodesRequest) |
        map!(NodesResponse::from_bytes, DhtPacket::NodesResponse) |
        map!(DhtRequest::from_bytes, DhtPacket::DhtRequest) |
        map!(OnionRequest0::from_bytes, DhtPacket::OnionRequest0) |
        map!(OnionRequest1::from_bytes, DhtPacket::OnionRequest1) |
        map!(OnionRequest2::from_bytes, DhtPacket::OnionRequest2) |
        map!(AnnounceRequest::from_bytes, DhtPacket::AnnounceRequest) |
        map!(AnnounceResponse::from_bytes, DhtPacket::AnnounceResponse) |
        map!(OnionDataRequest::from_bytes, DhtPacket::OnionDataRequest) |
        map!(OnionDataResponse::from_bytes, DhtPacket::OnionDataResponse) |
        map!(OnionResponse3::from_bytes, DhtPacket::OnionResponse3) |
        map!(OnionResponse2::from_bytes, DhtPacket::OnionResponse2) |
        map!(OnionResponse1::from_bytes, DhtPacket::OnionResponse1)
    ));
}

/** Ping request packet struct. Every 60 seconds DHT node sends `PingRequest`
packet to peers to check whether it is alive. When `PingRequest` is received
DHT node should respond with `PingResponse` that contains the same ping id
inside it's encrypted payload as it got from `PingRequest`. If `PingResponse`
doesn't arrive for 122 seconds the DHT node removes peer from kbucket and marks
it as offline if the peer is known friend.

https://zetok.github.io/tox-spec/#dht-packet
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PingRequest {
    /// public key used for payload encryption
    pub pk: PublicKey,
    /// one time serial number
    pub nonce: Nonce,
    /// encrypted payload
    pub payload: Vec<u8>,
}

impl ToBytes for PingRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x00) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl FromBytes for PingRequest {
    named!(from_bytes<PingRequest>, do_parse!(
        tag!("\x00") >>
        pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        payload: map!(rest, |bytes| bytes.to_vec() ) >>
        (PingRequest {
            pk: pk,
            nonce: nonce,
            payload: payload
        })
    ));
}

impl PingRequest {
    /** Decrypt payload and try to parse it as `PingRequestPayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as given packet type
    */
    pub fn get_payload(&self, own_secret_key: &SecretKey) -> Result<PingRequestPayload, Error> {
        debug!(target: "PingRequest", "Getting packet data from PingRequest.");
        trace!(target: "PingRequest", "With PingRequest: {:?}", self);
        let decrypted = open(&self.payload, &self.nonce, &self.pk, own_secret_key)
            .map_err(|e| {
                debug!("Decrypting PingRequest failed!");
                Error::new(ErrorKind::Other,
                    format!("PingRequest decrypt error: {:?}", e))
            })?;

        match PingRequestPayload::from_bytes(&decrypted) {
            IResult::Incomplete(e) => {
                error!(target: "PingRequest", "PingRequestPayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("PingRequestPayload deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                error!(target: "PingRequest", "PingRequestPayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("PingRequestPayload deserialize error: {:?}", e)))
            },
            IResult::Done(_, payload) => {
                Ok(payload)
            }
        }
    }
}

/**
Used to request/respond to ping. Used in an encrypted form. Request id is used
for resistance against replay attacks.

Serialized form:

Ping Packet (request and response)

Packet type `0x00` for request.

Response ID must match ID of the request, otherwise ping is invalid.

Length      | Contents
----------- | --------
`1`         | 0x00
`8`         | Ping ID

Serialized form should be put in the encrypted part of `PingRequest` packet.

[`PingResponsePayload`](./struct.PingResponsePayload.html) can only be created as a response
to [`PingRequestPayload`](./struct.PingRequestPayload.html).
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PingRequestPayload {
    /// Request ping id
    pub id: u64,
}

impl FromBytes for PingRequestPayload {
    named!(from_bytes<PingRequestPayload>, do_parse!(
        tag!("\x00") >>
        id: be_u64 >>
        eof!() >>
        (PingRequestPayload { id: id})
    ));
}

impl ToBytes for PingRequestPayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x00) >>
            gen_be_u64!(self.id)
        )
    }
}

/** Ping response packet struct. When `PingRequest` is received DHT node should
respond with `PingResponse` that contains the same ping id inside it's encrypted
payload as it got from `PingRequest`.

https://zetok.github.io/tox-spec/#dht-packet
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PingResponse {
    /// public key used for payload encryption
    pub pk: PublicKey,
    /// one time serial number
    pub nonce: Nonce,
    /// encrypted payload
    pub payload: Vec<u8>,
}

impl ToBytes for PingResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x01) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl FromBytes for PingResponse {
    named!(from_bytes<PingResponse>, do_parse!(
        tag!("\x01") >>
        pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        payload: map!(rest, |bytes| bytes.to_vec() ) >>
        (PingResponse {
            pk: pk,
            nonce: nonce,
            payload: payload
        })
    ));
}

impl PingResponse {
    /** Decrypt payload and try to parse it as `PingResponsePayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as given packet type
    */
    pub fn get_payload(&self, own_secret_key: &SecretKey) -> Result<PingResponsePayload, Error> {
        debug!(target: "PingResponse", "Getting packet data from PingResponse.");
        trace!(target: "PingResponse", "With PingResponse: {:?}", self);
        let decrypted = open(&self.payload, &self.nonce, &self.pk, own_secret_key)
            .map_err(|e| {
                debug!("Decrypting PingResponse failed!");
                Error::new(ErrorKind::Other,
                    format!("PingResponse decrypt error: {:?}", e))
            })?;

        match PingResponsePayload::from_bytes(&decrypted) {
            IResult::Incomplete(e) => {
                error!(target: "PingResponse", "PingResponsePayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("PingResponsePayload deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                error!(target: "PingResponse", "PingRequestPayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("PingResponsePayload deserialize error: {:?}", e)))
            },
            IResult::Done(_, payload) => {
                Ok(payload)
            }
        }
    }
}

/**
Used to request/respond to ping. Used in an encrypted form. Request id is used
for resistance against replay attacks.

Serialized form:

Ping Packet (request and response)

Packet type `0x01` for response.

Response ID must match ID of the request, otherwise ping is invalid.

Length      | Contents
----------- | --------
`1`         | 0x01
`8`         | Ping ID

Serialized form should be put in the encrypted part of `PingResponse` packet.

[`PingResponsePayload`](./struct.PingResponsePayload.html) can only be created as a response
to [`PingRequestPayload`](./struct.PingRequestPayload.html).
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PingResponsePayload {
    /// Ping id same as requested from PingRequest
    pub id: u64,
}

impl FromBytes for PingResponsePayload {
    named!(from_bytes<PingResponsePayload>, do_parse!(
        tag!("\x01") >>
        id: be_u64 >>
        eof!() >>
        (PingResponsePayload { id: id })
    ));
}

impl ToBytes for PingResponsePayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x01) >>
            gen_be_u64!(self.id)
        )
    }
}

/** Nodes request packet struct. It's used to get up to 4 closest nodes to
requested public key. Every 20 seconds DHT node sends `NodesRequest` packet to
a random node in kbucket and its known friends list.

https://zetok.github.io/tox-spec/#dht-packet
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodesRequest {
    /// public key used for payload encryption
    pub pk: PublicKey,
    /// one time serial number
    pub nonce: Nonce,
    /// encrypted payload
    pub payload: Vec<u8>,
}

impl ToBytes for NodesRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x02) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl FromBytes for NodesRequest {
    named!(from_bytes<NodesRequest>, do_parse!(
        tag!("\x02") >>
        pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        payload: map!(rest, |bytes| bytes.to_vec() ) >>
        (NodesRequest {
            pk: pk,
            nonce: nonce,
            payload: payload
        })
    ));
}

impl NodesRequest {
    /** Decrypt payload and try to parse it as `NodesRequestPayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as given packet type
    */
    pub fn get_payload(&self, own_secret_key: &SecretKey) -> Result<NodesRequestPayload, Error> {
        debug!(target: "NodesRequest", "Getting packet data from NodesRequest.");
        trace!(target: "NodesRequest", "With NodesRequest: {:?}", self);
        let decrypted = open(&self.payload, &self.nonce, &self.pk, own_secret_key)
            .map_err(|e| {
                debug!("Decrypting NodesRequest failed!");
                Error::new(ErrorKind::Other,
                    format!("NodesRequest decrypt error: {:?}", e))
            })?;

        match NodesRequestPayload::from_bytes(&decrypted) {
            IResult::Incomplete(e) => {
                error!(target: "NodesRequest", "NodesRequestPayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("NodesRequestPayload deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                error!(target: "NodesRequest", "PingRequestPayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("NodesRequestPayload deserialize error: {:?}", e)))
            },
            IResult::Done(_, payload) => {
                Ok(payload)
            }
        }
    }
}

/** Request to get address of given DHT PK, or nodes that are closest in DHT
to the given PK. Request id is used for resistance against replay attacks.

Serialized form:

Length | Content
------ | ------
`32`   | DHT Public Key
`8`    | Request ID

Serialized form should be put in the encrypted part of `NodesRequest` packet.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NodesRequestPayload {
    /// Public Key of the DHT node `NodesRequestPayload` is supposed to get address of.
    pub pk: PublicKey,
    /// An ID of the request.
    pub id: u64,
}

impl ToBytes for NodesRequestPayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.pk.as_ref()) >>
            gen_be_u64!(self.id)
        )
    }
}

impl FromBytes for NodesRequestPayload {
    named!(from_bytes<NodesRequestPayload>, do_parse!(
        pk: call!(PublicKey::from_bytes) >>
        id: be_u64 >>
        eof!() >>
        (NodesRequestPayload { pk: pk, id: id })
    ));
}

/** Nodes response packet struct. When DHT node receives `NodesRequest` it
should respond with `NodesResponse` that contains up to to 4 closest nodes to
requested public key. Ping id should be the same as it was in `NodesRequest`.

https://zetok.github.io/tox-spec/#dht-packet
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodesResponse {
    /// public key used for payload encryption
    pub pk: PublicKey,
    /// one time serial number
    pub nonce: Nonce,
    /// encrypted payload
    pub payload: Vec<u8>,
}

impl ToBytes for NodesResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x04) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl FromBytes for NodesResponse {
    named!(from_bytes<NodesResponse>, do_parse!(
        tag!("\x04") >>
        pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        payload: map!(rest, |bytes| bytes.to_vec() ) >>
        (NodesResponse {
            pk: pk,
            nonce: nonce,
            payload: payload
        })
    ));
}

impl NodesResponse {
    /** Decrypt payload and try to parse it as `NodesResponsePayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as given packet type
    */
    pub fn get_payload(&self, own_secret_key: &SecretKey) -> Result<NodesResponsePayload, Error> {
        debug!(target: "NodesResponse", "Getting packet data from NodesResponse.");
        trace!(target: "NodesResponse", "With NodesResponse: {:?}", self);
        let decrypted = open(&self.payload, &self.nonce, &self.pk, own_secret_key)
            .map_err(|e| {
                debug!("Decrypting NodesResponse failed!");
                Error::new(ErrorKind::Other,
                    format!("NodesResponse decrypt error: {:?}", e))
            })?;

        match NodesResponsePayload::from_bytes(&decrypted) {
            IResult::Incomplete(e) => {
                error!(target: "NodesResponse", "NodesResponsePayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("NodesResponsePayload deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                error!(target: "NodesResponse", "PingRequestPayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("NodesResponsePayload deserialize error: {:?}", e)))
            },
            IResult::Done(_, payload) => {
                Ok(payload)
            }
        }
    }
}

/** Response to [`NodesRequest`](./struct.NodesRequest.html) request, containing up to
`4` nodes closest to the requested node. Request id is used for resistance against
replay attacks.

Serialized form:

Length      | Contents
----------- | --------
`1`         | Number of packed nodes (maximum 4)
`[39, 204]` | Nodes in packed format
`8`         | Request ID

An IPv4 node is 39 bytes, an IPv6 node is 51 bytes, so the maximum size is
`51 * 4 = 204` bytes.

Serialized form should be put in the encrypted part of `NodesResponse` packet.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodesResponsePayload {
    /** Nodes sent in response to [`NodesRequest`](./struct.NodesRequest.html) request.

    There can be only 1 to 4 nodes in `NodesResponsePayload`.
    */
    pub nodes: Vec<PackedNode>,
    /// request id
    pub id: u64,
}

impl ToBytes for NodesResponsePayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_cond!(
                !self.nodes.is_empty() && self.nodes.len() <= 4,
                gen_be_u8!(self.nodes.len() as u8)
            ) >>
            gen_many_ref!(&self.nodes, |buf, node| PackedNode::to_bytes(node, buf)) >>
            gen_be_u64!(self.id)
        )
    }
}

impl FromBytes for NodesResponsePayload {
    named!(from_bytes<NodesResponsePayload>, do_parse!(
        nodes_number: le_u8 >>
        nodes: cond_reduce!(
            nodes_number > 0 && nodes_number <= 4,
            count!(PackedNode::from_bytes, nodes_number as usize)
        ) >>
        id: be_u64 >>
        eof!() >>
        (NodesResponsePayload {
            nodes: nodes,
            id: id,
        })
    ));
}

/** DHT Request packet struct.

https://zetok.github.io/tox-spec/#dht-request-packets
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtRequest {
    /// receiver public key
    pub rpk: PublicKey,
    /// sender public key
    pub spk: PublicKey,
    /// one time serial number
    pub nonce: Nonce,
    /// payload of DhtRequest packet
    pub payload: Vec<u8>,
}

impl ToBytes for DhtRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x20) >>
            gen_slice!(self.rpk.as_ref()) >>
            gen_slice!(self.spk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl FromBytes for DhtRequest {
    named!(from_bytes<DhtRequest>, do_parse!(
        tag!("\x20") >>
        rpk: call!(PublicKey::from_bytes) >>
        spk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        payload: map!(rest, |bytes| bytes.to_vec() ) >>
        (DhtRequest {
            rpk: rpk,
            spk: spk,
            nonce: nonce,
            payload: payload
        })
    ));
}

impl DhtRequest {
    /**
    Decrypt payload and try to parse it as packet type.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as given packet type
    */
    pub fn get_payload(&self, own_secret_key: &SecretKey) -> Result<DhtRequestPayload, Error>
    {
        debug!(target: "DhtRequest", "Getting packet data from DhtRequest.");
        trace!(target: "DhtRequest", "With DhtRequest: {:?}", self);
        let decrypted = open(&self.payload, &self.nonce, &self.spk,
                            own_secret_key)
            .map_err(|e| {
                debug!("Decrypting DhtRequest failed!");
                Error::new(ErrorKind::Other,
                    format!("DhtRequest decrypt error: {:?}", e))
            });

        match DhtRequestPayload::from_bytes(&decrypted?) {
            IResult::Incomplete(e) => {
                error!(target: "DhtRequest", "DhtRequest deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("DhtRequest deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                error!(target: "DhtRequest", "DhtRequest deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("DhtRequest deserialize error: {:?}", e)))
            },
            IResult::Done(_, packet) => {
                Ok(packet)
            }
        }
    }
}

/** Standart DHT Request packet that embedded in the payload of
[`DhtRequest`](./struct.DhtRequest.html)..

https://zetok.github.io/tox-spec/#dht-request-packets
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DhtRequestPayload {
    /// [`NatPingRequest`](./struct.NatPingRequest.html) structure.
    NatPingRequest(NatPingRequest),
    /// [`NatPingResponse`](./struct.NatPingResponse.html) structure.
    NatPingResponse(NatPingResponse),
}

impl ToBytes for DhtRequestPayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            DhtRequestPayload::NatPingRequest(ref p) => p.to_bytes(buf),
            DhtRequestPayload::NatPingResponse(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for DhtRequestPayload {
    named!(from_bytes<DhtRequestPayload>, alt!(
        map!(NatPingRequest::from_bytes, DhtRequestPayload::NatPingRequest) |
        map!(NatPingResponse::from_bytes, DhtRequestPayload::NatPingResponse)
    ));
}

/** NatPing request of DHT Request packet.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NatPingRequest {
    /// Request ping id
    pub id: u64,
}

impl FromBytes for NatPingRequest {
    named!(from_bytes<NatPingRequest>, do_parse!(
        tag!(&[0xfe][..]) >>
        tag!("\x00") >>
        id: be_u64 >>
        (NatPingRequest { id: id})
    ));
}

impl ToBytes for NatPingRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0xfe) >>
            gen_be_u8!(0x00) >>
            gen_be_u64!(self.id)
        )
    }
}

/** NatPing response of DHT Request packet.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NatPingResponse {
    /// Ping id same as requested from PingRequest
    pub id: u64,
}

impl FromBytes for NatPingResponse {
    named!(from_bytes<NatPingResponse>, do_parse!(
        tag!(&[0xfe][..]) >>
        tag!("\x01") >>
        id: be_u64 >>
        (NatPingResponse { id: id})
    ));
}

impl ToBytes for NatPingResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0xfe) >>
            gen_be_u8!(0x01) >>
            gen_be_u64!(self.id)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use toxcore::dht_new::codec::*;

    use quickcheck::{Arbitrary, Gen, quickcheck};

    impl PingRequest {
        pub fn new(shared_secret: &PrecomputedKey, pk: &PublicKey, payload: PingRequestPayload) -> PingRequest {
            let nonce = &gen_nonce();
            let mut buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
            let payload = seal_precomputed(&buf[..size] , nonce, shared_secret);

            PingRequest {
                pk: *pk,
                nonce: *nonce,
                payload: payload,
            }
        }
    }

    impl PingResponse {
        pub fn new(shared_secret: &PrecomputedKey, pk: &PublicKey, payload: PingResponsePayload) -> PingResponse {
            let nonce = &gen_nonce();
            let mut buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
            let payload = seal_precomputed(&buf[..size] , nonce, shared_secret);

            PingResponse {
                pk: *pk,
                nonce: *nonce,
                payload: payload,
            }
        }
    }

    impl NodesRequest {
        pub fn new(shared_secret: &PrecomputedKey, pk: &PublicKey, payload: NodesRequestPayload) -> NodesRequest {
            let nonce = &gen_nonce();
            let mut buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
            let payload = seal_precomputed(&buf[..size] , nonce, shared_secret);

            NodesRequest {
                pk: *pk,
                nonce: *nonce,
                payload: payload,
            }
        }
    }

    impl NodesResponse {
        pub fn new(shared_secret: &PrecomputedKey, pk: &PublicKey, payload: NodesResponsePayload) -> NodesResponse {
            let nonce = &gen_nonce();
            let mut buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
            let payload = seal_precomputed(&buf[..size] , nonce, shared_secret);

            NodesResponse {
                pk: *pk,
                nonce: *nonce,
                payload: payload,
            }
        }
    }

    impl DhtRequest {
        /// create new DhtRequest object
        pub fn new(shared_secret: &PrecomputedKey, rpk: &PublicKey, spk: &PublicKey, dp: DhtRequestPayload) -> DhtRequest {
            let nonce = &gen_nonce();

            let mut buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, size) = dp.to_bytes((&mut buf, 0)).unwrap();
            let payload = seal_precomputed(&buf[..size], nonce, shared_secret);

            DhtRequest {
                rpk: *rpk,
                spk: *spk,
                nonce: *nonce,
                payload: payload,
            }
        }
    }

    impl PingRequestPayload {
        /// Create new ping request with a randomly generated `request id`.
        pub fn new() -> Self {
            trace!("Creating new Ping.");
            PingRequestPayload { id: random_u64() }
        }

        /// An ID of the request / response.
        pub fn id(&self) -> u64 {
            self.id
        }
    }

    impl PingResponsePayload {
        /// An ID of the request / response.
        pub fn id(&self) -> u64 {
            self.id
        }
    }

    impl NatPingRequest {
        /// Create new ping request with a randomly generated `request id`.
        pub fn new() -> Self {
            trace!("Creating new Ping.");
            NatPingRequest { id: random_u64() }
        }

        /// An ID of the request / response.
        pub fn id(&self) -> u64 {
            self.id
        }
    }

    impl From<PingRequestPayload> for PingResponsePayload {
        fn from(p: PingRequestPayload) -> Self {
            PingResponsePayload { id: p.id }
        }
    }

    impl From<NatPingRequest> for NatPingResponse {
        fn from(p: NatPingRequest) -> Self {
            NatPingResponse { id: p.id }
        }
    }

    impl Arbitrary for DhtPacket {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let choice = g.gen_range(0, 5);
            match choice {
                0 => DhtPacket::PingRequest(PingRequest::arbitrary(g)),
                1 => DhtPacket::PingResponse(PingResponse::arbitrary(g)),
                2 => DhtPacket::NodesRequest(NodesRequest::arbitrary(g)),
                3 => DhtPacket::NodesResponse(NodesResponse::arbitrary(g)),
                4 => DhtPacket::DhtRequest(DhtRequest::arbitrary(g)),
                _ => unreachable!("Arbitrary for DhtPacket - should not have happened!")
            }
        }
    }

    macro_rules! dht_packet_arbitrary (
        ($packet:ident, $payload:ident) => (
            impl Arbitrary for $packet {
                fn arbitrary<G: Gen>(g: &mut G) -> Self {
                    let (pk, sk) = gen_keypair();  // "sender" keypair
                    let (r_pk, _) = gen_keypair();  // receiver PK
                    let precomputed = encrypt_precompute(&r_pk, &sk);
                    $packet::new(&precomputed, &pk, $payload::arbitrary(g))
                }
            }
        )
    );

    dht_packet_arbitrary!(PingRequest, PingRequestPayload);

    dht_packet_arbitrary!(PingResponse, PingResponsePayload);

    dht_packet_arbitrary!(NodesRequest, NodesRequestPayload);

    dht_packet_arbitrary!(NodesResponse, NodesResponsePayload);

    impl Arbitrary for DhtRequest {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let (pk, sk) = gen_keypair();  // "sender" keypair
            let (r_pk, _) = gen_keypair();  // receiver PK
            let precomputed = encrypt_precompute(&r_pk, &sk);
            DhtRequest::new(&precomputed, &r_pk, &pk, DhtRequestPayload::arbitrary(g))
        }
    }

    impl Arbitrary for DhtRequestPayload {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let choice = g.gen_range(0, 2);
            if choice == 0 {
                DhtRequestPayload::NatPingRequest(NatPingRequest::arbitrary(g))
            } else {
                DhtRequestPayload::NatPingResponse(NatPingResponse::arbitrary(g))
            }
        }
    }

    impl Arbitrary for PingRequestPayload {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            PingRequestPayload {
                id: g.gen()
            }
        }
    }

    impl Arbitrary for PingResponsePayload {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            PingResponsePayload {
                id: g.gen()
            }
        }
    }

    impl Arbitrary for NodesRequestPayload {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let mut a: [u8; PUBLICKEYBYTES] = [0; PUBLICKEYBYTES];
            g.fill_bytes(&mut a);
            NodesRequestPayload { pk: PublicKey(a), id: g.gen() }
        }
    }

    impl Arbitrary for NodesResponsePayload {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let nodes = vec![Arbitrary::arbitrary(g); g.gen_range(1, 4)];
            let id = g.gen();
            NodesResponsePayload { nodes: nodes, id: id }
        }
    }

    impl Arbitrary for NatPingRequest {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            NatPingRequest {
                id: g.gen()
            }
        }
    }

    impl Arbitrary for NatPingResponse {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            NatPingResponse {
                id: g.gen()
            }
        }
    }

    #[test]
    fn ping_request_payload_check() {
        fn with_payload(payload: PingRequestPayload) {
            let mut buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, len) = payload.to_bytes((&mut buf, 0)).ok().unwrap();
            let (_, decoded) = PingRequestPayload::from_bytes(&buf[..len]).unwrap();
            assert_eq!(decoded, payload);
        }
        quickcheck(with_payload as fn(PingRequestPayload));
    }

    #[test]
    fn ping_response_payload_check() {
        fn with_payload(payload: PingResponsePayload) {
            let mut buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, len) = payload.to_bytes((&mut buf, 0)).ok().unwrap();
            let (_, decoded) = PingResponsePayload::from_bytes(&buf[..len]).unwrap();
            assert_eq!(decoded, payload);
        }
        quickcheck(with_payload as fn(PingResponsePayload));
    }

    #[test]
    fn nodes_request_payload_check() {
        fn with_payload(payload: NodesRequestPayload) {
            let mut buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, len) = payload.to_bytes((&mut buf, 0)).ok().unwrap();
            let (_, decoded) = NodesRequestPayload::from_bytes(&buf[..len]).unwrap();
            assert_eq!(decoded, payload);
        }
        quickcheck(with_payload as fn(NodesRequestPayload));
    }

    #[test]
    fn nodes_response_payload_check() {
        fn with_payload(payload: NodesResponsePayload) {
            let mut buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, len) = payload.to_bytes((&mut buf, 0)).ok().unwrap();
            let (_, decoded) = NodesResponsePayload::from_bytes(&buf[..len]).unwrap();
            assert_eq!(decoded, payload);
        }
        quickcheck(with_payload as fn(NodesResponsePayload));
    }

    #[test]
    fn dht_request_payload_check() {
        fn with_payload(payload: DhtRequestPayload) {
            let mut buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, len) = payload.to_bytes((&mut buf, 0)).ok().unwrap();
            let (_, decoded) = DhtRequestPayload::from_bytes(&buf[..len]).unwrap();
            assert_eq!(decoded, payload);
        }
        quickcheck(with_payload as fn(DhtRequestPayload));
    }

    #[test]
    fn dht_packet_check() {
        fn with_packet(packet: DhtPacket) {
            let mut buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, len) = packet.to_bytes((&mut buf, 0)).ok().unwrap();
            let (_, decoded) = DhtPacket::from_bytes(&buf[..len]).unwrap();
            assert_eq!(decoded, packet);
        }
        quickcheck(with_packet as fn(DhtPacket));
    }

    encode_decode_test!(
        ping_request_payload_encode_decode,
        PingRequestPayload { id: 42 }
    );

    encode_decode_test!(
        ping_response_payload_encode_decode,
        PingResponsePayload { id: 42 }
    );

    encode_decode_test!(
        nodes_request_payload_encode_decode,
        NodesRequestPayload { pk: gen_keypair().0, id: 42 }
    );

    encode_decode_test!(
        nodes_response_payload_encode_decode,
        NodesResponsePayload { nodes: vec![
            PackedNode::new(false, SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &gen_keypair().0)
        ], id: 42 }
    );

    macro_rules! dht_packet_encode_decode (
        ($test:ident, $packet:ident) => (
            encode_decode_test!(
                $test,
                $packet {
                    pk: gen_keypair().0,
                    nonce: gen_nonce(),
                    payload: vec![42; 123],
                }
            );
        )
    );

    dht_packet_encode_decode!(ping_request_encode_decode, PingRequest);

    dht_packet_encode_decode!(ping_response_encode_decode, PingResponse);

    dht_packet_encode_decode!(nodes_request_encode_decode, NodesRequest);

    dht_packet_encode_decode!(nodes_response_encode_decode, NodesResponse);

    encode_decode_test!(
        nat_ping_request_payload_encode_decode,
        DhtRequestPayload::NatPingRequest(NatPingRequest { id: 42 })
    );

    encode_decode_test!(
        nat_ping_response_payload_encode_decode,
        DhtRequestPayload::NatPingResponse(NatPingResponse { id: 42 })
    );

    encode_decode_test!(
        dht_request_encode_decode,
        DhtRequest {
            rpk: gen_keypair().0,
            spk: gen_keypair().0,
            nonce: gen_nonce(),
            payload: vec![42; 123],
        }
    );

    macro_rules! dht_packet_encrypt_decrypt (
        ($test:ident, $packet:ident, $payload:expr) => (
            #[test]
            fn $test() {
                let (alice_pk, alice_sk) = gen_keypair();
                let (bob_pk, bob_sk) = gen_keypair();
                let (_eve_pk, eve_sk) = gen_keypair();
                let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
                let payload = $payload;
                // encode payload with shared secret
                let dht_packet = $packet::new(&shared_secret, &alice_pk, payload.clone());
                // try to decode payload with eve's secret key
                let decoded_payload = dht_packet.get_payload(&eve_sk);
                assert!(decoded_payload.is_err());
                // decode payload with bob's secret key
                let decoded_payload = dht_packet.get_payload(&bob_sk).unwrap();
                // payloads should be equal
                assert_eq!(decoded_payload, payload);
            }
        )
    );

    dht_packet_encrypt_decrypt!(
        ping_request_payload_encrypt_decrypt,
        PingRequest,
        PingRequestPayload { id: 42 }
    );

    dht_packet_encrypt_decrypt!(
        ping_response_payload_encrypt_decrypt,
        PingResponse,
        PingResponsePayload { id: 42 }
    );

    dht_packet_encrypt_decrypt!(
        nodes_request_payload_encrypt_decrypt,
        NodesRequest,
        NodesRequestPayload { pk: gen_keypair().0, id: 42 }
    );

    dht_packet_encrypt_decrypt!(
        nodes_response_payload_encrypt_decrypt,
        NodesResponse,
        NodesResponsePayload { nodes: vec![
            PackedNode::new(false, SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &gen_keypair().0)
        ], id: 42 }
    );

    #[test]
    fn dht_request_payload_encrypt_decrypt() {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let test_payloads = vec![
            DhtRequestPayload::NatPingRequest(NatPingRequest { id: 42 }),
            DhtRequestPayload::NatPingResponse(NatPingResponse { id: 42 })
        ];
        for payload in test_payloads {
            // encode payload with shared secret
            let dht_request = DhtRequest::new(&shared_secret, &bob_pk, &alice_pk, payload.clone());
            // try to decode payload with eve's secret key
            let decoded_payload = dht_request.get_payload(&eve_sk);
            assert!(decoded_payload.is_err());
            // decode payload with bob's secret key
            let decoded_payload = dht_request.get_payload(&bob_sk).unwrap();
            // payloads should be equal
            assert_eq!(decoded_payload, payload);
        }
    }

    macro_rules! dht_packet_decode_invalid (
        ($test:ident, $packet:ident) => (
            #[test]
            fn $test() {
                let (alice_pk, alice_sk) = gen_keypair();
                let (bob_pk, bob_sk) = gen_keypair();
                let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
                let nonce = gen_nonce();
                // Try long invalid array
                let invalid_payload = [42; 123];
                let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
                let invalid_packet = $packet {
                    pk: alice_pk,
                    nonce: nonce,
                    payload: invalid_payload_encoded
                };
                let decoded_payload = invalid_packet.get_payload(&bob_sk);
                assert!(decoded_payload.is_err());
                // Try short incomplete
                let invalid_payload = [0x00];
                let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
                let invalid_packet = $packet {
                    pk: alice_pk,
                    nonce: nonce,
                    payload: invalid_payload_encoded
                };
                let decoded_payload = invalid_packet.get_payload(&bob_sk);
                assert!(decoded_payload.is_err());
            }
        );
    );

    dht_packet_decode_invalid!(ping_request_decode_invalid, PingRequest);

    dht_packet_decode_invalid!(ping_response_decode_invalid, PingResponse);

    dht_packet_decode_invalid!(nodes_request_decode_invalid, NodesRequest);

    dht_packet_decode_invalid!(nodes_response_decode_invalid, NodesResponse);

    #[test]
    fn dht_request_decode_invalid() {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_packet = DhtRequest {
            rpk: bob_pk,
            spk: alice_pk,
            nonce: nonce,
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&bob_sk);
        assert!(decoded_payload.is_err());
        // Try short incomplete
        let invalid_payload = [0xfe];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_packet = DhtRequest {
            rpk: bob_pk,
            spk: alice_pk,
            nonce: nonce,
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&bob_sk);
        assert!(decoded_payload.is_err());
    }
}
