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

/*
    Packet structure

    first class                         second class
    ------------------------+--------------------------------------------
    PingRequest             +    ----------------------
    PingResponse            +    | this 4 first class packet is also
    GetNodes                + <--| grouped as DhtPacket
    SendNodes               +    ----------------------
    ------------------------+--------------------------------------------
    DhtRequest              +    NatPingRequest and NatPingResponse
    ------------------------+--------------------------------------------
*/

/*! DHT packet part of the toxcore.
    * takes care of the serializing and de-serializing DHT packets
*/

use nom::{le_u8, be_u64, rest};

use std::io::{Error, ErrorKind};

use toxcore::binary_io_new::*;
use toxcore::crypto_core::*;
use toxcore::dht_new::packet_kind::*;
use toxcore::dht_new::packed_node::PackedNode;

/// Length in bytes of [`PingRequest`](./struct.PingRequest.html) and
/// [`PingResponse`](./struct.PingResponse.html) when serialized into bytes.
pub const PING_SIZE: usize = 9;

/** DHT packet base enum that encapsulates
[`DhtPacket`](./struct.DhtPacket.html) or [`DhtRequest`](./struct.DhtRequest.html).

https://zetok.github.io/tox-spec/#dht-packet
https://zetok.github.io/tox-spec/#dht-request-packets
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DhtBase {
    /// DhtBase are wrapper for DhtPacket and DhtRequest
    DhtPacket(DhtPacket),
    /// DhtBase are wrapper for DhtPacket and DhtRequest
    DhtRequest(DhtRequest),
}

/** DHT packet struct that encapsulates in the payload
[`DhtPacketPayload`](./enum.DhtPacketPayload.html).

https://zetok.github.io/tox-spec/#dht-packet
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtPacket {
    /// first class packet kind
    pub packet_kind: PacketKind,
    /// Public Key of Request Packet
    pub pk: PublicKey,
    /// one time serial number
    pub nonce : Nonce,
    /// payload of DhtPacket
    pub payload: Vec<u8>,
}

/** DHT Request packet struct.

https://zetok.github.io/tox-spec/#dht-request-packets
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtRequest {
    /// receiver publik key
    pub rpk: PublicKey,
    /// sender publick key
    pub spk: PublicKey,
    /// one time serial number
    pub nonce: Nonce,
    /// payload of DhtRequest packet
    pub payload: Vec<u8>,
}

/** Standard DHT packet that embedded in the payload of
[`DhtPacket`](./struct.DhtPacket.html).

https://zetok.github.io/tox-spec/#dht-packet
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DhtPacketPayload {
    /// [`PingRequest`](./struct.PingRequest.html) structure.
    PingRequest(PingRequest),
    /// [`PingResponse`](./struct.PingResponse.html) structure.
    PingResponse(PingResponse),
    /// [`GetNodes`](./struct.GetNodes.html) structure.
    GetNodes(GetNodes),
    /// [`SendNodes`](./struct.SendNodes.html) structure.
    SendNodes(SendNodes),
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


impl ToBytes for DhtBase {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            DhtBase::DhtPacket(ref p) => p.to_bytes(buf),
            DhtBase::DhtRequest(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for DhtBase {
    named!(from_bytes<DhtBase>, alt!(
        map!(DhtPacket::from_bytes, DhtBase::DhtPacket) |
        map!(DhtRequest::from_bytes, DhtBase::DhtRequest)
    ));
}

impl ToBytes for DhtPacket {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(self.packet_kind as u8) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl FromBytes for DhtPacket {
    named!(from_bytes<DhtPacket>, do_parse!(
        packet_kind: verify!(call!(PacketKind::from_bytes), |packet_type| match packet_type {
            PacketKind::PingRequest | PacketKind::PingResponse |
            PacketKind::GetNodes | PacketKind::SendNodes => true,
            _ => false
        }) >>
        pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        payload: map!(rest, |bytes| bytes.to_vec() ) >>
        (DhtPacket {
            packet_kind: packet_kind,
            pk: pk,
            nonce: nonce,
            payload: payload
        })
    ));
}

impl DhtPacket {
    /**
    Decrypt payload and try to parse it as packet type.

    To get info about it's packet type use
    [`.kind()`](./struct.DhtPacket.html#method.kind) method.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as given packet type
    */
    pub fn get_payload(&self, own_secret_key: &SecretKey) -> Result<DhtPacketPayload, Error>
    {
        debug!(target: "DhtPacket", "Getting packet data from DhtPacket.");
        trace!(target: "DhtPacket", "With DhtPacket: {:?}", self);
        let decrypted = open(&self.payload, &self.nonce, &self.pk,
                            own_secret_key)
            .map_err(|e| {
                debug!("Decrypting DhtPacket failed!");
                Error::new(ErrorKind::Other,
                    format!("DhtPacket decrypt error: {:?}", e))
            });

        match DhtPacketPayload::from_bytes(&decrypted?, self.packet_kind) {
            IResult::Incomplete(e) => {
                error!(target: "DhtPacket", "DhtPacket deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("DhtPacket deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                error!(target: "DhtPacket", "DhtPacket deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("DhtPacket deserialize error: {:?}", e)))
            },
            IResult::Done(_, packet) => {
                Ok(packet)
            }
        }
    }
}

impl ToBytes for DhtPacketPayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            DhtPacketPayload::PingRequest(ref p) => p.to_bytes(buf),
            DhtPacketPayload::PingResponse(ref p) => p.to_bytes(buf),
            DhtPacketPayload::GetNodes(ref p) => p.to_bytes(buf),
            DhtPacketPayload::SendNodes(ref p) => p.to_bytes(buf),
        }
    }
}

#[allow(unused_variables)]
impl DhtPacketPayload {
    named_args!(from_bytes_inner(packet_type: PacketKind) <Self>, switch!(value!(packet_type),
        PacketKind::PingRequest => map!(PingRequest::from_bytes, DhtPacketPayload::PingRequest) |
        PacketKind::PingResponse => map!(PingResponse::from_bytes, DhtPacketPayload::PingResponse) |
        PacketKind::GetNodes => map!(GetNodes::from_bytes, DhtPacketPayload::GetNodes) |
        PacketKind::SendNodes => map!(SendNodes::from_bytes, DhtPacketPayload::SendNodes)
    ));
    /** Deserialize `DhtPacketPayload` struct using `nom` from raw bytes.
    Note that this function is not an implementation of `FromBytes` trait
    since it takes additional parameter.
    */
    pub fn from_bytes(i: &[u8], packet_type: PacketKind) -> IResult<&[u8], Self> {
        DhtPacketPayload::from_bytes_inner(i, packet_type)
    }
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
        packet_type: verify!(call!(PacketKind::from_bytes), |packet_type| match packet_type {
            PacketKind::DhtRequest => true,
            _ => false
        }) >>
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

/**
Used to request/respond to ping. Used in an encrypted form.

Used in:

- [`DhtPacket`](./struct.DhtPacket.html)
- [`DhtRequest`](./struct.DhtRequest.html)

Serialized form:

Ping Packet (request and response)

Packet type `0x00` for request.

Response ID must match ID of the request, otherwise ping is invalid.

Length      | Contents
----------- | --------
`1`         | 0x00
`8`         | Ping ID

Serialized form should be put in the encrypted part of DHT packet.

[`PingResponse`](./struct.PingResponse.html) can only be created as a response
to [`PingRequest`](./struct.PingRequest.html).
*/

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PingRequest {
    /// Request ping id
    pub id: u64,
}

impl FromBytes for PingRequest {
    named!(from_bytes<PingRequest>, do_parse!(
        tag!("\x00") >>
        id: be_u64 >>
        (PingRequest { id: id})
    ));
}

impl ToBytes for PingRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x00) >>
            gen_be_u64!(self.id)
        )
    }
}

/**
Used to request/respond to ping. Used in an encrypted form.

Used in:

- [`DhtPacket`](./struct.DhtPacket.html)
- [`DhtRequest`](./struct.DhtRequest.html)

Serialized form:

Ping Packet (request and response)

Packet type `0x01` for response.

Response ID must match ID of the request, otherwise ping is invalid.

Length      | Contents
----------- | --------
`1`         | 0x01
`8`         | Ping ID

Serialized form should be put in the encrypted part of DHT packet.

[`PingResponse`](./struct.PingResponse.html) can only be created as a response
to [`PingRequest`](./struct.PingRequest.html).
*/

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PingResponse {
    /// Ping id same as requested from PingRequest
    pub id: u64,
}

impl FromBytes for PingResponse {
    named!(from_bytes<PingResponse>, do_parse!(
        tag!("\x01") >>
        id: be_u64 >>
        (PingResponse { id: id})
    ));
}

impl ToBytes for PingResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x01) >>
            gen_be_u64!(self.id)
        )
    }
}

/** Request to get address of given DHT PK, or nodes that are closest in DHT
to the given PK.

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

impl ToBytes for GetNodes {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.pk.as_ref()) >>
            gen_be_u64!(self.id)
        )
    }
}

impl FromBytes for GetNodes {
    named!(from_bytes<GetNodes>, do_parse!(
        pk: call!(PublicKey::from_bytes) >>
        id: be_u64 >>
        (GetNodes { pk: pk, id: id })
    ));
}

/** Response to [`GetNodes`](./struct.GetNodes.html) request, containing up to
`4` nodes closest to the requested node.

Serialized form:

Length      | Contents
----------- | --------
`1`         | Number of packed nodes (maximum 4)
`[39, 204]` | Nodes in packed format
`8`         | ping id

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
    /// request id
    pub id: u64,
}

impl ToBytes for SendNodes {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_if_else!(!self.nodes.is_empty() && self.nodes.len() <= 4,
                gen_be_u8!(self.nodes.len() as u8), gen_call!(|_,_| Err(GenError::CustomError(0)), 1) ) >>
            gen_many_ref!(&self.nodes, |buf, node| PackedNode::to_bytes(node, buf)) >>
            gen_be_u64!(self.id)
        )
    }
}

impl FromBytes for SendNodes {
    named!(from_bytes<SendNodes>, do_parse!(
        nodes_number: le_u8 >>
        nodes: cond_reduce!(
            nodes_number > 0 && nodes_number <= 4,
            count!(PackedNode::from_bytes, nodes_number as usize)
        ) >>
        id: be_u64 >>
        (SendNodes {
            nodes: nodes,
            id: id,
        })
    ));
}

/** NatPing request of DHT Request packet.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NatPingRequest {
    /// Request ping id
    pub id: u64,
}

/** NatPing response of DHT Request packet.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NatPingResponse {
    /// Ping id same as requested from PingRequest
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
mod test {
    use super::*;
    use std::net::SocketAddr;
    use toxcore::dht_new::codec::*;

    use quickcheck::{Arbitrary, Gen, quickcheck};

    impl DhtPacket {
        pub fn new(shared_secret: &PrecomputedKey, pk: &PublicKey, dp: DhtPacketPayload) -> DhtPacket {
            let nonce = &gen_nonce();
            let mut buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, size) = dp.to_bytes((&mut buf, 0)).unwrap();
            let payload = seal_precomputed(&buf[..size] , nonce, shared_secret);

            DhtPacket {
                packet_kind: dp.kind(),
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

    impl DhtPacketPayload {
        /// Packet kind for enum DhtPacketPayload
        pub fn kind(&self) -> PacketKind {
            match *self {
                DhtPacketPayload::PingRequest(_) => PacketKind::PingRequest,
                DhtPacketPayload::PingResponse(_) => PacketKind::PingResponse,
                DhtPacketPayload::GetNodes(_) => PacketKind::GetNodes,
                DhtPacketPayload::SendNodes(_) => PacketKind::SendNodes,
            }
        }
    }

    impl PingRequest {
        /// Create new ping request with a randomly generated `request id`.
        pub fn new() -> Self {
            trace!("Creating new Ping.");
            PingRequest { id: random_u64() }
        }

        /// An ID of the request / response.
        pub fn id(&self) -> u64 {
            self.id
        }
    }

    impl PingResponse {
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

    impl From<PingRequest> for PingResponse {
        fn from(p: PingRequest) -> Self {
            PingResponse { id: p.id }
        }
    }

    impl From<NatPingRequest> for NatPingResponse {
        fn from(p: NatPingRequest) -> Self {
            NatPingResponse { id: p.id }
        }
    }

    impl Arbitrary for DhtBase {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let choice = g.gen_range(0, 2);
            if choice == 0 {
                DhtBase::DhtPacket(DhtPacket::arbitrary(g))
            } else {
                DhtBase::DhtRequest(DhtRequest::arbitrary(g))
            }
        }
    }

    impl Arbitrary for DhtPacket {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let (pk, sk) = gen_keypair();  // "sender" keypair
            let (r_pk, _) = gen_keypair();  // receiver PK
            let precomputed = encrypt_precompute(&r_pk, &sk);
            DhtPacket::new(&precomputed, &pk, DhtPacketPayload::arbitrary(g))
        }
    }

    impl Arbitrary for DhtPacketPayload {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let choice = g.gen_range(0, 4);
            match choice {
                0 =>
                    DhtPacketPayload::PingRequest(PingRequest::arbitrary(g)),
                1 =>
                    DhtPacketPayload::PingResponse(PingResponse::arbitrary(g)),
                2 =>
                    DhtPacketPayload::GetNodes(GetNodes::arbitrary(g)),
                3 =>
                    DhtPacketPayload::SendNodes(SendNodes::arbitrary(g)),
                _ => unreachable!("Arbitrary for DhtPacket - should not have happened!")
            }
        }
    }

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

    impl Arbitrary for PingRequest {
        fn arbitrary<G: Gen>(_g: &mut G) -> Self {
            PingRequest::new()
        }
    }

    impl Arbitrary for PingResponse {
        fn arbitrary<G: Gen>(_g: &mut G) -> Self {
            PingRequest::new().into()
        }
    }

    impl Arbitrary for NatPingRequest {
        fn arbitrary<G: Gen>(_g: &mut G) -> Self {
            NatPingRequest::new()
        }
    }

    impl Arbitrary for NatPingResponse {
        fn arbitrary<G: Gen>(_g: &mut G) -> Self {
            NatPingRequest::new().into()
        }
    }

    impl Arbitrary for GetNodes {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let mut a: [u8; PUBLICKEYBYTES] = [0; PUBLICKEYBYTES];
            g.fill_bytes(&mut a);
            GetNodes { pk: PublicKey(a), id: g.gen() }
        }
    }

    impl Arbitrary for SendNodes {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let nodes = vec![Arbitrary::arbitrary(g); g.gen_range(1, 4)];
            let id = g.gen();
            SendNodes { nodes: nodes, id: id }
        }
    }

    #[test]
    fn dht_packet_payload_check() {
        fn with_payload(payload: DhtPacketPayload) {
            let packet_kind = payload.kind();
            let mut buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, len) = payload.to_bytes((&mut buf, 0)).ok().unwrap();
            let (_, decoded) = DhtPacketPayload::from_bytes(&buf[..len], packet_kind).unwrap();
            assert_eq!(decoded, payload);
        }
        quickcheck(with_payload as fn(DhtPacketPayload));
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

    #[test]
    fn dht_request_check() {
        fn with_packet(packet: DhtRequest) {
            let mut buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, len) = packet.to_bytes((&mut buf, 0)).ok().unwrap();
            let (_, decoded) = DhtRequest::from_bytes(&buf[..len]).unwrap();
            assert_eq!(decoded, packet);
        }
        quickcheck(with_packet as fn(DhtRequest));
    }

    #[test]
    fn dht_packet_encode_decode() {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let packed_node = PackedNode::new(false, SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &alice_pk);
        let test_payloads = vec![
            DhtPacketPayload::PingRequest(PingRequest { id: 42 }),
            DhtPacketPayload::PingResponse(PingResponse { id: 42 }),
            DhtPacketPayload::GetNodes(GetNodes { pk: alice_pk, id: 42 }),
            DhtPacketPayload::SendNodes(SendNodes { nodes: vec![packed_node], id: 42 })
        ];
        for payload in test_payloads {
            // encode payload with shared secret
            let dht_packet = DhtPacket::new(&shared_secret, &alice_pk, payload.clone());
            // create dht_base
            let dht_base = DhtBase::DhtPacket(dht_packet.clone());
            // serialize dht base to bytes
            let mut buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, size) = dht_base.to_bytes((&mut buf, 0)).unwrap();
            // deserialize dht base from bytes
            let (_, decoded_dht_base) = DhtBase::from_bytes(&buf[..size]).unwrap();
            // bases should be equal
            assert_eq!(decoded_dht_base, dht_base);
            // get packet from base
            let decoded_dht_packet = match decoded_dht_base {
                DhtBase::DhtPacket(decoded_dht_packet) => decoded_dht_packet,
                _ => unreachable!("should be DhtPacket")
            };
            // packets should be equal
            assert_eq!(decoded_dht_packet, dht_packet);
            // try to decode payload with eve's secret key
            let decoded_payload = decoded_dht_packet.get_payload(&eve_sk);
            assert!(decoded_payload.is_err());
            // decode payload with bob's secret key
            let decoded_payload = decoded_dht_packet.get_payload(&bob_sk).unwrap();
            // payloads should be equal
            assert_eq!(decoded_payload, payload);
        }
    }

    #[test]
    fn dht_request_encode_decode() {
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
            // create dht_base
            let dht_base = DhtBase::DhtRequest(dht_request.clone());
            // serialize dht base to bytes
            let mut buf = [0; MAX_DHT_PACKET_SIZE];
            let (_, size) = dht_base.to_bytes((&mut buf, 0)).unwrap();
            // deserialize dht base from bytes
            let (_, decoded_dht_base) = DhtBase::from_bytes(&buf[..size]).unwrap();
            // bases should be equal
            assert_eq!(decoded_dht_base, dht_base);
            // get packet from base
            let decoded_dht_request = match decoded_dht_base {
                DhtBase::DhtRequest(decoded_dht_request) => decoded_dht_request,
                _ => unreachable!("should be DhtRequest")
            };
            // requests should be equal
            assert_eq!(decoded_dht_request, dht_request);
            // try to decode payload with eve's secret key
            let decoded_payload = decoded_dht_request.get_payload(&eve_sk);
            assert!(decoded_payload.is_err());
            // decode payload with bob's secret key
            let decoded_payload = decoded_dht_request.get_payload(&bob_sk).unwrap();
            // payloads should be equal
            assert_eq!(decoded_payload, payload);
        }
    }

    #[test]
    fn dht_packet_decode_invalid() {
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_packet = DhtPacket {
            packet_kind: PacketKind::PingRequest,
            pk: alice_pk,
            nonce: nonce,
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&bob_sk);
        assert!(decoded_payload.is_err());
        // Try short incomplete
        let invalid_payload = [0x00];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_packet = DhtPacket {
            packet_kind: PacketKind::PingRequest,
            pk: alice_pk,
            nonce: nonce,
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&bob_sk);
        assert!(decoded_payload.is_err());
    }

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
