/*! DhtRequest packet
*/

use nom::{be_u64, rest};

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::dht::codec::*;
use toxcore::dht::packet::errors::*;

/** DHT Request packet struct.
DHT Request packet consists of NatPingRequest and NatPingResponse.
When my known friend is not connected directly, send NatPingRequest to peers
which are in Ktree. When NatPingResponse arrives to me,
it means that my known friend is also searching me, and running behind NAT,
so start hole-punching.

https://zetok.github.io/tox-spec/#dht-request-packets

Length    | Content
--------- | -------------------------
`1`       | `0x20`
`32`      | Receiver's Public Key
`32`      | Sender's Public Key
`24`      | Nonce
variable  | Payload

where Payload is encrypted [`DhtRequestPayload`](./struct.DhtRequestPayload.html)

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
        (DhtRequest { rpk, spk, nonce, payload })
    ));
}

impl DhtRequest {
    /// create new DhtRequest object
    pub fn new(shared_secret: &PrecomputedKey, rpk: &PublicKey, spk: &PublicKey, dp: &DhtRequestPayload) -> DhtRequest {
        let nonce = gen_nonce();

        let mut buf = [0; MAX_DHT_PACKET_SIZE];
        let (_, size) = dp.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        DhtRequest {
            rpk: *rpk,
            spk: *spk,
            nonce,
            payload,
        }
    }
    /**
    Decrypt payload and try to parse it as packet type.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as given packet type
    */
    pub fn get_payload(&self, shared_secret: &PrecomputedKey) -> Result<DhtRequestPayload, GetPayloadError>
    {
        debug!(target: "DhtRequest", "Getting packet data from DhtRequest.");
        trace!(target: "DhtRequest", "With DhtRequest: {:?}", self);
        let decrypted = open_precomputed(&self.payload, &self.nonce, shared_secret)
            .map_err(|()| {
                debug!("Decrypting DhtRequest failed!");
                GetPayloadError::decrypt()
            })?;

        match DhtRequestPayload::from_bytes(&decrypted) {
            IResult::Incomplete(needed) => {
                debug!(target: "DhtRequest", "DhtRequest deserialize error: {:?}", needed);
                Err(GetPayloadError::incomplete(needed, self.payload.to_vec()))
            },
            IResult::Error(error) => {
                debug!(target: "DhtRequest", "DhtRequest deserialize error: {:?}", error);
                Err(GetPayloadError::deserialize(error, self.payload.to_vec()))
            },
            IResult::Done(_, packet) => {
                Ok(packet)
            }
        }
    }
}

/** Standart DHT Request packet that embedded in the payload of
[`DhtRequest`](./struct.DhtRequest.html).

https://zetok.github.io/tox-spec/#dht-request-packets
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DhtRequestPayload {
    /// [`NatPingRequest`](./struct.NatPingRequest.html) structure.
    NatPingRequest(NatPingRequest),
    /// [`NatPingResponse`](./struct.NatPingResponse.html) structure.
    NatPingResponse(NatPingResponse),
    /// [`DhtPkAnnounce`](./struct.DhtPkAnnounce.html) structure.
    DhtPkAnnounce(DhtPkAnnounce),
    /// [`HardeningRequest`](./struct.HardeningRequest.html) structure.
    HardeningRequest(HardeningRequest),
    /// [`HardeningResponse`](./struct.HardeningResponse.html) structure.
    HardeningResponse(HardeningResponse),
}

impl ToBytes for DhtRequestPayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            DhtRequestPayload::NatPingRequest(ref p) => p.to_bytes(buf),
            DhtRequestPayload::NatPingResponse(ref p) => p.to_bytes(buf),
            DhtRequestPayload::DhtPkAnnounce(ref p) => p.to_bytes(buf),
            DhtRequestPayload::HardeningRequest(ref p) => p.to_bytes(buf),
            DhtRequestPayload::HardeningResponse(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for DhtRequestPayload {
    named!(from_bytes<DhtRequestPayload>, alt!(
        map!(NatPingRequest::from_bytes, DhtRequestPayload::NatPingRequest) |
        map!(NatPingResponse::from_bytes, DhtRequestPayload::NatPingResponse) |
        map!(DhtPkAnnounce::from_bytes, DhtRequestPayload::DhtPkAnnounce) |
        map!(HardeningRequest::from_bytes, DhtRequestPayload::HardeningRequest) |
        map!(HardeningResponse::from_bytes, DhtRequestPayload::HardeningResponse)
    ));
}

/** NatPing request of DHT Request packet.

Length    | Content
--------- | -------------------------
`1`       | `0xFE`
`1`       | `0x00`
`8`       | Request Id (Ping Id)

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
        (NatPingRequest { id })
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

Length    | Content
--------- | -------------------------
`1`       | `0xFE`
`1`       | `0x01`
`8`       | Request Id (Ping Id)

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
        (NatPingResponse { id })
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

/** Packet to announce self short term DHT `PublicKey` to a friend.

Onion client can send self announce info to its friend via two channels: through
`OnionDataRequest` or through `DhtRequest`. `DhtRequest` will be used if
friend's DHT `PublicKey` is known.

Length    | Content
--------- | -------------------------
`1`       | `0x9C`
`32`      | Public Key
`24`      | Nonce
variable  | Payload

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtPkAnnounce {
    /// `PublicKey` for the current encrypted payload
    pub pk: PublicKey,
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for DhtPkAnnounce {
    named!(from_bytes<DhtPkAnnounce>, do_parse!(
        tag!(&[0x9c][..]) >>
        pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        payload: rest >>
        (DhtPkAnnounce { pk, nonce, payload: payload.to_vec() })
    ));
}

impl ToBytes for DhtPkAnnounce {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x9c) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

/** Hardening nodes request of DHT Request packet.

Length    | Content
--------- | -------------------------
`1`       | `0x30`
`1`       | `0x02`
`rest`    | ignored

Hardening will be deprecated later.
So we just ignore rest except packet ids.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HardeningRequest;

impl FromBytes for HardeningRequest {
    named!(from_bytes<HardeningRequest>, do_parse!(
        tag!("\x30") >>
        tag!("\x02") >>
        rest >> // Hardening will be deprecated, so no need to parse body of packet.
        (HardeningRequest)
    ));
}

impl ToBytes for HardeningRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x30) >>
            gen_be_u8!(0x02)
        )
    }
}

/** Hardening nodes response of DHT Request packet.

Length    | Content
--------- | -------------------------
`1`       | `0x30`
`1`       | `0x03`
`rest`    | ignored

Hardening will be deprecated later.
So we just ignore rest except packet ids.
*/

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardeningResponse;

impl FromBytes for HardeningResponse {
    named!(from_bytes<HardeningResponse>, do_parse!(
        tag!("\x30") >>
        tag!("\x03") >>
        rest >> // Hardening will be deprecated, so no need to parse body of packet.
        (HardeningResponse)
    ));
}

impl ToBytes for HardeningResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x30) >>
            gen_be_u8!(0x03)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::{Needed, ErrorKind};

    encode_decode_test!(
        nat_ping_request_payload_encode_decode,
        DhtRequestPayload::NatPingRequest(NatPingRequest { id: 42 })
    );

    encode_decode_test!(
        nat_ping_response_payload_encode_decode,
        DhtRequestPayload::NatPingResponse(NatPingResponse { id: 42 })
    );

    encode_decode_test!(
        dht_pk_announce_payload_encode_decode,
        DhtRequestPayload::DhtPkAnnounce(DhtPkAnnounce {
            pk: gen_keypair().0,
            nonce: gen_nonce(),
            payload: vec![42; 123]
        })
    );

    encode_decode_test!(
        hardening_request_payload_encode_decode,
        DhtRequestPayload::HardeningRequest(HardeningRequest)
    );

    encode_decode_test!(
        hardening_response_payload_encode_decode,
        DhtRequestPayload::HardeningResponse(HardeningResponse)
    );

    #[test]
    fn dht_request_payload_encrypt_decrypt() {
        crypto_init().unwrap();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let test_payloads = vec![
            DhtRequestPayload::NatPingRequest(NatPingRequest { id: 42 }),
            DhtRequestPayload::NatPingResponse(NatPingResponse { id: 42 }),
            DhtRequestPayload::HardeningRequest(HardeningRequest),
            DhtRequestPayload::HardeningResponse(HardeningResponse)
        ];

        for payload in test_payloads {
            // encode payload with shared secret
            let dht_request = DhtRequest::new(&shared_secret, &bob_pk, &alice_pk, &payload);
            // decode payload with bob's secret key & sender's public key
            let precomputed_key = precompute(&dht_request.spk, &bob_sk);
            let decoded_payload = dht_request.get_payload(&precomputed_key).unwrap();
            // payloads should be equal
            assert_eq!(decoded_payload, payload);
        }
    }

    #[test]
    fn dht_request_payload_encrypt_decrypt_invalid_key() {
        crypto_init().unwrap();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, _bob_sk) = gen_keypair();
        let (_eve_pk, eve_sk) = gen_keypair();
        let shared_secret = encrypt_precompute(&bob_pk, &alice_sk);
        let test_payloads = vec![
            DhtRequestPayload::NatPingRequest(NatPingRequest { id: 42 }),
            DhtRequestPayload::NatPingResponse(NatPingResponse { id: 42 }),
            DhtRequestPayload::HardeningRequest(HardeningRequest),
            DhtRequestPayload::HardeningResponse(HardeningResponse)
        ];
        for payload in test_payloads {
            // encode payload with shared secret
            let dht_request = DhtRequest::new(&shared_secret, &bob_pk, &alice_pk, &payload);
            // try to decode payload with eve's secret key & sender's public key
            let precomputed_key = precompute(&dht_request.spk, &eve_sk);
            let decoded_payload = dht_request.get_payload(&precomputed_key);
            assert!(decoded_payload.is_err());
            assert_eq!(*decoded_payload.err().unwrap().kind(), GetPayloadErrorKind::Decrypt);
        }
    }

    #[test]
    fn dht_request_decode_invalid() {
        crypto_init().unwrap();
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
            nonce,
            payload: invalid_payload_encoded
        };

        let precomputed_key = precompute(&alice_pk, &bob_sk);

        let decoded_payload = invalid_packet.get_payload(&precomputed_key);
        assert!(decoded_payload.is_err());
        assert_eq!(*decoded_payload.err().unwrap().kind(), GetPayloadErrorKind::Deserialize { error: ErrorKind::Alt, payload: invalid_packet.payload });
        // Try short incomplete
        let invalid_payload = [0xfe];
        let invalid_payload_encoded = seal_precomputed(&invalid_payload, &nonce, &shared_secret);
        let invalid_packet = DhtRequest {
            rpk: bob_pk,
            spk: alice_pk,
            nonce,
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&precomputed_key);
        assert!(decoded_payload.is_err());
        assert_eq!(*decoded_payload.err().unwrap().kind(), GetPayloadErrorKind::IncompletePayload { needed: Needed::Size(2), payload: invalid_packet.payload });
    }
}
