/*! DhtRequest packet
*/
use super::*;

use crypto_box::{SalsaBox, aead::{Aead, AeadCore, Error as AeadError}};
use nom::{
    number::complete::be_u64,
    combinator::{rest, eof, cond},
    bytes::complete::tag,
    multi::many0,
};

use tox_binary_io::*;
use tox_crypto::*;
use crate::dht::errors::*;
use crate::packed_node::*;

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
            gen_slice!(self.rpk.as_bytes()) >>
            gen_slice!(self.spk.as_bytes()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl FromBytes for DhtRequest {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x20")(input)?;
        let (input, rpk) = PublicKey::from_bytes(input)?;
        let (input, spk) = PublicKey::from_bytes(input)?;
        let (input, nonce) = Nonce::from_bytes(input)?;
        let (input, payload) = map(rest, |bytes: &[u8]| bytes.to_vec() )(input)?;
        Ok((input, DhtRequest { rpk, spk, nonce, payload }))
    }
}

impl DhtRequest {
    /// create new DhtRequest object
    pub fn new(shared_secret: &SalsaBox, rpk: PublicKey, spk: PublicKey, dp: &DhtRequestPayload) -> DhtRequest {
        let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());

        let mut buf = [0; MAX_DHT_PACKET_SIZE];
        let (_, size) = dp.to_bytes((&mut buf, 0)).unwrap();
        let payload = shared_secret.encrypt(&nonce, &buf[..size]).unwrap();

        DhtRequest {
            rpk,
            spk,
            nonce: nonce.into(),
            payload,
        }
    }
    /**
    Decrypt payload and try to parse it as packet type.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as given packet type
    */
    pub fn get_payload(&self, shared_secret: &SalsaBox) -> Result<DhtRequestPayload, GetPayloadError> {
        let decrypted = shared_secret.decrypt((&self.nonce).into(), self.payload.as_slice())
            .map_err(|AeadError| {
                GetPayloadError::decrypt()
            })?;

        match DhtRequestPayload::from_bytes(&decrypted) {
            Err(error) => {
                Err(GetPayloadError::deserialize(error, decrypted.clone()))
            },
            Ok((_, payload)) => {
                Ok(payload)
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
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        alt((
            map(NatPingRequest::from_bytes, DhtRequestPayload::NatPingRequest),
            map(NatPingResponse::from_bytes, DhtRequestPayload::NatPingResponse),
            map(DhtPkAnnounce::from_bytes, DhtRequestPayload::DhtPkAnnounce),
            map(HardeningRequest::from_bytes, DhtRequestPayload::HardeningRequest),
            map(HardeningResponse::from_bytes, DhtRequestPayload::HardeningResponse),
        ))(input)
    }
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
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag(&[0xfe][..])(input)?;
        let (input, _) = tag("\x00")(input)?;
        let (input, id) = be_u64(input)?;
        Ok((input, NatPingRequest { id }))
    }
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
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag(&[0xfe][..])(input)?;
        let (input, _) = tag("\x01")(input)?;
        let (input, id) = be_u64(input)?;
        Ok((input, NatPingResponse { id }))
    }
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
    /// Long term `PublicKey` that was used for the inner encrypted payload
    pub real_pk: PublicKey,
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for DhtPkAnnounce {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag(&[0x9c][..])(input)?;
        let (input, real_pk) = PublicKey::from_bytes(input)?;
        let (input, nonce) = Nonce::from_bytes(input)?;
        let (input, payload) = rest(input)?;
        Ok((input, DhtPkAnnounce { real_pk, nonce, payload: payload.to_vec() }))
    }
}

impl ToBytes for DhtPkAnnounce {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x9c) >>
            gen_slice!(self.real_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl DhtPkAnnounce {
    /// Create `DhtPkAnnounce` from `DhtPkAnnouncePayload` encrypting it with
    /// `shared_key`
    pub fn new(shared_secret: &SalsaBox, real_pk: PublicKey, payload: &DhtPkAnnouncePayload) -> DhtPkAnnounce {
        let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
        let mut buf = [0; 245];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = shared_secret.encrypt(&nonce, &buf[..size]).unwrap();

        DhtPkAnnounce {
            real_pk,
            nonce: nonce.into(),
            payload,
        }
    }

    /** Decrypt payload and try to parse it as `DhtPkAnnouncePayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as `DhtPkAnnouncePayload`
    */
    pub fn get_payload(&self, shared_secret: &SalsaBox) -> Result<DhtPkAnnouncePayload, GetPayloadError> {
        let decrypted = shared_secret.decrypt((&self.nonce).into(), self.payload.as_slice())
            .map_err(|AeadError| {
                GetPayloadError::decrypt()
            })?;
        match DhtPkAnnouncePayload::from_bytes(&decrypted) {
            Err(error) => {
                Err(GetPayloadError::deserialize(error, decrypted.clone()))
            },
            Ok((_, payload)) => {
                Ok(payload)
            }
        }
    }
}

/** Packet used to announce our DHT `PublicKey` to a friend. Can be sent as
inner packet of `OnionDataResponse` and `DhtRequest` packets.

Serialized form:

Length     | Content
---------- | ------
`1`        | `0x9C`
`8`        | `no_reply`
`32`       | Friend's DHT `PublicKey`
`[0, 204]` | Nodes in packed format

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtPkAnnouncePayload {
    /// Number used as a protection against reply attacks. The packet should be
    /// accepted only if it's higher than the number in the last received packet.
    pub no_reply: u64,
    /// Announced DHT `PublicKey`.
    pub dht_pk: PublicKey,
    /// Up to 4 nodes that can be either DHT close node or TCP relay we
    /// connected to.
    pub nodes: Vec<TcpUdpPackedNode>,
}

impl FromBytes for DhtPkAnnouncePayload {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag(&[0x9c][..])(input)?;
        let (input, no_reply) = be_u64(input)?;
        let (input, dht_pk) = PublicKey::from_bytes(input)?;
        let (input, nodes) = many0(TcpUdpPackedNode::from_bytes)(input)?;
        let (input, _) = cond(nodes.len() <= 4, eof)(input)?;
        Ok((input, DhtPkAnnouncePayload {
            no_reply,
            dht_pk,
            nodes,
        }))
    }
}

impl ToBytes for DhtPkAnnouncePayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x9c) >>
            gen_be_u64!(self.no_reply) >>
            gen_slice!(self.dht_pk.as_ref()) >>
            gen_cond!(
                self.nodes.len() <= 4,
                gen_many_ref!(&self.nodes, |buf, node| TcpUdpPackedNode::to_bytes(node, buf))
            )
        )
    }
}

impl DhtPkAnnouncePayload {
    /// Create new `DhtPkAnnouncePayload` with `no_reply` set to current time.
    pub fn new(dht_pk: PublicKey, nodes: Vec<TcpUdpPackedNode>) -> Self {
        use std::time::SystemTime;

        DhtPkAnnouncePayload {
            no_reply: unix_time(SystemTime::now()),
            dht_pk,
            nodes,
        }
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
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x30")(input)?;
        let (input, _) = tag("\x02")(input)?;
        let (input, _) = rest(input)?; // Hardening will be deprecated, so no need to parse body of packet.
        Ok((input, HardeningRequest))
    }
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
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x30")(input)?;
        let (input, _) = tag("\x03")(input)?;
        let (input, _) = rest(input)?; // Hardening will be deprecated, so no need to parse body of packet.
        Ok((input, HardeningResponse))
    }
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

    use nom::{Err, error::{ErrorKind, Error}};
    use crypto_box::aead::{AeadCore, generic_array::typenum::marker_traits::Unsigned};
    use rand::thread_rng;

    use crate::ip_port::*;

    encode_decode_test!(
        nat_ping_request_encode_decode,
        DhtRequestPayload::NatPingRequest(NatPingRequest { id: 42 })
    );

    encode_decode_test!(
        nat_ping_response_encode_decode,
        DhtRequestPayload::NatPingResponse(NatPingResponse { id: 42 })
    );

    encode_decode_test!(
        dht_pk_announce_encode_decode,
        DhtRequestPayload::DhtPkAnnounce(DhtPkAnnounce {
            real_pk: SecretKey::generate(&mut thread_rng()).public_key(),
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 123]
        })
    );

    encode_decode_test!(
        hardening_request_encode_decode,
        DhtRequestPayload::HardeningRequest(HardeningRequest)
    );

    encode_decode_test!(
        hardening_response_encode_decode,
        DhtRequestPayload::HardeningResponse(HardeningResponse)
    );

    encode_decode_test!(
        dht_pk_announce_payload_encode_decode,
        DhtPkAnnouncePayload {
            no_reply: 42,
            dht_pk: SecretKey::generate(&mut thread_rng()).public_key(),
            nodes: vec![
                TcpUdpPackedNode {
                    ip_port: IpPort {
                        protocol: ProtocolType::Udp,
                        ip_addr: "127.0.0.1".parse().unwrap(),
                        port: 12345,
                    },
                    pk: SecretKey::generate(&mut thread_rng()).public_key(),
                },
                TcpUdpPackedNode {
                    ip_port: IpPort {
                        protocol: ProtocolType::Udp,
                        ip_addr: "127.0.0.1".parse().unwrap(),
                        port: 12346,
                    },
                    pk: SecretKey::generate(&mut thread_rng()).public_key(),
                },
                TcpUdpPackedNode {
                    ip_port: IpPort {
                        protocol: ProtocolType::Tcp,
                        ip_addr: "127.0.0.2".parse().unwrap(),
                        port: 12345,
                    },
                    pk: SecretKey::generate(&mut thread_rng()).public_key(),
                },
                TcpUdpPackedNode {
                    ip_port: IpPort {
                        protocol: ProtocolType::Tcp,
                        ip_addr: "127.0.0.2".parse().unwrap(),
                        port: 12346,
                    },
                    pk: SecretKey::generate(&mut thread_rng()).public_key(),
                },
            ],
        }
    );

    #[test]
    fn dht_request_payload_encrypt_decrypt() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let alice_pk = alice_sk.public_key();
        let bob_sk = SecretKey::generate(&mut rng);
        let bob_pk = bob_sk.public_key();
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let test_payloads = vec![
            DhtRequestPayload::NatPingRequest(NatPingRequest { id: 42 }),
            DhtRequestPayload::NatPingResponse(NatPingResponse { id: 42 }),
            DhtRequestPayload::DhtPkAnnounce(DhtPkAnnounce {
                real_pk: SecretKey::generate(&mut rng).public_key(),
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                payload: vec![42; 123],
            }),
            DhtRequestPayload::HardeningRequest(HardeningRequest),
            DhtRequestPayload::HardeningResponse(HardeningResponse)
        ];

        for payload in test_payloads {
            // encode payload with shared secret
            let dht_request = DhtRequest::new(&shared_secret, bob_pk.clone(), alice_pk.clone(), &payload);
            // decode payload with bob's secret key & sender's public key
            let precomputed_key = SalsaBox::new(&dht_request.spk, &bob_sk);
            let decoded_payload = dht_request.get_payload(&precomputed_key).unwrap();
            // payloads should be equal
            assert_eq!(decoded_payload, payload);
        }
    }

    #[test]
    fn dht_request_payload_encrypt_decrypt_invalid_key() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let alice_pk = alice_sk.public_key();
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let eve_sk = SecretKey::generate(&mut rng);
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let test_payloads = vec![
            DhtRequestPayload::NatPingRequest(NatPingRequest { id: 42 }),
            DhtRequestPayload::NatPingResponse(NatPingResponse { id: 42 }),
            DhtRequestPayload::DhtPkAnnounce(DhtPkAnnounce {
                real_pk: SecretKey::generate(&mut rng).public_key(),
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                payload: vec![42; 123],
            }),
            DhtRequestPayload::HardeningRequest(HardeningRequest),
            DhtRequestPayload::HardeningResponse(HardeningResponse)
        ];
        for payload in test_payloads {
            // encode payload with shared secret
            let dht_request = DhtRequest::new(&shared_secret, bob_pk.clone(), alice_pk.clone(), &payload);
            // try to decode payload with eve's secret key & sender's public key
            let precomputed_key = SalsaBox::new(&dht_request.spk, &eve_sk);
            let decoded_payload = dht_request.get_payload(&precomputed_key);
            let error = decoded_payload.err().unwrap();
            assert_eq!(error, GetPayloadError::Decrypt);
        }
    }

    #[test]
    fn dht_request_decode_invalid() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let alice_pk = alice_sk.public_key();
        let bob_sk = SecretKey::generate(&mut rng);
        let bob_pk = bob_sk.public_key();
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_packet = DhtRequest {
            rpk: bob_pk.clone(),
            spk: alice_pk.clone(),
            nonce: nonce.into(),
            payload: invalid_payload_encoded
        };

        let precomputed_key = SalsaBox::new(&alice_pk, &bob_sk);

        let decoded_payload = invalid_packet.get_payload(&precomputed_key);
        let error = decoded_payload.err().unwrap();
        assert_eq!(error, GetPayloadError::Deserialize {
            error: Err::Error(Error::new(invalid_payload.to_vec(), ErrorKind::Tag)),
            payload: invalid_payload.to_vec()
        });
        // Try short incomplete
        let invalid_payload = [0xfe];
        let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_packet = DhtRequest {
            rpk: bob_pk,
            spk: alice_pk,
            nonce: nonce.into(),
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&precomputed_key);
        let error = decoded_payload.err().unwrap();
        assert_eq!(error, GetPayloadError::Deserialize {
            error: Err::Error(Error::new(invalid_payload.to_vec(), ErrorKind::Tag)),
            payload: invalid_payload.to_vec()
        });
    }

    #[test]
    fn dht_pk_announce_payload_encrypt_decrypt() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let alice_pk = alice_sk.public_key();
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let payload = DhtPkAnnouncePayload::new(
            SecretKey::generate(&mut rng).public_key(),
            vec![
                TcpUdpPackedNode {
                    ip_port: IpPort {
                        protocol: ProtocolType::Udp,
                        ip_addr: "127.0.0.1".parse().unwrap(),
                        port: 12345,
                    },
                    pk: SecretKey::generate(&mut rng).public_key(),
                },
            ],
        );
        // encode payload with shared secret
        let packet = DhtPkAnnounce::new(&shared_secret, alice_pk, &payload);
        // decode payload with shared secret
        let decoded_payload = packet.get_payload(&shared_secret).unwrap();
        // payloads should be equal
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn dht_pk_announce_payload_encrypt_decrypt_invalid_key() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let alice_pk = alice_sk.public_key();
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let eve_sk = SecretKey::generate(&mut rng);
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let shared_secret_invalid = SalsaBox::new(&bob_pk, &eve_sk);
        let payload = DhtPkAnnouncePayload::new(
            SecretKey::generate(&mut rng).public_key(),
            vec![
                TcpUdpPackedNode {
                    ip_port: IpPort {
                        protocol: ProtocolType::Udp,
                        ip_addr: "127.0.0.1".parse().unwrap(),
                        port: 12345,
                    },
                    pk: SecretKey::generate(&mut rng).public_key(),
                },
            ],
        );
        // encode payload with shared secret
        let packet = DhtPkAnnounce::new(&shared_secret, alice_pk, &payload);
        // try to decode payload with invalid shared secret
        let decoded_payload = packet.get_payload(&shared_secret_invalid);
        assert!(decoded_payload.is_err());
    }

    #[test]
    fn dht_pk_announce_payload_encrypt_decrypt_invalid() {
        let mut rng = thread_rng();
        let alice_sk = SecretKey::generate(&mut rng);
        let alice_pk = alice_sk.public_key();
        let bob_pk = SecretKey::generate(&mut rng).public_key();
        let shared_secret = SalsaBox::new(&bob_pk, &alice_sk);
        let nonce = SalsaBox::generate_nonce(&mut rand::thread_rng());
        // Try long invalid array
        let invalid_payload = [42; 123];
        let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_packet = DhtPkAnnounce {
            real_pk: alice_pk.clone(),
            nonce: nonce.into(),
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&shared_secret);
        assert!(decoded_payload.is_err());
        // Try short incomplete array
        let invalid_payload = [];
        let invalid_payload_encoded = shared_secret.encrypt(&nonce, &invalid_payload[..]).unwrap();
        let invalid_packet = DhtPkAnnounce {
            real_pk: alice_pk,
            nonce: nonce.into(),
            payload: invalid_payload_encoded
        };
        let decoded_payload = invalid_packet.get_payload(&shared_secret);
        assert!(decoded_payload.is_err());
    }
}
