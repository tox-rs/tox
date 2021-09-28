/*! OnionRequest packet
*/

use super::*;

use crypto_box::{SalsaBox, aead::{AeadCore, generic_array::typenum::marker_traits::Unsigned}};
use tox_binary_io::*;
use tox_crypto::*;
use crate::ip_port::*;
use crate::onion::{
    ONION_MAX_PACKET_SIZE,
    ONION_RETURN_1_SIZE,
};

use nom::bytes::complete::tag;
use nom::combinator::{rest, verify};

/// Encrypted payload should contain `IpPort`, `PublicKey` and inner encrypted
/// payload that should contain at least `IpPort` struct.
const ONION_MIN_PAYLOAD_SIZE: usize = (SIZE_IPPORT + <SalsaBox as AeadCore>::TagSize::USIZE) * 2 + crypto_box::KEY_SIZE;

/// `OnionRequest1` packet with encrypted payload from `OnionRequest` packet
/// shouldn't be bigger than `ONION_MAX_PACKET_SIZE`.
const ONION_MAX_PAYLOAD_SIZE: usize = ONION_MAX_PACKET_SIZE - (1 + NONCEBYTES + crypto_box::KEY_SIZE + ONION_RETURN_1_SIZE);

/** Sent by client to server.
The server will pack payload from this request to `OnionRequest1` packet and send
it to UDP socket. The server can accept both TCP and UDP families as destination
IP address but regardless of this it will always send `OnionRequest1` to UDP
socket. Return address from `OnionRequest1` will contain TCP address so that
when we get `OnionResponse2` we will know that this response should be sent to
TCP client connected to our server.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x08`
`24`     | Nonce
`1`      | IpType
`4` or `16` | IPv4 or IPv6 address
`0` or `12` | Padding for IPv4
`2`      | Port
`32`     | PublicKey
variable | Payload

*/
#[derive(Debug, PartialEq, Clone)]
pub struct OnionRequest {
    /// Nonce that was used for payload encryption
    pub nonce: Nonce,
    /// Address of the next onion node
    pub ip_port: IpPort,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for OnionRequest {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x08")(input)?;
        let (input, nonce) = Nonce::from_bytes(input)?;
        let (input, ip_port) = IpPort::from_bytes(input, IpPortPadding::WithPadding)?;
        let (input, temporary_pk) = PublicKey::from_bytes(input)?;
        let (input, payload) = verify(
            rest,
            |payload: &[u8]| payload.len() >= ONION_MIN_PAYLOAD_SIZE && payload.len() <= ONION_MAX_PAYLOAD_SIZE
        )(input)?;
        Ok((input, OnionRequest { nonce, ip_port, temporary_pk, payload: payload.to_vec() }))
    }
}

impl ToBytes for OnionRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_cond!(
                self.payload.len() < ONION_MIN_PAYLOAD_SIZE || self.payload.len() > ONION_MAX_PAYLOAD_SIZE,
                |buf| gen_error(buf, 0)
            ) >>
            gen_be_u8!(0x08) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_call!(|buf, ip_port| IpPort::to_bytes(ip_port, buf, IpPortPadding::WithPadding), &self.ip_port) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

#[cfg(test)]
mod test {
    use rand::thread_rng;

    use super::*;

    encode_decode_test!(
        onion_request_encode_decode,
        OnionRequest {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            ip_port: IpPort {
                protocol: ProtocolType::Tcp,
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345,
            },
            temporary_pk: SecretKey::generate(&mut thread_rng()).public_key(),
            payload: vec![42; ONION_MIN_PAYLOAD_SIZE]
        }
    );
}
