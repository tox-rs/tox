/*! OnionRequest packet
*/

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::ip_port::*;
use crate::toxcore::onion::packet::{
    ONION_MAX_PACKET_SIZE,
    ONION_RETURN_1_SIZE,
};

use nom::combinator::rest;

/// Encrypted payload should contain `IpPort`, `PublicKey` and inner encrypted
/// payload that should contain at least `IpPort` struct.
const ONION_MIN_PAYLOAD_SIZE: usize = (SIZE_IPPORT + MACBYTES) * 2 + PUBLICKEYBYTES;

/// `OnionRequest1` packet with encrypted payload from `OnionRequest` packet
/// shouldn't be bigger than `ONION_MAX_PACKET_SIZE`.
const ONION_MAX_PAYLOAD_SIZE: usize = ONION_MAX_PACKET_SIZE - (1 + NONCEBYTES + PUBLICKEYBYTES + ONION_RETURN_1_SIZE);

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
    named!(from_bytes<OnionRequest>, do_parse!(
        tag!("\x08") >>
        nonce: call!(Nonce::from_bytes) >>
        ip_port: call!(IpPort::from_bytes, IpPortPadding::WithPadding) >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        payload: verify!(
            rest,
            |payload: &[u8]| payload.len() >= ONION_MIN_PAYLOAD_SIZE && payload.len() <= ONION_MAX_PAYLOAD_SIZE
        ) >>
        (OnionRequest { nonce, ip_port, temporary_pk, payload: payload.to_vec() })
    ));
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
    use super::*;

    encode_decode_test!(
        onion_request_encode_decode,
        OnionRequest {
            nonce: gen_nonce(),
            ip_port: IpPort {
                protocol: ProtocolType::TCP,
                ip_addr: "5.6.7.8".parse().unwrap(),
                port: 12345,
            },
            temporary_pk: gen_keypair().0,
            payload: vec![42; ONION_MIN_PAYLOAD_SIZE]
        }
    );
}
