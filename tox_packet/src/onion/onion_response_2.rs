/*! OnionResponse2 packet
*/

use super::*;

use nom::combinator::{rest_len, map_parser, verify};
use nom::bytes::complete::{tag, take};

use tox_binary_io::*;

/** Second onion response packet. It's sent back from the third to the second node
from onion chain.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x8d`
`118`    | `OnionReturn`
variable | Payload

where payload is encrypted [`OnionAnnounceResponse`](./struct.OnionAnnounceResponse.html)
or [`OnionDataResponse`](./struct.OnionDataResponse.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionResponse2 {
    /// Return address encrypted by the second node from onion chain
    pub onion_return: OnionReturn,
    /// Encrypted payload
    pub payload: InnerOnionResponse
}

impl FromBytes for OnionResponse2 {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = verify(rest_len, |len| *len <= ONION_MAX_PACKET_SIZE)(input)?;
        let (input, _) = tag(&[0x8d][..])(input)?;
        let (input, onion_return) = map_parser(take(ONION_RETURN_2_SIZE), OnionReturn::from_bytes)(input)?;
        let (input, payload) = InnerOnionResponse::from_bytes(input)?;
        Ok((input, OnionResponse2 { onion_return, payload }))
    }
}

impl ToBytes for OnionResponse2 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x8d) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return) >>
            gen_call!(|buf, payload| InnerOnionResponse::to_bytes(payload, buf), &self.payload) >>
            gen_len_limit(ONION_MAX_PACKET_SIZE)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_box::{SalsaBox, aead::generic_array::typenum::marker_traits::Unsigned};
    use crypto_box::aead::AeadCore;

    const ONION_RETURN_2_PAYLOAD_SIZE: usize = ONION_RETURN_2_SIZE - xsalsa20poly1305::NONCE_SIZE;

    encode_decode_test!(
        onion_response_2_encode_decode,
        OnionResponse2 {
            onion_return: OnionReturn {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
            },
            payload: InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
                sendback_data: 12345,
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                payload: vec![42; 123]
            })
        }
    );
}
