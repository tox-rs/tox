/*! OnionResponse1 packet
*/

use super::*;

use nom::combinator::{rest_len, map_parser, verify};
use nom::bytes::complete::{tag, take};

use tox_binary_io::*;

/** First onion response packet. It's sent back from the second to the first node
from onion chain.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x8e`
`59`     | `OnionReturn`
variable | Payload

where payload is encrypted [`OnionAnnounceResponse`](./struct.OnionAnnounceResponse.html)
or [`OnionDataResponse`](./struct.OnionDataResponse.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionResponse1 {
    /// Return address encrypted by the first node from onion chain
    pub onion_return: OnionReturn,
    /// Encrypted payload
    pub payload: InnerOnionResponse
}

impl FromBytes for OnionResponse1 {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = verify(rest_len, |len| *len <= ONION_MAX_PACKET_SIZE)(input)?;
        let (input, _) = tag(&[0x8e][..])(input)?;
        let (input, onion_return) = map_parser(take(ONION_RETURN_1_SIZE), OnionReturn::from_bytes)(input)?;
        let (input, payload) = InnerOnionResponse::from_bytes(input)?;
        Ok((input, OnionResponse1 { onion_return, payload }))
    }
}

impl ToBytes for OnionResponse1 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x8e) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return) >>
            gen_call!(|buf, payload| InnerOnionResponse::to_bytes(payload, buf), &self.payload) >>
            gen_len_limit(ONION_MAX_PACKET_SIZE)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION_RETURN_1_PAYLOAD_SIZE: usize = ONION_RETURN_1_SIZE - xsalsa20poly1305::NONCE_SIZE;

    encode_decode_test!(
        onion_response_1_encode_decode,
        OnionResponse1 {
            onion_return: OnionReturn {
                nonce: [42; xsalsa20poly1305::NONCE_SIZE],
                payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
            },
            payload: InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
                sendback_data: 12345,
                nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
                payload: vec![42; 123]
            })
        }
    );
}
