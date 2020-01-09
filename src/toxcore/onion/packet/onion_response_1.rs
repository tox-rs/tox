/*! OnionResponse1 packet
*/

use super::*;

use nom::combinator::rest_len;

use crate::toxcore::binary_io::*;

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
    named!(from_bytes<OnionResponse1>, do_parse!(
        verify!(rest_len, |len| *len <= ONION_MAX_PACKET_SIZE) >>
        tag!(&[0x8e][..]) >>
        onion_return: flat_map!(take!(ONION_RETURN_1_SIZE), OnionReturn::from_bytes) >>
        payload: call!(InnerOnionResponse::from_bytes) >>
        (OnionResponse1 { onion_return, payload })
    ));
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

    const ONION_RETURN_1_PAYLOAD_SIZE: usize = ONION_RETURN_1_SIZE - secretbox::NONCEBYTES;

    encode_decode_test!(
        onion_response_1_encode_decode,
        OnionResponse1 {
            onion_return: OnionReturn {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; ONION_RETURN_1_PAYLOAD_SIZE]
            },
            payload: InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
                sendback_data: 12345,
                nonce: gen_nonce(),
                payload: vec![42; 123]
            })
        }
    );
}
