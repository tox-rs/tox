/*! OnionResponse3 packet
*/

use super::*;

use nom::combinator::rest_len;

use crate::toxcore::binary_io::*;

/** Third onion response packet. It's sent back from the destination node to the
third node from onion chain.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x8c`
`177`    | `OnionReturn`
variable | Payload

where payload is encrypted [`OnionAnnounceResponse`](./struct.OnionAnnounceResponse.html)
or [`OnionDataResponse`](./struct.OnionDataResponse.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionResponse3 {
    /// Return address encrypted by the third node from onion chain
    pub onion_return: OnionReturn,
    /// Encrypted payload
    pub payload: InnerOnionResponse
}

impl FromBytes for OnionResponse3 {
    named!(from_bytes<OnionResponse3>, do_parse!(
        verify!(rest_len, |len| *len <= ONION_MAX_PACKET_SIZE) >>
        tag!(&[0x8c][..]) >>
        onion_return: flat_map!(take!(ONION_RETURN_3_SIZE), OnionReturn::from_bytes) >>
        payload: call!(InnerOnionResponse::from_bytes) >>
        (OnionResponse3 { onion_return, payload })
    ));
}

impl ToBytes for OnionResponse3 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x8c) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return) >>
            gen_call!(|buf, payload| InnerOnionResponse::to_bytes(payload, buf), &self.payload) >>
            gen_len_limit(ONION_MAX_PACKET_SIZE)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION_RETURN_3_PAYLOAD_SIZE: usize = ONION_RETURN_3_SIZE - secretbox::NONCEBYTES;

    encode_decode_test!(
        onion_response_3_encode_decode,
        OnionResponse3 {
            onion_return: OnionReturn {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; ONION_RETURN_3_PAYLOAD_SIZE]
            },
            payload: InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
                sendback_data: 12345,
                nonce: gen_nonce(),
                payload: vec![42; 123]
            })
        }
    );
}
