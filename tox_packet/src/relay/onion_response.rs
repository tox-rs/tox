/*! OnionResponse packet
*/

use super::*;

use tox_binary_io::*;
use crate::onion::InnerOnionResponse;

/** Sent by server to client.
The server just sends payload from `OnionResponse1` packet that it got from a
UDP node to the client.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x09`
variable | Payload

*/
#[derive(Debug, PartialEq, Clone)]
pub struct OnionResponse {
    /// Inner onion response
    pub payload: InnerOnionResponse
}

impl FromBytes for OnionResponse {
    named!(from_bytes<OnionResponse>, do_parse!(
        tag!("\x09") >>
        payload: call!(InnerOnionResponse::from_bytes) >>
        (OnionResponse { payload })
    ));
}

impl ToBytes for OnionResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x09) >>
            gen_call!(|buf, payload| InnerOnionResponse::to_bytes(payload, buf), &self.payload)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::onion::{OnionAnnounceResponse, OnionDataResponse};

    encode_decode_test!(
        tox_crypto::crypto_init().unwrap(),
        onion_response_with_announce_encode_decode,
        OnionResponse {
            payload: InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
                sendback_data: 12345,
                nonce: tox_crypto::gen_nonce(),
                payload: vec![42; 123]
            })
        }
    );

    encode_decode_test!(
        tox_crypto::crypto_init().unwrap(),
        onion_response_with_data_encode_decode,
        OnionResponse {
            payload: InnerOnionResponse::OnionDataResponse(OnionDataResponse {
                nonce: tox_crypto::gen_nonce(),
                temporary_pk: tox_crypto::gen_keypair().0,
                payload: vec![42; 123]
            })
        }
    );
}
