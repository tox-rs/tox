/*! InnerOnionResponse enum
*/

use super::*;

use nom::branch::alt;
use nom::combinator::map;
use tox_binary_io::*;

/** Onion responses that can be enclosed in onion packets and sent through onion
path.

Onion allows only two types of packets to be sent as a response through onion
paths: `OnionAnnounceResponse` and `OnionDataResponse`.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InnerOnionResponse {
    /// [`OnionAnnounceResponse`](./struct.OnionAnnounceResponse.html) structure.
    OnionAnnounceResponse(OnionAnnounceResponse),
    /// [`OnionDataResponse`](./struct.OnionDataResponse.html) structure.
    OnionDataResponse(OnionDataResponse),
}

impl ToBytes for InnerOnionResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            InnerOnionResponse::OnionAnnounceResponse(ref inner) => inner.to_bytes(buf),
            InnerOnionResponse::OnionDataResponse(ref inner) => inner.to_bytes(buf),
        }
    }
}

impl FromBytes for InnerOnionResponse {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        alt((
            map(
                OnionAnnounceResponse::from_bytes,
                InnerOnionResponse::OnionAnnounceResponse,
            ),
            map(OnionDataResponse::from_bytes, InnerOnionResponse::OnionDataResponse),
        ))(input)
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;

    encode_decode_test!(
        inner_onion_announce_response_encode_decode,
        InnerOnionResponse::OnionAnnounceResponse(OnionAnnounceResponse {
            sendback_data: 12345,
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            payload: vec![42; 123]
        })
    );

    encode_decode_test!(
        inner_onion_data_response_encode_decode,
        InnerOnionResponse::OnionDataResponse(OnionDataResponse {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            temporary_pk: SecretKey::generate(&mut thread_rng()).public_key(),
            payload: vec![42; 123]
        })
    );
}
