/*! InnerOnionRequest enum
*/

use super::*;

use nom::branch::alt;
use nom::combinator::map;
use tox_binary_io::*;

/** Onion requests that can be enclosed in onion packets and sent through onion
path.

Onion allows only two types of packets to be sent as a request through onion
paths: `OnionAnnounceRequest` and `OnionDataRequest`.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InnerOnionRequest {
    /// [`InnerOnionAnnounceRequest`](./struct.InnerOnionAnnounceRequest.html) structure.
    InnerOnionAnnounceRequest(InnerOnionAnnounceRequest),
    /// [`InnerOnionDataRequest`](./struct.InnerOnionDataRequest.html) structure.
    InnerOnionDataRequest(InnerOnionDataRequest),
}

impl ToBytes for InnerOnionRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            InnerOnionRequest::InnerOnionAnnounceRequest(ref inner) => inner.to_bytes(buf),
            InnerOnionRequest::InnerOnionDataRequest(ref inner) => inner.to_bytes(buf),
        }
    }
}

impl FromBytes for InnerOnionRequest {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        alt((
            map(
                InnerOnionAnnounceRequest::from_bytes,
                InnerOnionRequest::InnerOnionAnnounceRequest,
            ),
            map(
                InnerOnionDataRequest::from_bytes,
                InnerOnionRequest::InnerOnionDataRequest,
            ),
        ))(input)
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;

    encode_decode_test!(
        inner_onion_announce_request_encode_decode,
        InnerOnionRequest::InnerOnionAnnounceRequest(InnerOnionAnnounceRequest {
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            pk: SecretKey::generate(&mut thread_rng()).public_key(),
            payload: vec![42; 123]
        })
    );

    encode_decode_test!(
        inner_onion_data_request_encode_decode,
        InnerOnionRequest::InnerOnionDataRequest(InnerOnionDataRequest {
            destination_pk: SecretKey::generate(&mut thread_rng()).public_key(),
            nonce: [42; <SalsaBox as AeadCore>::NonceSize::USIZE],
            temporary_pk: SecretKey::generate(&mut thread_rng()).public_key(),
            payload: vec![42; 123]
        })
    );
}
