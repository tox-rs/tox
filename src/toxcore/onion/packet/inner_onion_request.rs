/*! InnerOnionRequest enum
*/

use super::*;

use crate::toxcore::binary_io::*;

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
    InnerOnionDataRequest(InnerOnionDataRequest)
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
    named!(from_bytes<InnerOnionRequest>, alt!(
        map!(InnerOnionAnnounceRequest::from_bytes, InnerOnionRequest::InnerOnionAnnounceRequest) |
        map!(InnerOnionDataRequest::from_bytes, InnerOnionRequest::InnerOnionDataRequest)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        inner_onion_announce_request_encode_decode,
        InnerOnionRequest::InnerOnionAnnounceRequest(InnerOnionAnnounceRequest {
            nonce: gen_nonce(),
            pk: gen_keypair().0,
            payload: vec![42; 123]
        })
    );

    encode_decode_test!(
        inner_onion_data_request_encode_decode,
        InnerOnionRequest::InnerOnionDataRequest(InnerOnionDataRequest {
            destination_pk: gen_keypair().0,
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123]
        })
    );
}
