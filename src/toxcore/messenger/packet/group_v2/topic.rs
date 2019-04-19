/*! Topic struct.
*/

use std::str;
use nom::{be_u16, be_u32, be_u64};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::messenger::packet::nickname::MAX_NICKNAME_DATA_SIZE;

/// Size in bytes of signature
pub const SIGNATURE_DATA_SIZE: usize = 64;

/** Topic is a struct that holds info to send invite request packet to a peer.

Serialized form:

Length      | Content
----------- | ------
`1`         | `0x5b`
`4`         | `hash id`
`32`        | `PK of sender`
`24`        | `nonce`
`1`         | `0xfa`(packet kind: topic)
`8`         | `message id`
`4`         | `sender pk hash`
`64`        | `signature`
`2`         | `length`(of topic)
variable    | `topic` of length `length`(UTF-8 string)
`32`        | `PK`(of signature)
`4`         | `version`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Topic {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    signature: Vec<u8>,
    topic: String,
    sig_pk: PublicKey,
    version: u32,
}

impl Topic {
    /// Create new Topic object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32,
               signature: Vec<u8>, topic: String, sig_pk: PublicKey, version: u32) -> Self {
        Topic {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            signature,
            topic,
            sig_pk,
            version,
        }
    }
}

impl FromBytes for Topic {
    named!(from_bytes<Topic>, do_parse!(
        tag!("\x5b") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!(&[0xfa][..]) >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        signature: take!(64) >>
        length: verify!(be_u16, |len| len <= MAX_NICKNAME_DATA_SIZE as u16) >>
        topic: map_res!(take!(length), str::from_utf8) >>
        sig_pk: call!(PublicKey::from_bytes) >>
        version: be_u32 >>
        (Topic {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            signature: signature.to_vec(),
            topic: topic.to_string(),
            sig_pk,
            version,
        })
    ));
}

impl ToBytes for Topic {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5b) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0xfa) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_cond!(self.signature.len() != SIGNATURE_DATA_SIZE, |buf| gen_error(buf, 0)) >>
            gen_slice!(self.signature) >>
            gen_cond!(self.topic.len() > MAX_NICKNAME_DATA_SIZE, |buf| gen_error(buf, 0)) >>
            gen_be_u16!(self.topic.len()) >>
            gen_slice!(self.topic.as_bytes()) >>
            gen_slice!(self.sig_pk.as_ref()) >>
            gen_be_u32!(self.version)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        topic_encode_decode,
        Topic::new(1, gen_keypair().0, gen_nonce(), 2, 3, vec![32; SIGNATURE_DATA_SIZE], "1234".to_owned(), gen_keypair().0, 4)
    );
}
