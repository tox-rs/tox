/*! Custom struct.
*/

use nom::{be_u32, be_u64, rest};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use super::MAX_MESSAGE_V2_DATA_SIZE;

/// Maximum length in bytes of data size of custom packet.
const MAX_CUSTOM_DATA_SIZE: usize = MAX_MESSAGE_V2_DATA_SIZE + 9;

/** Custom is a struct that holds info to send custom packet to a group chat.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x5b`
`4`       | `hash id`
`32`      | `PK of sender`
`24`      | `nonce`
`1`       | `0xf1`(packet kind: custom)
`8`       | `action id`
`4`       | `sender pk hash`
variable  | `user data`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Custom {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    data: Vec<u8>,
}

impl FromBytes for Custom {
    named!(from_bytes<Custom>, do_parse!(
        tag!("\x5b") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!(&[0xf1][..]) >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        verify!(rest_len, |len| len <= MAX_CUSTOM_DATA_SIZE) >>
        data: rest >>
        (Custom {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            data: data.to_vec(),
        })
    ));
}

impl ToBytes for Custom {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5b) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0xf1) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_cond!(self.data.len() > MAX_CUSTOM_DATA_SIZE, |buf| gen_error(buf, 0)) >>
            gen_slice!(self.data)
        )
    }
}

impl Custom {
    /// Create new Custom object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32, data: Vec<u8>) -> Self {
        Custom {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        custom_encode_decode,
        Custom::new(1, gen_keypair().0, gen_nonce(), 2, 3, [32u8; 32].to_vec())
    );
}
