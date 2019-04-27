/*! LossyCustom struct.
*/

use nom::{be_u32, be_u64, rest};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::messenger::packet::group_v2::custom::MAX_CUSTOM_DATA_SIZE;

/** LossyCustom is a struct that holds info to send lossy custom packet to a peer.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x5c`
`4`       | `hash id`
`32`      | `PK of sender`
`24`      | `nonce`
`1`       | `0xf1`(packet kind: custom)
`8`       | `action id`
`4`       | `sender pk hash`
variable  | `user data`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LossyCustom {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    data: Vec<u8>,
}

impl FromBytes for LossyCustom {
    named!(from_bytes<LossyCustom>, do_parse!(
        tag!("\x5c") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!(&[0xf1][..]) >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        verify!(rest_len, |len| len <= MAX_CUSTOM_DATA_SIZE) >>
        data: rest >>
        (LossyCustom {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            data: data.to_vec(),
        })
    ));
}

impl ToBytes for LossyCustom {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5c) >>
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

impl LossyCustom {
    /// Create new LossyCustom object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32, data: Vec<u8>) -> Self {
        LossyCustom {
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
        lossy_custom_encode_decode,
        LossyCustom::new(1, gen_keypair().0, gen_nonce(), 2, 3, [32u8; 32].to_vec())
    );
}
