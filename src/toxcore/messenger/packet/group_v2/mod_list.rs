/*! ModList struct.
*/

use nom::{be_u32, be_u64};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/** ModList is a struct that holds info to send mod list packet to a peer.

Serialized form:

Length      | Content
----------- | ------
`1`         | `0x5b`
`4`         | `hash id`
`32`        | `PK of sender`
`24`        | `nonce`
`1`         | `0xfc`(packet kind: mod list)
`8`         | `message id`
`4`         | `sender pk hash`
`2`         | `number`(of moderators)
variable    | `mod list`

An entry of `mod list` is

Length      | Content
------------|-------
`32`        | `PK of signature`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModList {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    pks: Vec<PublicKey>,
}

impl FromBytes for ModList {
    named!(from_bytes<ModList>, do_parse!(
        tag!("\x5b") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!(&[0xfc][..]) >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        take!(2) >>
        pks: many0!(call!(PublicKey::from_bytes)) >>
        (ModList {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            pks,
        })
    ));
}

impl ToBytes for ModList {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5b) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0xfc) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_be_u16!(self.pks.len()) >>
            gen_many_ref!(&self.pks, |buf: (&'a mut [u8], usize), pk: &PublicKey| do_gen!(buf, gen_slice!(pk.as_ref())))
        )
    }
}

impl ModList {
    /// Create new ModList object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32, pks: Vec<PublicKey>) -> Self {
        ModList {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            pks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        mod_list_encode_decode,
        ModList::new(1, gen_keypair().0, gen_nonce(), 2, 3, vec![gen_keypair().0, gen_keypair().0, gen_keypair().0])
    );
}
