/*! Ping struct.
*/

use nom::{be_u32, be_u64};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/** Ping is a struct that holds info to send ping packet to a group chat.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x5c`
`4`       | `hash id`
`32`      | `PK of sender`
`24`      | `nonce`
`1`       | `0x01`(packet kind: ping)
`4`       | `sender pk hash`
`4`       | `num peers`
`4`       | `state version`
`4`       | `screds version`
`4`       | `topic version`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ping {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    num_peers: u32,
    state_version: u32,
    screds_version: u32,
    topic_version: u32,
}

impl FromBytes for Ping {
    named!(from_bytes<Ping>, do_parse!(
        tag!("\x5c") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!("\x01") >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        num_peers: be_u32 >>
        state_version: be_u32 >>
        screds_version: be_u32 >>
        topic_version: be_u32 >>
        (Ping {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            num_peers,
            state_version,
            screds_version,
            topic_version,
        })
    ));
}

impl ToBytes for Ping {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5c) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0x01) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_be_u32!(self.num_peers) >>
            gen_be_u32!(self.state_version) >>
            gen_be_u32!(self.screds_version) >>
            gen_be_u32!(self.topic_version)
        )
    }
}

impl Ping {
    /// Create new Ping object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32,
               num_peers: u32, state_version: u32, screds_version: u32, topic_version: u32) -> Self {
        Ping {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            num_peers,
            state_version,
            screds_version,
            topic_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        ping_encode_decode,
        Ping::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, 5, 6, 7)
    );
}
