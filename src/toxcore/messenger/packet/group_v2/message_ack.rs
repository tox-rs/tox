/*! MessageAck struct.
*/

use nom::{be_u8, be_u32, be_u64};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/** MessageAck is a struct that holds info to send message ack packet to a group chat.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x5c`
`4`       | `hash id`
`32`      | `PK of sender`
`24`      | `nonce`
`1`       | `0x02`(packet kind: message ack)
`4`       | `sender pk hash`
`1`       | `read id`
`1`       | `request id`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageAck {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    read_id: u8,
    request_id: u8,
}

impl FromBytes for MessageAck {
    named!(from_bytes<MessageAck>, do_parse!(
        tag!("\x5c") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!("\x02") >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        read_id: be_u8 >>
        request_id: be_u8 >>
        (MessageAck {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            read_id,
            request_id,
        })
    ));
}

impl ToBytes for MessageAck {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5c) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0x02) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_be_u8!(self.read_id) >>
            gen_be_u8!(self.request_id)
        )
    }
}

impl MessageAck {
    /// Create new MessageAck object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32, read_id: u8, request_id: u8) -> Self {
        MessageAck {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            read_id,
            request_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        message_ack_encode_decode,
        MessageAck::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, 5)
    );
}
