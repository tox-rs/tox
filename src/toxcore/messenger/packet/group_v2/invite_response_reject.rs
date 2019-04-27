/*! InviteResponseReject struct.
*/

use nom::{be_u8, be_u32, be_u64};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/// Type of invite response reject
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InviteRejectType {
    /// Nickname is already used by other peer.
    NicknameTaken = 0x00,
    /// Bannded nickname.
    NicknameBanned,
    /// Number of member of group is full.
    GroupFull,
    /// Password is incorrect.
    InvalidPassword,
    /// Other reason.
    InviteFailed,
}

impl FromBytes for InviteRejectType {
    named!(from_bytes<InviteRejectType>,
        switch!(be_u8,
            0 => value!(InviteRejectType::NicknameTaken) |
            1 => value!(InviteRejectType::NicknameBanned) |
            2 => value!(InviteRejectType::GroupFull) |
            3 => value!(InviteRejectType::InvalidPassword) |
            4 => value!(InviteRejectType::InviteFailed)
        )
    );
}

/** InviteResponseReject is a struct that holds info to send invite response reject packet to a peer.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x5c`
`4`       | `hash id`
`32`      | `PK of sender`
`24`      | `nonce`
`1`       | `0x03`(packet kind: invite response reject)
`4`       | `sender pk hash`
`1`       | `reject_type`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InviteResponseReject {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    reject_type: InviteRejectType,
}

impl FromBytes for InviteResponseReject {
    named!(from_bytes<InviteResponseReject>, do_parse!(
        tag!("\x5c") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!("\x03") >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        reject_type: call!(InviteRejectType::from_bytes) >>
        (InviteResponseReject {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            reject_type,
        })
    ));
}

impl ToBytes for InviteResponseReject {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5c) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0x03) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_be_u8!(self.reject_type as u8)
        )
    }
}

impl InviteResponseReject {
    /// Create new InviteResponseReject object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32, reject_type: InviteRejectType) -> Self {
        InviteResponseReject {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            reject_type,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        invite_response_reject_encode_decode,
        InviteResponseReject::new(1, gen_keypair().0, gen_nonce(), 2, 3, InviteRejectType::GroupFull)
    );
}
