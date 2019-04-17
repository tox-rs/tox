/*! SetModerator struct.
*/

use nom::{be_u32, be_u64};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/// Length of group chat unique bytes
pub const GROUP_UID_BYTES: usize = 32;

/// Unique id used in group chat
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupUID([u8; GROUP_UID_BYTES]);

impl GroupUID {
    /// Create new object
    pub fn random() -> GroupUID {
        let mut array = [0; GROUP_UID_BYTES];
        randombytes_into(&mut array);
        GroupUID(array)
    }

    /// Custom from_slice function of GroupUID
    pub fn from_slice(bs: &[u8]) -> Option<GroupUID> {
        if bs.len() != GROUP_UID_BYTES {
            return None
        }
        let mut n = GroupUID([0; GROUP_UID_BYTES]);
        for (ni, &bsi) in n.0.iter_mut().zip(bs.iter()) {
            *ni = bsi
        }
        Some(n)
    }
}

impl FromBytes for GroupUID {
    named!(from_bytes<GroupUID>, map_opt!(take!(GROUP_UID_BYTES), GroupUID::from_slice));
}

/// Enum of Set or Unset to moderator
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetRole {
    /// Set to user
    ToUser(ToUser),
    /// Set to moderator
    ToModerator(ToModerator),
}

impl ToBytes for SetRole {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            SetRole::ToUser(ref p) => p.to_bytes(buf),
            SetRole::ToModerator(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for SetRole {
    named!(from_bytes<SetRole>, alt!(
        map!(ToUser::from_bytes, SetRole::ToUser) |
        map!(ToModerator::from_bytes, SetRole::ToModerator)
    ));
}

/// Set to user
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToUser(PublicKey);

impl ToUser {
    /// Create new object
    pub fn new(pk: PublicKey) -> Self {
        ToUser(pk)
    }
}

impl FromBytes for ToUser {
    named!(from_bytes<ToUser>, do_parse!(
        tag!("\x00") >>
        pk: call!(PublicKey::from_bytes) >>
        (ToUser(pk))
    ));
}

impl ToBytes for ToUser {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x00) >>
            gen_slice!(self.0.as_ref())
        )
    }
}

/// Set to moderator
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToModerator(GroupUID);

impl FromBytes for ToModerator {
    named!(from_bytes<ToModerator>, do_parse!(
        none_of!("\x00") >>
        hash: call!(GroupUID::from_bytes) >>
        (ToModerator(hash))
    ));
}

impl ToModerator {
    /// Create new object
    pub fn new(hash: GroupUID) -> Self {
        ToModerator(hash)
    }
}

impl ToBytes for ToModerator {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x01) >>
            gen_slice!((self.0).0)
        )
    }
}

/** SetModerator is a struct that holds info to send set/unset moderator packet to a group chat.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x5b`
`4`       | `hash id`
`32`      | `PK of sender`
`24`      | `nonce`
`1`       | `0xf3`(packet kind: broadcast)
`8`       | `message id`
`4`       | `sender pk hash`
`1`       | `0x08`(type: set moderator)
`8`       | `timestamp`
`33`      | `role`(set to user or moderator)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetModerator {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    timestamp: u64,
    role: SetRole,
}

impl FromBytes for SetModerator {
    named!(from_bytes<SetModerator>, do_parse!(
        tag!("\x5b") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!(&[0xf3][..]) >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        tag!("\x08") >>
        timestamp: be_u64 >>
        role: call!(SetRole::from_bytes) >>
        (SetModerator {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            timestamp,
            role,
        })
    ));
}

impl ToBytes for SetModerator {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5b) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0xf3) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_be_u8!(0x08) >>
            gen_be_u64!(self.timestamp) >>
            gen_call!(|buf, role| SetRole::to_bytes(role, buf), &self.role)
        )
    }
}

impl SetModerator {
    /// Create new SetModerator object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32, timestamp: u64, role: SetRole) -> Self {
        SetModerator {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            timestamp,
            role,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        set_moderator_encode_decode,
        SetModerator::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, SetRole::ToUser(ToUser::new(gen_keypair().0)))
    );

    encode_decode_test!(
        set_moderator_enum_encode_decode,
        SetModerator::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, SetRole::ToModerator(ToModerator::new(GroupUID::random())))
    );
}
