/*! SharedState struct.
*/

use std::str;
use nom::{be_u8, be_u16, be_u32, be_u64};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::messenger::packet::group_v2::peer_info_response::*;
use crate::toxcore::messenger::packet::group_v2::topic::SIGNATURE_DATA_SIZE;

/// Privacy state of group chat
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyState {
    /// Public chat room
    Public = 0x00,
    /// Private chat room
    Private,
}

impl FromBytes for PrivacyState {
    named!(from_bytes<PrivacyState>,
        switch!(be_u8,
            0 => value!(PrivacyState::Public) |
            1 => value!(PrivacyState::Private)
        )
    );
}

/// Length in bytes of moderation hash
pub const MODERATION_HASH_DATA_SIZE: usize = 32;

/// Length in bytes of group name
pub const GROUP_NAME_DATA_SIZE: usize = 48;

/// Moderation hash object
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModerationHash(pub [u8; MODERATION_HASH_DATA_SIZE]);

impl ModerationHash {
    /// Custom from_slice function of ModerationHash
    pub fn from_slice(bs: &[u8]) -> Option<ModerationHash> {
        if bs.len() != MODERATION_HASH_DATA_SIZE {
            return None
        }
        let mut n = ModerationHash([0; MODERATION_HASH_DATA_SIZE]);
        for (ni, &bsi) in n.0.iter_mut().zip(bs.iter()) {
            *ni = bsi
        }
        Some(n)
    }
}

impl FromBytes for ModerationHash {
    named!(from_bytes<ModerationHash>, map_opt!(take!(MODERATION_HASH_DATA_SIZE), ModerationHash::from_slice));
}

/** SharedState is a struct that holds info to send shared state packet to a peer.

Serialized form:

Length      | Content
----------- | ------
`1`         | `0x5b`
`4`         | `hash id`
`32`        | `PK of sender`
`24`        | `nonce`
`1`         | `0xfb`(packet kind: shared state)
`8`         | `message id`
`4`         | `sender pk hash`
`64`        | `signature`
`32`        | `PK`(of founder)
`2`         | `length`(of group name)
variable    | `group name` of length `length`(UTF-8 string)
`1`         | `privacy state`
`2`         | `password length`
`32`        | `password`
`32`        | `moderation hash`
`4`         | `version`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedState {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    signature: Vec<u8>,
    founder_pk: PublicKey,
    group_name: String,
    privacy_state: PrivacyState,
    password: GroupPassword,
    moderation_hash: ModerationHash,
    version: u32,
}

impl SharedState {
    /// Create new SharedState object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32,
               signature: Vec<u8>, founder_pk: PublicKey, group_name: String,  privacy_state: PrivacyState, password: GroupPassword,
               moderation_hash: ModerationHash, version: u32) -> Self {
        SharedState {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            signature,
            founder_pk,
            group_name,
            privacy_state,
            password,
            moderation_hash,
            version,
        }
    }
}

// It has length of group name, but this length value is always 48. It is current state of spec of group chat v2.
// And length of password has the same style.
impl FromBytes for SharedState {
    named!(from_bytes<SharedState>, do_parse!(
        tag!("\x5b") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!(&[0xfb][..]) >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        signature: take!(SIGNATURE_DATA_SIZE) >>
        founder_pk: call!(PublicKey::from_bytes) >>
        length: verify!(be_u16, |len| len == GROUP_NAME_DATA_SIZE as u16) >>
        group_name: map_res!(take!(length), str::from_utf8) >>
        privacy_state: call!(PrivacyState::from_bytes) >>
        _pass_len: verify!(be_u16, |len| len == GROUP_PASSWORD_BYTES as u16) >>
        password: call!(GroupPassword::from_bytes) >>
        moderation_hash: call!(ModerationHash::from_bytes) >>
        version: be_u32 >>
        (SharedState {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            signature: signature.to_vec(),
            founder_pk,
            group_name: group_name.to_string(),
            privacy_state,
            password,
            moderation_hash,
            version,
        })
    ));
}

impl ToBytes for SharedState {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5b) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0xfb) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_cond!(self.signature.len() != SIGNATURE_DATA_SIZE, |buf| gen_error(buf, 0)) >>
            gen_slice!(self.signature) >>
            gen_slice!(self.founder_pk.as_ref()) >>
            gen_cond!(self.group_name.len() != GROUP_NAME_DATA_SIZE, |buf| gen_error(buf, 0)) >>
            gen_be_u16!(self.group_name.len()) >>
            gen_slice!(self.group_name.as_bytes()) >>
            gen_be_u8!(self.privacy_state as u8) >>
            gen_cond!(self.password.0.len() != GROUP_PASSWORD_BYTES, |buf| gen_error(buf, 0)) >>
            gen_be_u16!(self.password.0.len()) >>
            gen_slice!(self.password.0) >>
            gen_slice!(self.moderation_hash.0) >>
            gen_be_u32!(self.version)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        shared_state_encode_decode,
        SharedState::new(1, gen_keypair().0, gen_nonce(), 2, 3, vec![32u8; SIGNATURE_DATA_SIZE], gen_keypair().0,
            String::from_utf8(vec![32u8; GROUP_NAME_DATA_SIZE]).unwrap(),
            PrivacyState::Public, GroupPassword([32u8; GROUP_PASSWORD_BYTES]),
            ModerationHash([32u8; MODERATION_HASH_DATA_SIZE]), 4)
    );
}
