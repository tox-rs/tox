/*! PeerInfoResponse struct.
*/

use std::str;
use nom::{be_u8, be_u32, be_u64, IResult};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/// Role in group chat.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Role of founder.
    Founder = 0x00,
    /// Role of moderator.
    Moderator,
    /// Role of user.
    User,
    /// Role of observer.
    Observer,
}

impl FromBytes for Role {
    named!(from_bytes<Role>,
        switch!(be_u8,
            0 => value!(Role::Founder) |
            1 => value!(Role::Moderator) |
            2 => value!(Role::User) |
            3 => value!(Role::Observer)
        )
    );
}

/// Status of peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerStatus {
    /// Peer is online.
    Online = 0x00,
    /// Peer is away,
    Away,
    /// Peer is busy.
    Busy,
}

impl FromBytes for PeerStatus {
    named!(from_bytes<PeerStatus>,
        switch!(be_u8,
            0 => value!(PeerStatus::Online) |
            1 => value!(PeerStatus::Away) |
            2 => value!(PeerStatus::Busy)
        )
    );
}

/// Use password or not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsePassword {
    /// Chatting room uses password.
    Use,
    /// Chatting room doesn't use password.
    NotUse,
}

/// Length of group chat password bytes
pub const GROUP_PASSWORD_BYTES: usize = 32;

/// Password used in group chat
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupPassword(pub [u8; GROUP_PASSWORD_BYTES]);

impl GroupPassword {
    /// Custom from_slice function of GroupPassword
    pub fn from_slice(bs: &[u8]) -> Option<GroupPassword> {
        if bs.len() != GROUP_PASSWORD_BYTES {
            return None
        }
        let mut n = GroupPassword([0; GROUP_PASSWORD_BYTES]);
        for (ni, &bsi) in n.0.iter_mut().zip(bs.iter()) {
            *ni = bsi
        }
        Some(n)
    }
}

impl FromBytes for GroupPassword {
    named!(from_bytes<GroupPassword>, map_opt!(take!(GROUP_PASSWORD_BYTES), GroupPassword::from_slice));
}

/** PeerInfoResponse is a struct that holds info to send peer info request packet to a peer.

Serialized form:

Length      | Content
----------- | ------
`1`         | `0x5b`
`4`         | `hash id`
`32`        | `PK of sender`
`24`        | `nonce`
`1`         | `0xf5`(packet kind: peer info response)
`8`         | `message id`
`4`         | `sender pk hash`
`32`        | `password`(comes only when password is setted)
`2`         | `length` of nickname
`128`       | `nickname`(UTF-8 string)
`1`         | `peer status`
`1`         | `role`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerInfoResponse {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    password: Option<GroupPassword>,
    nickname: String,
    status: PeerStatus,
    role: Role,
}

impl PeerInfoResponse {
    /// Create new PeerInfoResponse object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32,
        password: Option<GroupPassword>, nickname: String, status: PeerStatus, role: Role) -> Self {
        PeerInfoResponse {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            password,
            nickname,
            status,
            role,
        }
    }

    /// `password` comes only when chatting room is locked using password.
    pub fn from_custom_bytes(input: &[u8], use_password: UsePassword) -> IResult<&[u8], PeerInfoResponse> {
        do_parse!(input,
            tag!("\x5b") >>
            hash_id: be_u32 >>
            sender_pk: call!(PublicKey::from_bytes) >>
            nonce: call!(Nonce::from_bytes) >>
            tag!(&[0xf5][..]) >>
            message_id: be_u64 >>
            sender_pk_hash: be_u32 >>
            password: cond!(use_password == UsePassword::Use, call!(GroupPassword::from_bytes)) >>
            take!(2) >>
            nickname: map_res!(take!(128), str::from_utf8) >>
            status: call!(PeerStatus::from_bytes) >>
            role: call!(Role::from_bytes) >>
            (PeerInfoResponse {
                hash_id,
                sender_pk,
                nonce,
                message_id,
                sender_pk_hash,
                password,
                nickname: nickname.to_string(),
                status,
                role,
            })
        )
    }

    /// Write `PeerInfoResponse` with use password option.
    pub fn to_custom_bytes<'a>(&self, buf: (&'a mut [u8], usize), use_password: UsePassword) -> Result<(&'a mut [u8], usize), GenError> {
        let padding = vec![0u8; 128 - self.nickname.len()];
        do_gen!(buf,
            gen_be_u8!(0x5b) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0xf5) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_cond!(use_password == UsePassword::Use, gen_slice!(&self.password.unwrap().0)) >>
            gen_be_u16!(self.nickname.len() as u16) >>
            gen_slice!(self.nickname.as_bytes()) >>
            gen_slice!(padding) >>
            gen_be_u8!(self.status as u8) >>
            gen_be_u8!(self.role as u8)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! peer_info_response_with_password_encode_decode_test (
        ($test:ident, $password:expr) => (
            #[test]
            fn $test() {
                let password: Option<GroupPassword> = $password;
                let value = PeerInfoResponse::new(1, gen_keypair().0, gen_nonce(), 2, 3, password, "a".repeat(128), PeerStatus::Online, Role::User);
                let use_password = if password.is_some() {
                        UsePassword::Use
                    } else {
                        UsePassword::NotUse
                    };
                let mut buf = [0; 240];
                let (_, size) = value.to_custom_bytes((&mut buf, 0), use_password).unwrap();
                let (rest, decoded_value) = PeerInfoResponse::from_custom_bytes(&buf[..size], use_password).unwrap();
                assert!(rest.is_empty());
                assert_eq!(decoded_value, value);
            }
        )
    );

    peer_info_response_with_password_encode_decode_test!(peer_info_response_with_password_encode_decode, Some(GroupPassword([0u8; 32])));
    peer_info_response_with_password_encode_decode_test!(peer_info_response_without_password_encode_decode, None);
}
