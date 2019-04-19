/*! InviteRequest struct.
*/

use std::str;
use nom::{be_u16, be_u32, be_u64};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::messenger::packet::nickname::MAX_NICKNAME_DATA_SIZE;
use crate::toxcore::messenger::packet::group_v2::peer_info_response::*;

/** InviteRequest is a struct that holds info to send invite request packet to a peer.

Serialized form:

Length      | Content
----------- | ------
`1`         | `0x5b`
`4`         | `hash id`
`32`        | `PK of sender`
`24`        | `nonce`
`1`         | `0xf6`(packet kind: invite request)
`8`         | `message id`
`4`         | `sender pk hash`
`2`         | `length`(of nickname)
variable    | `nickname` of length `length`(UTF-8 string)
`32`        | `password`(comes only when password is setted)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InviteRequest {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    nickname: String,
    password: Option<GroupPassword>,
}

impl InviteRequest {
    /// Create new InviteRequest object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32, nickname: String, password: Option<GroupPassword>) -> Self {
        InviteRequest {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            nickname,
            password,
        }
    }

    /// `password` comes only when chatting room is locked using password.
    pub fn from_custom_bytes(input: &[u8], use_password: UsePassword) -> IResult<&[u8], InviteRequest> {
        do_parse!(input,
            tag!("\x5b") >>
            hash_id: be_u32 >>
            sender_pk: call!(PublicKey::from_bytes) >>
            nonce: call!(Nonce::from_bytes) >>
            tag!(&[0xf6][..]) >>
            message_id: be_u64 >>
            sender_pk_hash: be_u32 >>
            length: verify!(be_u16, |len| len <= MAX_NICKNAME_DATA_SIZE as u16) >>
            nickname: map_res!(take!(length), str::from_utf8) >>
            password: cond!(use_password == UsePassword::Use, call!(GroupPassword::from_bytes)) >>
            (InviteRequest {
                hash_id,
                sender_pk,
                nonce,
                message_id,
                sender_pk_hash,
                nickname: nickname.to_string(),
                password,
            })
        )
    }

    /// `password` comes only when chatting room is locked using password.
    pub fn to_custom_bytes<'a>(&self, buf: (&'a mut [u8], usize), use_password: UsePassword) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5b) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0xf6) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_cond!(self.nickname.len() > MAX_NICKNAME_DATA_SIZE, |buf| gen_error(buf, 0)) >>
            gen_be_u16!(self.nickname.len()) >>
            gen_slice!(self.nickname.as_bytes()) >>
            gen_cond!(use_password == UsePassword::Use, gen_slice!(&self.password.unwrap().0))
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! invite_request_with_password_encode_decode_test (
        ($test:ident, $password:expr) => (
            #[test]
            fn $test() {
                let password: Option<GroupPassword> = $password;
                let value = InviteRequest::new(1, gen_keypair().0, gen_nonce(), 2, 3, "1234".to_owned(), password);
                let use_password = if password.is_some() {
                        UsePassword::Use
                    } else {
                        UsePassword::NotUse
                    };
                let mut buf = [0; 240];
                let (_, size) = value.to_custom_bytes((&mut buf, 0), use_password).unwrap();
                let (rest, decoded_value) = InviteRequest::from_custom_bytes(&buf[..size], use_password).unwrap();
                assert!(rest.is_empty());
                assert_eq!(decoded_value, value);
            }
        )
    );

    invite_request_with_password_encode_decode_test!(invite_request_with_password_encode_decode, Some(GroupPassword([0u8; 32])));
    invite_request_with_password_encode_decode_test!(invite_request_without_password_encode_decode, None);
}
