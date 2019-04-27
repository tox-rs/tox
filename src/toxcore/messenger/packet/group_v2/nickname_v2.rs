/*! NicknameV2 struct.
*/

use std::str;
use nom::{be_u32, be_u64, rest};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::messenger::packet::MAX_NICKNAME_DATA_SIZE;

/** NicknameV2 is a struct that holds info to send nickname packet to a group chat.
Sent to notify changing of nickname to all member of group chat.

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
`1`       | `0x01`(type: nickname)
`8`       | `timestamp`
variable  | `nickname`(UTF-8 C String)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NicknameV2 {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    timestamp: u64,
    nickname: String,
}

impl FromBytes for NicknameV2 {
    named!(from_bytes<NicknameV2>, do_parse!(
        tag!("\x5b") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!(&[0xf3][..]) >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        tag!("\x01") >>
        timestamp: be_u64 >>
        nickname: map_res!(verify!(rest, |nickname: &[u8]| nickname.len() <= MAX_NICKNAME_DATA_SIZE),
            str::from_utf8) >>
        (NicknameV2 {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            timestamp,
            nickname: nickname.to_string(),
        })
    ));
}

impl ToBytes for NicknameV2 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5b) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0xf3) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_be_u8!(0x01) >>
            gen_be_u64!(self.timestamp) >>
            gen_cond!(self.nickname.len() > MAX_NICKNAME_DATA_SIZE, |buf| gen_error(buf, 0)) >>
            gen_slice!(self.nickname.as_bytes())
        )
    }
}

impl NicknameV2 {
    /// Create new NicknameV2 object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32, timestamp: u64, nickname: String) -> Self {
        NicknameV2 {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            timestamp,
            nickname,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        nickname_v2_encode_decode,
        NicknameV2::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, "1234".to_owned())
    );

    // Test for encoding error of from_bytes.
    #[test]
    fn message_from_bytes_encoding_error() {
        let mut buf = vec![0x5b, 0x01, 0x00, 0x00, 0x00];
        let sender_pk = gen_keypair().0;
        let nonce = gen_nonce();
        let err_string = vec![0, 159, 146, 150]; // not UTF8 bytes.
        let good_string = "1234".to_owned();

        buf.extend_from_slice(sender_pk.as_ref());
        buf.extend_from_slice(nonce.as_ref());
        buf.extend_from_slice(&[0xf3, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let mut good_buf = buf.clone();
        buf.extend_from_slice(&err_string);
        assert!(NicknameV2::from_bytes(&buf).is_err());

        good_buf.extend_from_slice(good_string.as_bytes());
        assert!(NicknameV2::from_bytes(&good_buf).is_done());
    }

    // Test for overflow of from_bytes.
    #[test]
    fn message_from_bytes_overflow() {
        let mut buf = vec![0x5b, 0x01, 0x00, 0x00, 0x00];
        let sender_pk = gen_keypair().0;
        let nonce = gen_nonce();

        buf.extend_from_slice(sender_pk.as_ref());
        buf.extend_from_slice(nonce.as_ref());
        buf.extend_from_slice(&[0xf3, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let large_string = vec![32; MAX_NICKNAME_DATA_SIZE + 1];
        let good_string = vec![32; MAX_NICKNAME_DATA_SIZE];
        let mut good_buf = buf.clone();
        buf.extend_from_slice(&large_string);
        assert!(NicknameV2::from_bytes(&buf).is_err());

        good_buf.extend_from_slice(&good_string);
        assert!(NicknameV2::from_bytes(&good_buf).is_done());
    }

    // Test for overflow of to_bytes.
    #[test]
    fn message_to_bytes_overflow() {
        let large_string = String::from_utf8(vec![32u8; MAX_NICKNAME_DATA_SIZE + 1]).unwrap();
        let large_msg = NicknameV2::new(1,gen_keypair().0,gen_nonce(),2,3,4,large_string);
        let mut buf = [0; MAX_NICKNAME_DATA_SIZE + 100]; // `100` is for enough space.
        assert!(large_msg.to_bytes((&mut buf, 0)).is_err());
    }
}
