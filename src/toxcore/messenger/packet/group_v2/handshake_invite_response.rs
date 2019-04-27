/*! HandshakeInviteResponse struct.
*/

use nom::{be_u32, be_u64};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/** HandshakeInviteResponse is a struct that holds info to send handshake invite response packet to a peer.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x5a`
`4`       | `hash id`
`32`      | `PK of sender`
`24`      | `nonce`
`1`       | `0x01`(packet kind: handshake response)
`4`       | `sender pk hash`
`32`      | `enc PK`
`32`      | `sig PK`
`1`       | `0x00`(request type: invite request)
`1`       | `padding`
`4`       | `state version`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeInviteResponse {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    enc_pk: PublicKey,
    sig_pk: PublicKey,
    version: u32,
}

impl FromBytes for HandshakeInviteResponse {
    named!(from_bytes<HandshakeInviteResponse>, do_parse!(
        tag!("\x5a") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!("\x01") >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        enc_pk: call!(PublicKey::from_bytes) >>
        sig_pk: call!(PublicKey::from_bytes) >>
        tag!("\x00") >>
        take!(1) >>
        version: be_u32 >>
        (HandshakeInviteResponse {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            enc_pk,
            sig_pk,
            version,
        })
    ));
}

impl ToBytes for HandshakeInviteResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5a) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0x01) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_slice!(self.enc_pk.as_ref()) >>
            gen_slice!(self.sig_pk.as_ref()) >>
            gen_be_u8!(0x00) >>
            gen_be_u8!(0x00) >>
            gen_be_u32!(self.version)
        )
    }
}

impl HandshakeInviteResponse {
    /// Create new HandshakeInviteResponse object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32,
               enc_pk: PublicKey, sig_pk: PublicKey, version: u32) -> Self {
        HandshakeInviteResponse {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            enc_pk,
            sig_pk,
            version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        handshake_invite_response_encode_decode,
        HandshakeInviteResponse::new(1, gen_keypair().0, gen_nonce(), 2, 3, gen_keypair().0, gen_keypair().0, 4)
    );
}
