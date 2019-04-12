/*! Status struct.
*/

use nom::{be_u8, be_u32, be_u64};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/// Enum of peer status in group chat v2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerStatusV2 {
    /// Peer status of None
    GsNone = 0x00,
    /// Peer status of Away
    GsAway,
    /// Peer status of Busy
    GsBusy,
    /// Invalid value
    GsInvalid,
}

impl FromBytes for PeerStatusV2 {
    named!(from_bytes<PeerStatusV2>,
        switch!(be_u8,
            0 => value!(PeerStatusV2::GsNone) |
            1 => value!(PeerStatusV2::GsAway) |
            2 => value!(PeerStatusV2::GsBusy) |
            3 => value!(PeerStatusV2::GsInvalid)
        )
    );
}

/** Status is a struct that holds status of peer and used to send status packet to a group chat.

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
`1`       | `0x00`(type: status)
`8`       | `timestamp`
`1`       | `status`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    timestamp: u64,
    status: PeerStatusV2,
}

impl FromBytes for Status {
    named!(from_bytes<Status>, do_parse!(
        tag!("\x5b") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!(&[0xf3][..]) >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        tag!("\x00") >>
        timestamp: be_u64 >>
        status: call!(PeerStatusV2::from_bytes) >>
        (Status {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            timestamp,
            status,
        })
    ));
}

impl ToBytes for Status {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5b) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0xf3) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_be_u8!(0x00) >>
            gen_be_u64!(self.timestamp) >>
            gen_be_u8!(self.status as u8)
        )
    }
}

impl Status {
    /// Create new Status object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32, timestamp: u64, status: PeerStatusV2) -> Self {
        Status {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            timestamp,
            status,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        status_encode_decode,
        Status::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, PeerStatusV2::GsNone)
    );
}
