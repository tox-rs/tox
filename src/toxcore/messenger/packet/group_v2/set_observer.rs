/*! SetObserver struct.
*/

use nom::{be_u8, be_u32, be_u64};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::messenger::packet::group_v2::remove_peer::*;

/// Set/unset sanctions
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetOrUnset {
    /// Unset sanctions
    Unset = 0x00,
    /// Set sanctions
    Set,
}

impl FromBytes for SetOrUnset {
    named!(from_bytes<SetOrUnset>,
        switch!(be_u8,
            0 => value!(SetOrUnset::Unset) |
            _ => value!(SetOrUnset::Set)
        )
    );
}

/** SetObserver is a struct that holds info to send set observer packet to a group chat.
Sent to notify set/unset to observer of sanctions to all member of group chat.

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
`1`       | `0x09`(type: set observer)
`8`       | `timestamp`
`1`       | `kind`(0 = remove sanction, otherwise = set sanction)
`32`      | `PK`
variable  | `sanction list`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetObserver {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    timestamp: u64,
    kind: SetOrUnset,
    pk: PublicKey,
    sanctions: Vec<Sanction>,
}

impl FromBytes for SetObserver {
    named!(from_bytes<SetObserver>, do_parse!(
        tag!("\x5b") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!(&[0xf3][..]) >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        tag!("\x09") >>
        timestamp: be_u64 >>
        kind: call!(SetOrUnset::from_bytes) >>
        pk: call!(PublicKey::from_bytes) >>
        sanctions: many0!(Sanction::from_bytes) >>
        (SetObserver {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            timestamp,
            kind,
            pk,
            sanctions,
        })
    ));
}

impl ToBytes for SetObserver {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5b) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0xf3) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_be_u8!(0x09) >>
            gen_be_u64!(self.timestamp) >>
            gen_be_u8!(self.kind as u8) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_many_ref!(&self.sanctions, |buf, sanction| Sanction::to_bytes(sanction, buf))
        )
    }
}

impl SetObserver {
    /// Create new SetObserver object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32, timestamp: u64, kind: SetOrUnset, pk: PublicKey, sanctions: Vec<Sanction>) -> Self {
        SetObserver {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            timestamp,
            kind,
            pk,
            sanctions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toxcore::ip_port::*;

    encode_decode_test!(
        set_observer_encode_decode,
        SetObserver::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, SetOrUnset::Set, gen_keypair().0,
            vec![
                Sanction(SanctionType::BanIpPort(
                    BanIpPort::new(
                    gen_keypair().0, 1, 2, IpPort::from_udp_saddr("127.0.0.1:33445".parse().unwrap())
                )
            ))]
        )
    );
}
