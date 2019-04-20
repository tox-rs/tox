/*! SanctionList struct.
*/

use nom::{be_u32, be_u64};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::messenger::packet::group_v2::remove_peer::*;

/** SanctionList is a struct that holds info to send sanction list packet to a peer.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x5b`
`4`       | `hash id`
`32`      | `PK of sender`
`24`      | `nonce`
`1`       | `0xfd`(packet kind: sanction list)
`8`       | `message id`
`4`       | `sender pk hash`
`4`       | `number`(of sanctions)
variable  | `sanction list`

An entry of `sanction list` is

Length    | Content
--------- | ------
`1`       | `type`(see below)
`32`      | PK of signature
`8`       | timestamp
variable  | Data

`Data` depends on `type`.

`type` is

- `SA_BAN_IP_PORT`,
- `SA_BAN_PUBLIC_KEY`,
- `SA_BAN_NICK`,
- `SA_OBSERVER`,

- SA_BAN_IP_PORT

Serialized form:

Length      | Content
------------| ------
`4`         | `id`
`1`         | `type`(of ip)
`4` or `16` | IPv4 or IPv6 address
`2`         | port

- SA_BAN_NICK

Serialized form:

Length      | Content
------------| ------
`4`         | `id`
`128`       | nickname

- SA_BAN_PUBLIC_KEY

Serialized form:

Length      | Content
------------| ------
`4`         | `id`
`32`        | PK of target

- SA_OBSERVER

Serialized form:

Length      | Content
------------| ------
`32`        | PK of target

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SanctionList {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    sanctions: Vec<Sanction>,
}

impl FromBytes for SanctionList {
    named!(from_bytes<SanctionList>, do_parse!(
        tag!("\x5b") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!(&[0xfd][..]) >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        take!(4) >>
        sanctions: many0!(Sanction::from_bytes) >>
        (SanctionList {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            sanctions,
        })
    ));
}

impl ToBytes for SanctionList {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5b) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0xfd) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_be_u32!(self.sanctions.len()) >>
            gen_many_ref!(&self.sanctions, |buf, sanction| Sanction::to_bytes(sanction, buf))
        )
    }
}

impl SanctionList {
    /// Create new SanctionList object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32, sanctions: Vec<Sanction>) -> Self {
        SanctionList {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            sanctions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toxcore::ip_port::*;

    encode_decode_test!(
        sanction_list_encode_decode,
        SanctionList::new(1, gen_keypair().0, gen_nonce(), 2, 3, vec![
            Sanction(SanctionType::BanIpPort(
                BanIpPort::new(
                    gen_keypair().0, 1, 2, IpPort::from_udp_saddr("127.0.0.1:33445".parse().unwrap())
                )
            )),
            Sanction(SanctionType::BanPublicKey(
                BanPublicKey::new(gen_keypair().0, 3, 4, gen_keypair().0
                )
            )),
            Sanction(SanctionType::BanNickname(
                BanNickname::new(gen_keypair().0, 5, 6, String::from_utf8([32; 128].to_vec()).unwrap()
                )
            )),
            Sanction(SanctionType::Observer(
                Observer::new(gen_keypair().0, 7, gen_keypair().0
                )
            ))
        ])
    );
}