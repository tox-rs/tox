/*! RemovePeer struct.
*/

use std::str;
use nom::{be_u8, be_u32, be_u64};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::ip_port::*;

/// Enums of event of group chat v2
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventV2 {
    /// Event of kick
    Kick = 0x00,
    /// Event of ban
    Ban,
    /// Event of to observer
    Observer,
    /// Event of to user
    User,
    /// Event of to moderator
    Moderator,
    /// Invalid value
    Invalid,
}

impl FromBytes for EventV2 {
    named!(from_bytes<EventV2>,
        switch!(be_u8,
            0 => value!(EventV2::Kick) |
            1 => value!(EventV2::Ban) |
            2 => value!(EventV2::Observer) |
            3 => value!(EventV2::User) |
            4 => value!(EventV2::Moderator) |
            5 => value!(EventV2::Invalid)
        )
    );
}

/// Type of sanction
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SanctionType {
    /// Ban to ip and port
    BanIpPort(BanIpPort),
    /// Ban to public key
    BanPublicKey(BanPublicKey),
    /// Ban to nickname
    BanNickname(BanNickname),
    /// To observer
    Observer(Observer),
}

impl ToBytes for SanctionType {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            SanctionType::BanIpPort(ref p) => p.to_bytes(buf),
            SanctionType::BanPublicKey(ref p) => p.to_bytes(buf),
            SanctionType::BanNickname(ref p) => p.to_bytes(buf),
            SanctionType::Observer(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for SanctionType {
    named!(from_bytes<SanctionType>, alt!(
        map!(BanIpPort::from_bytes, SanctionType::BanIpPort) |
        map!(BanPublicKey::from_bytes, SanctionType::BanPublicKey) |
        map!(BanNickname::from_bytes, SanctionType::BanNickname) |
        map!(Observer::from_bytes, SanctionType::Observer)
    ));
}

/// Sanction of ban to an Ip and port
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BanIpPort {
    sig_pk: PublicKey,
    timestamp: u64,
    sanction_id: u32,
    ip_port: IpPort,
}

impl BanIpPort {
    /// Create new object
    pub fn new (sig_pk: PublicKey, timestamp: u64, sanction_id: u32, ip_port: IpPort) -> Self {
        BanIpPort {
            sig_pk,
            timestamp,
            sanction_id,
            ip_port,
        }
    }
}

impl FromBytes for BanIpPort {
    named!(from_bytes<BanIpPort>, do_parse!(
        tag!("\x00") >>
        sig_pk: call!(PublicKey::from_bytes) >>
        timestamp: be_u64 >>
        sanction_id: be_u32 >>
        ip_port: call!(IpPort::from_bytes, IpPortPadding::NoPadding) >>
        (BanIpPort {
            sig_pk,
            timestamp,
            sanction_id,
            ip_port,
        })
    ));
}

impl ToBytes for BanIpPort {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x00) >>
            gen_slice!(self.sig_pk.as_ref()) >>
            gen_be_u64!(self.timestamp) >>
            gen_be_u32!(self.sanction_id) >>
            gen_call!(|buf, ip_port| IpPort::to_bytes(ip_port, buf, IpPortPadding::NoPadding), &self.ip_port)
    )}
}

/// Sanction of ban to a public key
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BanPublicKey {
    sig_pk: PublicKey,
    timestamp: u64,
    sanction_id: u32,
    pk: PublicKey,
}

impl BanPublicKey {
    /// Create new object
    pub fn new (sig_pk: PublicKey, timestamp: u64, sanction_id: u32, pk: PublicKey) -> Self {
        BanPublicKey {
            sig_pk,
            timestamp,
            sanction_id,
            pk,
        }
    }
}

impl FromBytes for BanPublicKey {
    named!(from_bytes<BanPublicKey>, do_parse!(
        tag!("\x01") >>
        sig_pk: call!(PublicKey::from_bytes) >>
        timestamp: be_u64 >>
        sanction_id: be_u32 >>
        pk: call!(PublicKey::from_bytes) >>
        (BanPublicKey {
            sig_pk,
            timestamp,
            sanction_id,
            pk,
        })
    ));
}

impl ToBytes for BanPublicKey {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x01) >>
            gen_slice!(self.sig_pk.as_ref()) >>
            gen_be_u64!(self.timestamp) >>
            gen_be_u32!(self.sanction_id) >>
            gen_slice!(self.pk.as_ref())
    )}
}

/// Sanction of ban to a nick name
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BanNickname {
    sig_pk: PublicKey,
    timestamp: u64,
    sanction_id: u32,
    nickname: String,
}

impl BanNickname {
    /// Create new object
    pub fn new (sig_pk: PublicKey, timestamp: u64, sanction_id: u32, nickname: String) -> Self {
        BanNickname {
            sig_pk,
            timestamp,
            sanction_id,
            nickname,
        }
    }
}

impl FromBytes for BanNickname {
    named!(from_bytes<BanNickname>, do_parse!(
        tag!("\x02") >>
        sig_pk: call!(PublicKey::from_bytes) >>
        timestamp: be_u64 >>
        sanction_id: be_u32 >>
        nickname: map_res!(take!(128), str::from_utf8) >>
        (BanNickname {
            sig_pk,
            timestamp,
            sanction_id,
            nickname: nickname.to_string(),
        })
    ));
}

impl ToBytes for BanNickname {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        let padding = vec![0u8; 128 - self.nickname.len()];
        do_gen!(buf,
            gen_be_u8!(0x02) >>
            gen_slice!(self.sig_pk.as_ref()) >>
            gen_be_u64!(self.timestamp) >>
            gen_be_u32!(self.sanction_id) >>
            gen_slice!(self.nickname.as_bytes()) >>
            gen_slice!(padding)
    )}
}

/// Sanction of changing role to observer to a peer
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observer {
    sig_pk: PublicKey,
    timestamp: u64,
    pk: PublicKey,
}

impl Observer {
    /// Create new object
    pub fn new (sig_pk: PublicKey, timestamp: u64, pk: PublicKey) -> Self {
        Observer {
            sig_pk,
            timestamp,
            pk,
        }
    }
}

impl FromBytes for Observer {
    named!(from_bytes<Observer>, do_parse!(
        tag!("\x03") >>
        sig_pk: call!(PublicKey::from_bytes) >>
        timestamp: be_u64 >>
        pk: call!(PublicKey::from_bytes) >>
        (Observer {
            sig_pk,
            timestamp,
            pk,
        })
    ));
}

impl ToBytes for Observer {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x03) >>
            gen_slice!(self.sig_pk.as_ref()) >>
            gen_be_u64!(self.timestamp) >>
            gen_slice!(self.pk.as_ref())
    )}
}

/// An entry of sanction list
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sanction(pub SanctionType);

impl FromBytes for Sanction {
    named!(from_bytes<Sanction>, do_parse!(
        sanction_type: call!(SanctionType::from_bytes) >>
        (Sanction(sanction_type))
    ));
}

impl ToBytes for Sanction {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, sanction_type| SanctionType::to_bytes(sanction_type, buf), &self.0)
    )}
}

/** RemovePeer is a struct that holds info to send removing peer packet to a group chat.

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
`1`       | `0x06`(type: remove peer)
`8`       | `timestamp`
`1`       | `event`(EventV2)
`32`      | `PK of target`
variable  | `sanction list`(Sanction)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemovePeer {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    timestamp: u64,
    event: EventV2,
    target_pk: PublicKey,
    sanctions: Vec<Sanction>,
}

impl FromBytes for RemovePeer {
    named!(from_bytes<RemovePeer>, do_parse!(
        tag!("\x5b") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!(&[0xf3][..]) >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        tag!("\x06") >>
        timestamp: be_u64 >>
        event: call!(EventV2::from_bytes) >>
        target_pk: call!(PublicKey::from_bytes) >>
        sanctions: many0!(Sanction::from_bytes) >>
        (RemovePeer {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            timestamp,
            event,
            target_pk,
            sanctions,
        })
    ));
}

impl ToBytes for RemovePeer {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5b) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0xf3) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_be_u8!(0x06) >>
            gen_be_u64!(self.timestamp) >>
            gen_be_u8!(self.event as u8) >>
            gen_slice!(self.target_pk.as_ref()) >>
            gen_many_ref!(self.sanctions.clone(), |buf, sanction| Sanction::to_bytes(sanction, buf))
        )
    }
}

impl RemovePeer {
    /// Create new RemovePeer object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64,
               sender_pk_hash: u32, timestamp: u64, event: EventV2, target_pk: PublicKey, sanctions: Vec<Sanction>) -> Self {
        RemovePeer {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            timestamp,
            event,
            target_pk,
            sanctions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        remove_peer_encode_decode,
        RemovePeer::new(1, gen_keypair().0, gen_nonce(), 2, 3, 4, EventV2::Ban, gen_keypair().0, vec![
            Sanction(SanctionType::BanIpPort(
                BanIpPort {
                    sig_pk: gen_keypair().0,
                    timestamp: 1,
                    sanction_id: 2,
                    ip_port: IpPort::from_udp_saddr("127.0.0.1:33445".parse().unwrap()),
                }
            )),
            Sanction(SanctionType::BanPublicKey(
                BanPublicKey {
                    sig_pk: gen_keypair().0,
                    timestamp: 3,
                    sanction_id: 4,
                    pk: gen_keypair().0,
                }
            )),
            Sanction(SanctionType::BanNickname(
                BanNickname {
                    sig_pk: gen_keypair().0,
                    timestamp: 5,
                    sanction_id: 6,
                    nickname: String::from_utf8([32; 128].to_vec()).unwrap(),
                }
            )),
            Sanction(SanctionType::Observer(
                Observer {
                    sig_pk: gen_keypair().0,
                    timestamp: 7,
                    pk: gen_keypair().0,
                }
            ))
        ])
    );

    encode_decode_test!(
        ban_ip_port_encode_decode,
        BanIpPort {
            sig_pk: gen_keypair().0,
            timestamp: 1,
            sanction_id: 2,
            ip_port: IpPort::from_udp_saddr("127.0.0.1:33445".parse().unwrap()),
        }
    );

    encode_decode_test!(
        ban_publickey_encode_decode,
        BanPublicKey {
            sig_pk: gen_keypair().0,
            timestamp: 3,
            sanction_id: 4,
            pk: gen_keypair().0,
        }
    );

    encode_decode_test!(
        ban_nickname_encode_decode,
        BanNickname {
            sig_pk: gen_keypair().0,
            timestamp: 5,
            sanction_id: 6,
            nickname: String::from_utf8([32; 128].to_vec()).unwrap(),
        }
    );

    encode_decode_test!(
        observer_encode_decode,
        Observer {
            sig_pk: gen_keypair().0,
            timestamp: 7,
            pk: gen_keypair().0,
        }
    );

    encode_decode_test!(
        sanction_encode_decode,
        Sanction(SanctionType::BanIpPort(
            BanIpPort {
                sig_pk: gen_keypair().0,
                timestamp: 1,
                sanction_id: 2,
                ip_port: IpPort::from_udp_saddr("127.0.0.1:33445".parse().unwrap()),
            }))
    );
}
