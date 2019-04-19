/*! SyncResponse struct.
*/

use nom::{be_u8, be_u32, be_u64};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::ip_port::*;
use crate::toxcore::packed_node::TcpUdpPackedNode;

/** SyncResponse is a struct that holds info to send sync response packet to a peer.

Serialized form:

Length      | Content
----------- | ------
`1`         | `0x5b`
`4`         | `hash id`
`32`        | `PK of sender`
`24`        | `nonce`
`1`         | `0xf9`(packet kind: sync response)
`8`         | `message id`
`4`         | `sender pk hash`
`4`         | `number`(of peers)
variable    | `announce list`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncResponse {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    announces: Vec<Announce>,
}


impl FromBytes for SyncResponse {
    named!(from_bytes<SyncResponse>, do_parse!(
        tag!("\x5b") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!(&[0xf9][..]) >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        announces: many0!(Announce::from_bytes) >>
        (SyncResponse {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            announces,
        })
    ));
}

impl ToBytes for SyncResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5b) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0xf9) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_many_ref!(&self.announces, |buf, announce| Announce::to_bytes(announce, buf))
        )
    }
}

impl SyncResponse {
    /// Create new SyncResponse object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32, announces: Vec<Announce>) -> Self {
        SyncResponse {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            announces,
        }
    }
}

/** An entry of `announce list` is

Length      | Content
------------|-------
`32`        | PK of peer
`1`         | `flag`(of ip port is setted)
`1`         | `count`(of tcp relays)
`1`         | `type`(of ip)
`4` or `16` | IPv4 or IPv6 address(comes only when `flag` is setted)
`2`         | port(comes only when `flag` is setted)
variable    | `tcp relay list`

An entry of `tcp relay list` is

Length      | Content
------------|-------
`1`         | `type`(of ip)
`4` or `16` | IPv4 or IPv6 address
`2`         | port
`32`        | PK of peer

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Announce {
    peer_pk: PublicKey,
    ip_port: Option<IpPort>,
    relays: Vec<TcpUdpPackedNode>,
}

impl FromBytes for Announce {
    named!(from_bytes<Announce>, do_parse!(
        peer_pk: call!(PublicKey::from_bytes) >>
        flag: be_u8 >>
        relay_count: be_u8 >>
        ip_port: cond!(flag != 0, call!(IpPort::from_bytes, IpPortPadding::NoPadding)) >>
        relays: many0!(TcpUdpPackedNode::from_bytes) >>
        (Announce {
            peer_pk,
            ip_port,
            relays,
        })
    ));
}

impl ToBytes for Announce {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.peer_pk.as_ref()) >>
            gen_if_else!(self.ip_port.is_some(), gen_be_u8!(0x01), gen_be_u8!(0x00)) >>
            gen_be_u8!(self.relays.len() as u8) >>
            gen_cond!(self.ip_port.is_some(), gen_call!(|buf, ip_port| IpPort::to_bytes(ip_port, buf, IpPortPadding::NoPadding), &self.ip_port.clone().unwrap())) >>
            gen_many_ref!(&self.relays, |buf, relay| TcpUdpPackedNode::to_bytes(relay, buf))
        )
    }
}

impl Announce {
    /// Create new AnnouncePeer object.
    pub fn new(peer_pk: PublicKey, ip_port: Option<IpPort>, relays: Vec<TcpUdpPackedNode>) -> Self {
        Announce {
            peer_pk,
            ip_port,
            relays,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        sync_response_encode_decode,
        SyncResponse::new(1, gen_keypair().0, gen_nonce(), 2, 3, vec![
            Announce::new(gen_keypair().0, Some(IpPort::from_tcp_saddr("127.0.0.1:33445".parse().unwrap())),
                vec![
                    TcpUdpPackedNode {
                        ip_port: IpPort::from_tcp_saddr("127.0.0.1:33447".parse().unwrap()),
                        pk: gen_keypair().0,
                    },
                    TcpUdpPackedNode {
                        ip_port: IpPort::from_tcp_saddr("127.0.0.1:33448".parse().unwrap()),
                        pk: gen_keypair().0,
                    },
                    TcpUdpPackedNode {
                        ip_port: IpPort::from_tcp_saddr("127.0.0.1:33449".parse().unwrap()),
                        pk: gen_keypair().0,
                    },
                ]),
            Announce::new(gen_keypair().0, Some(IpPort::from_tcp_saddr("127.0.0.1:33445".parse().unwrap())),
                vec![
                    TcpUdpPackedNode {
                        ip_port: IpPort::from_tcp_saddr("127.0.0.1:33410".parse().unwrap()),
                        pk: gen_keypair().0,
                    },
                    TcpUdpPackedNode {
                        ip_port: IpPort::from_tcp_saddr("127.0.0.1:33411".parse().unwrap()),
                        pk: gen_keypair().0,
                    },
                    TcpUdpPackedNode {
                        ip_port: IpPort::from_tcp_saddr("127.0.0.1:33412".parse().unwrap()),
                        pk: gen_keypair().0,
                    },
                ]),
            Announce::new(gen_keypair().0, Some(IpPort::from_tcp_saddr("127.0.0.1:33445".parse().unwrap())),
                vec![
                    TcpUdpPackedNode {
                        ip_port: IpPort::from_tcp_saddr("127.0.0.1:33413".parse().unwrap()),
                        pk: gen_keypair().0,
                    },
                    TcpUdpPackedNode {
                        ip_port: IpPort::from_tcp_saddr("127.0.0.1:33448".parse().unwrap()),
                        pk: gen_keypair().0,
                    },
                    TcpUdpPackedNode {
                        ip_port: IpPort::from_tcp_saddr("127.0.0.1:33449".parse().unwrap()),
                        pk: gen_keypair().0,
                    },
                ]),
        ])
    );
}
