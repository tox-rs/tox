/*! TcpRelays struct.
*/

use nom::{be_u32, be_u64};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::packed_node::TcpUdpPackedNode;

/** TcpRelays is a struct that holds info to send tcp relays packet to a peer.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x5c`
`4`       | `hash id`
`32`      | `PK of sender`
`24`      | `nonce`
`1`       | `0x04`(packet kind: tcp relays)
`4`       | `sender pk hash`
`variable`| `tcp relays`

An entry of `tcp relays` is

Length      | Content
------------|-------
`1`         | `type`(of ip)
`4` or `16` | IPv4 or IPv6 address
`2`         | port
`32`        | PK of peer

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpRelays {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    relays: Vec<TcpUdpPackedNode>,
}

impl FromBytes for TcpRelays {
    named!(from_bytes<TcpRelays>, do_parse!(
        tag!("\x5c") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!("\x04") >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        relays: many0!(TcpUdpPackedNode::from_bytes) >>
        (TcpRelays {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            relays,
        })
    ));
}

impl ToBytes for TcpRelays {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5c) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0x04) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_many_ref!(&self.relays, |buf, relay| TcpUdpPackedNode::to_bytes(relay, buf))
        )
    }
}

impl TcpRelays {
    /// Create new TcpRelays object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32, relays: Vec<TcpUdpPackedNode>) -> Self {
        TcpRelays {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            relays,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toxcore::ip_port::*;

    encode_decode_test!(
        tcp_relays_encode_decode,
        TcpRelays::new(1, gen_keypair().0, gen_nonce(), 2, 3, vec![
            TcpUdpPackedNode {
                ip_port: IpPort::from_tcp_saddr("127.0.0.1:35447".parse().unwrap()),
                pk: gen_keypair().0,
            },
            TcpUdpPackedNode {
                ip_port: IpPort::from_tcp_saddr("127.0.0.1:35448".parse().unwrap()),
                pk: gen_keypair().0,
            },
            TcpUdpPackedNode {
                ip_port: IpPort::from_tcp_saddr("127.0.0.1:35449".parse().unwrap()),
                pk: gen_keypair().0,
            },
        ])
    );
}
