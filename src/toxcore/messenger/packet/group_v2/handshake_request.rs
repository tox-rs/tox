/*! HandshakeRequest struct.
*/

use nom::{be_u8, be_u32, be_u64};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::packed_node::TcpUdpPackedNode;

/// Type of handshake request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeRequestType {
    /// Type of invite request of Handshake request.
    InviteRequest = 0x00,
    /// Type of peer info exchange of handshake request.
    PeerInfoExchange,
}

impl FromBytes for HandshakeRequestType {
    named!(from_bytes<HandshakeRequestType>,
        switch!(be_u8,
            0 => value!(HandshakeRequestType::InviteRequest) |
            1 => value!(HandshakeRequestType::PeerInfoExchange)
        )
    );
}

/// Type of handshake join
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeJoinType {
    /// Join to public
    Public = 0x00,
    /// Join to private
    Private,
}

impl FromBytes for HandshakeJoinType {
    named!(from_bytes<HandshakeJoinType>,
        switch!(be_u8,
            0 => value!(HandshakeJoinType::Public) |
            1 => value!(HandshakeJoinType::Private)
        )
    );
}

/** HandshakeRequest is a struct that holds info to send handshake request packet to a peer.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x5a`
`4`       | `hash id`
`32`      | `PK of sender`
`24`      | `nonce`
`1`       | `0x00`(packet kind: handshake request)
`4`       | `sender pk hash`
`32`      | `enc PK`
`32`      | `sig PK`
`1`       | `request type`
`1`       | `join type`
`4`       | `state version`
`variable`| `node`

`node` is

Length      | Content
------------|-------
`1`         | `type`(of ip)
`4` or `16` | IPv4 or IPv6 address
`2`         | port
`32`        | PK of peer

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeRequest {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
    enc_pk: PublicKey,
    sig_pk: PublicKey,
    request_type: HandshakeRequestType,
    join_type: HandshakeJoinType,
    version: u32,
    node: TcpUdpPackedNode,
}

impl FromBytes for HandshakeRequest {
    named!(from_bytes<HandshakeRequest>, do_parse!(
        tag!("\x5a") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!("\x00") >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        enc_pk: call!(PublicKey::from_bytes) >>
        sig_pk: call!(PublicKey::from_bytes) >>
        request_type: call!(HandshakeRequestType::from_bytes) >>
        join_type: call!(HandshakeJoinType::from_bytes) >>
        version: be_u32 >>
        node: call!(TcpUdpPackedNode::from_bytes) >>
        (HandshakeRequest {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            enc_pk,
            sig_pk,
            request_type,
            join_type,
            version,
            node,
        })
    ));
}

impl ToBytes for HandshakeRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5a) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0x00) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash) >>
            gen_slice!(self.enc_pk.as_ref()) >>
            gen_slice!(self.sig_pk.as_ref()) >>
            gen_be_u8!(self.request_type as u8) >>
            gen_be_u8!(self.join_type as u8) >>
            gen_be_u32!(self.version) >>
            gen_call!(|buf, node| TcpUdpPackedNode::to_bytes(node, buf), &self.node)
        )
    }
}

impl HandshakeRequest {
    /// Create new HandshakeRequest object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32,
               enc_pk: PublicKey, sig_pk: PublicKey, request_type: HandshakeRequestType, join_type: HandshakeJoinType, version: u32,
               node: TcpUdpPackedNode) -> Self {
        HandshakeRequest {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
            enc_pk,
            sig_pk,
            request_type,
            join_type,
            version,
            node,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toxcore::ip_port::*;

    encode_decode_test!(
        handshake_request_invite_encode_decode,
        HandshakeRequest::new(1, gen_keypair().0, gen_nonce(), 2, 3, gen_keypair().0, gen_keypair().0,
            HandshakeRequestType::InviteRequest, HandshakeJoinType::Public, 4,
            TcpUdpPackedNode {
                ip_port: IpPort::from_tcp_saddr("127.0.0.1:35547".parse().unwrap()),
                pk: gen_keypair().0,
            }
        )
    );
}
