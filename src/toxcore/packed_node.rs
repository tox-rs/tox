//! Variant of PackedNode to contain both TCP and UDP

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::ip_port::*;

/// Variant of PackedNode to contain both TCP and UDP
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpUdpPackedNode { // TODO: unify with dht::packed_node
    /// IP address of the node.
    pub ip_port: IpPort,
    /// Public Key of the node.
    pub pk: PublicKey,
}

impl FromBytes for TcpUdpPackedNode {
    named!(from_bytes<TcpUdpPackedNode>, do_parse!(
        ip_port: call!(IpPort::from_bytes, IpPortPadding::NoPadding) >>
        pk: call!(PublicKey::from_bytes) >>
        (TcpUdpPackedNode {
            ip_port,
            pk,
        })
    ));
}

impl ToBytes for TcpUdpPackedNode {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, data| IpPort::to_bytes(data, buf, IpPortPadding::NoPadding), &self.ip_port) >>
            gen_slice!(self.pk.as_ref())
        )
    }
}
