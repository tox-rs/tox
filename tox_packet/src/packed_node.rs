//! Variant of PackedNode to contain both TCP and UDP

use tox_binary_io::*;
use tox_crypto::*;
use cookie_factory::{do_gen, gen_call, gen_slice,};

use crate::ip_port::*;

/// Variant of PackedNode to contain both TCP and UDP
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpUdpPackedNode { // TODO: unify with dht::packed_node
    /// IP address of the node.
    pub ip_port: IpPort,
    /// Public Key of the node.
    pub pk: PublicKey,
}

impl FromBytes for TcpUdpPackedNode {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, ip_port) = IpPort::from_bytes(input, IpPortPadding::NoPadding)?;
        let (input, pk) = PublicKey::from_bytes(input)?;
        Ok((input, TcpUdpPackedNode {
            ip_port,
            pk,
        }))
    }
}

impl ToBytes for TcpUdpPackedNode {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, data| IpPort::to_bytes(data, buf, IpPortPadding::NoPadding), &self.ip_port) >>
            gen_slice!(self.pk.as_ref())
        )
    }
}
