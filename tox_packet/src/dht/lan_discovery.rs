/*! LanDiscovery packet
*/
use super::*;

use nom::bytes::complete::tag;
use tox_binary_io::*;
use tox_crypto::*;

/** LanDiscovery packet struct.
LanDiscovery packets contain the DHT public key of the sender. When a LanDiscovery packet
is received, a NodesRequest packet will be sent to the sender of the packet. This means that
the DHT instance will bootstrap itself to every peer from which it receives one of these packet.
Through this mechanism, Tox clients will bootstrap themselve
 automatically from other Tox clients running on the local network.


Serialized form:

Length | Content
------ | ------
`1`    | `0x21`
`32`   | Public Key

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LanDiscovery {
    /// DHT public key of the sender
    pub pk: PublicKey,
}

impl ToBytes for LanDiscovery {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x21) >>
            gen_slice!(self.pk.as_ref())
        )
    }
}

impl FromBytes for LanDiscovery {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x21")(input)?;
        let (input, pk) = PublicKey::from_bytes(input)?;
        Ok((input, LanDiscovery { pk }))
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use crate::dht::lan_discovery::*;

    encode_decode_test!(
        lan_discovery_encode_decode,
        LanDiscovery {
            pk: SecretKey::generate(&mut thread_rng()).public_key()
        }
    );
}
