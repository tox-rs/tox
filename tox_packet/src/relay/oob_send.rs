/*! OobSend packet
*/

use super::*;

use tox_binary_io::*;
use tox_crypto::*;

use nom::bytes::complete::tag;
use nom::combinator::rest;

/** Sent by client to server.
If a peer with private key equal to the key they announced themselves with is
connected, the data in the OOB send packet will be sent to that peer as an
OOB recv packet. If no such peer is connected, the packet is discarded. The
toxcore `TCP_server` implementation has a hard maximum OOB data length of 1024.
1024 was picked because it is big enough for the `net_crypto` packets related
to the handshake and is large enough that any changes to the protocol would not
require breaking `TCP server`. It is however not large enough for the bigges
`net_crypto` packets sent with an established `net_crypto` connection to
prevent sending those via OOB packets.

OOB packets can be used just like normal data packets however the extra size
makes sending data only through them less efficient than data packets.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x06`
`32`     | Public Key
variable | Data

*/
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OobSend {
    /// Public Key of the receiver
    pub destination_pk: PublicKey,
    /// OOB data packet
    pub data: Vec<u8>,
}

impl FromBytes for OobSend {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x06")(input)?;
        let (input, destination_pk) = PublicKey::from_bytes(input)?;
        let (input, data) = rest(input)?;
        Ok((
            input,
            OobSend {
                destination_pk,
                data: data.to_vec(),
            },
        ))
    }
}

impl ToBytes for OobSend {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x06) >>
            gen_slice!(self.destination_pk.as_bytes()) >>
            gen_slice!(self.data.as_slice())
        )
    }
}

#[cfg(test)]
mod test {
    use rand::thread_rng;

    use super::*;

    encode_decode_test!(
        oob_send_encode_decode,
        OobSend {
            destination_pk: SecretKey::generate(&mut thread_rng()).public_key(),
            data: vec![42; 123]
        }
    );
}
