/*! OobReceive packet
*/

use super::*;

use tox_binary_io::*;
use tox_crypto::*;

use nom::combinator::rest;
use nom::bytes::complete::tag;

/** Sent by server to client.
OOB recv are sent with the announced public key of the peer that sent the
OOB send packet and the exact data.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x07`
`32`     | Public Key
variable | Data

*/
#[derive(Debug, PartialEq, Clone)]
pub struct OobReceive {
    /// Public Key of the sender
    pub sender_pk: PublicKey,
    /// OOB data packet
    pub data: Vec<u8>
}

impl FromBytes for OobReceive {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x07")(input)?;
        let (input, sender_pk) = PublicKey::from_bytes(input)?;
        let (input, data) = rest(input)?;
        Ok((input, OobReceive { sender_pk, data: data.to_vec() }))
    }
}

impl ToBytes for OobReceive {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x07) >>
            gen_slice!(self.sender_pk.as_bytes()) >>
            gen_slice!(self.data.as_slice())
        )
    }
}

#[cfg(test)]
mod test {
    use rand::thread_rng;

    use super::*;

    encode_decode_test!(
        oob_receive_encode_decode,
        OobReceive {
            sender_pk: SecretKey::generate(&mut thread_rng()).public_key(),
            data: vec![42; 123]
        }
    );
}
