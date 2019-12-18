/*! OobReceive packet
*/

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

use nom::combinator::rest;

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
    named!(from_bytes<OobReceive>, do_parse!(
        tag!("\x07") >>
        sender_pk: call!(PublicKey::from_bytes) >>
        data: rest >>
        (OobReceive { sender_pk, data: data.to_vec() })
    ));
}

impl ToBytes for OobReceive {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x07) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.data.as_slice())
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        oob_receive_encode_decode,
        OobReceive {
            sender_pk: gen_keypair().0,
            data: vec![42; 123]
        }
    );
}
