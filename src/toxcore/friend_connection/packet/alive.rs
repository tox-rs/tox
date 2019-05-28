/*! Alive struct
*/

use crate::toxcore::binary_io::*;

/// Id of the ping packet.
pub const PACKET_ID_ALIVE: u8 = 0x10;

/** Alive is a struct that holds nothing.

This packet is used to check if the friend is online by sending this packet
every 8 seconds using net_crypto connection.
If one node has not received this packet for 32 seconds, the friend connection is timed out
and destroyed.

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Alive;

impl FromBytes for Alive {
    named!(from_bytes<Alive>, do_parse!(
        tag!(&[PACKET_ID_ALIVE][..]) >>
        (Alive)
    ));
}

impl ToBytes for Alive {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        gen_be_u8!(buf, PACKET_ID_ALIVE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        alive_encode_decode,
        Alive
    );

}
