/*! Offline struct
*/

use crate::toxcore::binary_io::*;

/** Offline is a struct that holds nothing.

This packet is used to notify that a friend is being deleted.
Though the friend is deleted, because of conference, Tox client
may try to connect to the friend, this message prevent this friend to
be shown as Online.

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Offline;

impl FromBytes for Offline {
    named!(from_bytes<Offline>, do_parse!(
        tag!("\x19") >>
        (Offline)
    ));
}

impl ToBytes for Offline {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x19)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        offline_encode_decode,
        Offline
    );

}
