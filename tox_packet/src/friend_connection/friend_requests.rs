/*! Friend requests struct
*/

use super::*;

use crate::ip_port::SIZE_IPPORT;
use crate::onion::*;
use crate::toxid::NoSpam;
use crypto_box::{
    aead::{generic_array::typenum::marker_traits::Unsigned, AeadCore},
    SalsaBox,
};
use nom::bytes::complete::tag;
use nom::combinator::{rest, verify};

const ONION_SEND_BASE: usize = crypto_box::KEY_SIZE + SIZE_IPPORT + <SalsaBox as AeadCore>::TagSize::USIZE;
const ONION_SEND_1: usize = xsalsa20poly1305::NONCE_SIZE + ONION_SEND_BASE * 3;
const MAX_ONION_DATA_SIZE: usize = ONION_MAX_PACKET_SIZE - (ONION_SEND_1 + 1); // 1 is for packet_id
const MIN_ONION_DATA_REQUEST_SIZE: usize = 1
    + crypto_box::KEY_SIZE
    + xsalsa20poly1305::NONCE_SIZE
    + crypto_box::KEY_SIZE
    + <SalsaBox as AeadCore>::TagSize::USIZE; // 1 is for packet_id
/// Maximum size in butes of Onion Data Request packet
pub const MAX_DATA_REQUEST_SIZE: usize = MAX_ONION_DATA_SIZE - MIN_ONION_DATA_REQUEST_SIZE;
/// Minimum size in bytes of Onion Data Response packet
pub const MIN_ONION_DATA_RESPONSE_SIZE: usize = crypto_box::KEY_SIZE + <SalsaBox as AeadCore>::TagSize::USIZE;
/// Maximum size in bytes of Onion Data Response inner payload
pub const MAX_ONION_CLIENT_DATA_SIZE: usize = MAX_DATA_REQUEST_SIZE - MIN_ONION_DATA_RESPONSE_SIZE;

/** FriendRequests is a struct that holds info of nospam and greeting message.

This packet is used to transmit sender's long term public key, npspam and a message.
It is sent by onion data packet or net-crypto.
If the friend is already directly connected with me and not in conference, it is sent using net-crypto.
Otherwise it is sent using onion.
Both onion and net-crypto packet itself have real public key of sender.
This is why this packet does not contain long term public key.

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriendRequests {
    nospam: NoSpam,
    message: Vec<u8>,
}

impl FromBytes for FriendRequests {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x12")(input)?;
        let (input, nospam) = NoSpam::from_bytes(input)?;
        let (input, message) = verify(rest, |message: &[u8]| message.len() <= MAX_ONION_CLIENT_DATA_SIZE)(input)?;
        Ok((
            input,
            FriendRequests {
                nospam,
                message: message.to_vec(),
            },
        ))
    }
}

impl ToBytes for FriendRequests {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x12) >>
            gen_slice!(self.nospam.0) >>
            gen_cond!(self.message.len() > MAX_ONION_CLIENT_DATA_SIZE, |buf| gen_error(buf, 0)) >>
            gen_slice!(self.message.as_slice())
        )
    }
}

impl FriendRequests {
    /// Create new FriendRequests object
    pub fn new(nospam: NoSpam, message: Vec<u8>) -> Self {
        FriendRequests { nospam, message }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toxid::NOSPAMBYTES;

    encode_decode_test!(
        friend_requests_encode_decode,
        FriendRequests::new(NoSpam([42; NOSPAMBYTES]), vec![1, 2, 3, 4])
    );
}
