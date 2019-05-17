/*! Friend requests struct
*/

use nom::combinator::rest;

use crate::toxcore::binary_io::*;
use crate::toxcore::onion::packet::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::ip_port::SIZE_IPPORT;
use crate::toxcore::toxid::NoSpam;

const ONION_SEND_BASE: usize =  PUBLICKEYBYTES + SIZE_IPPORT + MACBYTES;
const ONION_SEND_1: usize = secretbox::NONCEBYTES + ONION_SEND_BASE * 3;
const MAX_ONION_DATA_SIZE: usize = ONION_MAX_PACKET_SIZE - (ONION_SEND_1 + 1); // 1 is for packet_id
const MIN_ONION_DATA_REQUEST_SIZE: usize = 1 + PUBLICKEYBYTES + secretbox::NONCEBYTES + PUBLICKEYBYTES + MACBYTES; // 1 is for packet_id
/// Maximum size in butes of Onion Data Request packet
pub const MAX_DATA_REQUEST_SIZE: usize = MAX_ONION_DATA_SIZE - MIN_ONION_DATA_REQUEST_SIZE;
/// Minimum size in bytes of Onion Data Response packet
pub const MIN_ONION_DATA_RESPONSE_SIZE: usize = PUBLICKEYBYTES + MACBYTES;
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
    named!(from_bytes<FriendRequests>, do_parse!(
        tag!("\x12") >>
        nospam: call!(NoSpam::from_bytes) >>
        message: verify!(rest, |message: &[u8]| message.len() <= MAX_ONION_CLIENT_DATA_SIZE) >>
        (FriendRequests { nospam, message: message.to_vec() })
    ));
}

impl ToBytes for FriendRequests {
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

    encode_decode_test!(
        friend_requests_encode_decode,
        FriendRequests::new(NoSpam::random(), vec![1,2,3,4])
    );
}
