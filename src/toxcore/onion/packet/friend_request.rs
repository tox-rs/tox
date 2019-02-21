/*! FriendRequest packet
*/

use super::*;
use std::str;
use crate::toxcore::toxid::{NoSpam, NOSPAMBYTES};
use crate::toxcore::friend_connection::packet::MAX_ONION_CLIENT_DATA_SIZE;

const MAX_FRIEND_REQUEST_DATA_SIZE: usize = MAX_ONION_CLIENT_DATA_SIZE - (1 + NOSPAMBYTES);

/** Friend request that can be enclosed in onion data packet and sent through onion
path.

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriendRequest {
    nospam: NoSpam,
    msg: String,
}

impl ToBytes for FriendRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x20) >>
            gen_slice!(self.nospam.0) >>
            gen_cond!(self.msg.len() > MAX_FRIEND_REQUEST_DATA_SIZE, |buf| gen_error(buf, 0)) >>
            gen_slice!(self.msg.as_bytes())
        )
    }
}

impl FromBytes for FriendRequest {
    named!(from_bytes<FriendRequest>, do_parse!(
        tag!(&[0x20][..]) >>
        nospam: call!(NoSpam::from_bytes) >>
        msg: map_res!(verify!(rest, |msg: &[u8]| msg.len() <= MAX_FRIEND_REQUEST_DATA_SIZE), str::from_utf8) >>
        (FriendRequest {
            nospam,
            msg: msg.to_string(),
        })
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        friend_req_encode_decode,
        FriendRequest {
            nospam: NoSpam::random(),
            msg: "1234".to_owned(),
        }
    );

    // Test for encoding error of from_bytes.
    #[test]
    fn friend_req_from_bytes_encoding_error() {
        let err_string = vec![0, 159, 146, 150]; // not UTF8 bytes.
        let nospam = NoSpam::random();

        let mut friend_req = vec![0x20];
        friend_req.extend_from_slice(&nospam.0);
        friend_req.extend(err_string);
        assert!(FriendRequest::from_bytes(&friend_req).is_err());
    }

    // Test for overflow of from_bytes.
    #[test]
    fn friend_req_from_bytes_overflow() {
        let large_string = vec![32; MAX_FRIEND_REQUEST_DATA_SIZE + 1];
        let nospam = NoSpam::random();

        let mut friend_req = vec![0x20];
        friend_req.extend_from_slice(&nospam.0);
        friend_req.extend(large_string);
        assert!(FriendRequest::from_bytes(&friend_req).is_err());
    }

    // Test for overflow of to_bytes.
    #[test]
    fn friend_req_to_bytes_overflow() {
        let large_string = String::from_utf8(vec![32u8; MAX_FRIEND_REQUEST_DATA_SIZE + 1]).unwrap();
        let friend_req = FriendRequest {
            nospam: NoSpam::random(),
            msg: large_string
        };
        let mut buf = [0; MAX_FRIEND_REQUEST_DATA_SIZE + 1]; // `1` is for packet_id.
        assert!(friend_req.to_bytes((&mut buf, 0)).is_err());
    }
}
