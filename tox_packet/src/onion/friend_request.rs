/*! FriendRequest packet
*/

use super::*;
use crate::toxid::{NoSpam, NOSPAMBYTES};
use nom::bytes::complete::tag;
use nom::combinator::{map_res, verify};
use std::str;

const MAX_FRIEND_REQUEST_MSG_SIZE: usize = MAX_ONION_CLIENT_DATA_SIZE - (1 + NOSPAMBYTES);

/** Friend request that can be enclosed in onion data packet and sent through onion
path.

Length    | Content
--------- | -------------------------
`1`       | `0x20`
`4`       | NoSpam
`1..991`  | Message

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriendRequest {
    nospam: NoSpam,
    msg: String,
}

impl FriendRequest {
    /// Create new object
    pub fn new(nospam: NoSpam, msg: String) -> Self {
        FriendRequest { nospam, msg }
    }
}

impl ToBytes for FriendRequest {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x20) >>
            gen_slice!(self.nospam.0) >>
            gen_cond!(self.msg.len() > MAX_FRIEND_REQUEST_MSG_SIZE || self.msg.is_empty(), |buf| gen_error(buf, 0)) >>
            gen_slice!(self.msg.as_bytes())
        )
    }
}

impl FromBytes for FriendRequest {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag(&[0x20][..])(input)?;
        let (input, nospam) = NoSpam::from_bytes(input)?;
        let (input, msg) = map_res(
            verify(rest, |msg: &[u8]| {
                msg.len() <= MAX_FRIEND_REQUEST_MSG_SIZE && !msg.is_empty()
            }),
            str::from_utf8,
        )(input)?;
        Ok((
            input,
            FriendRequest {
                nospam,
                msg: msg.to_string(),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toxid::NOSPAMBYTES;

    encode_decode_test!(
        friend_req_encode_decode,
        FriendRequest {
            nospam: NoSpam([42; NOSPAMBYTES]),
            msg: "1234".to_owned(),
        }
    );

    #[test]
    fn friend_request_from_bytes_encoding_error() {
        let err_string = vec![0, 159, 146, 150]; // not UTF8 bytes.
        let nospam = [42; NOSPAMBYTES];

        let mut friend_req = vec![0x20];
        friend_req.extend_from_slice(&nospam);
        friend_req.extend(err_string);
        assert!(FriendRequest::from_bytes(&friend_req).is_err());
    }

    #[test]
    fn friend_request_from_bytes_overflow() {
        let large_string = vec![32; MAX_FRIEND_REQUEST_MSG_SIZE + 1];
        let nospam = [42; NOSPAMBYTES];

        let mut friend_req = vec![0x20];
        friend_req.extend_from_slice(&nospam);
        friend_req.extend(large_string);
        assert!(FriendRequest::from_bytes(&friend_req).is_err());
    }

    #[test]
    fn friend_request_to_bytes_overflow() {
        let large_string = String::from_utf8(vec![32u8; MAX_FRIEND_REQUEST_MSG_SIZE + 1]).unwrap();
        let friend_req = FriendRequest {
            nospam: NoSpam([42; NOSPAMBYTES]),
            msg: large_string,
        };
        let mut buf = [0; MAX_ONION_CLIENT_DATA_SIZE + 1]; // `1` is to provide enough space for success of serializing
        assert!(friend_req.to_bytes((&mut buf, 0)).is_err());
    }

    #[test]
    fn friend_request_from_bytes_underflow() {
        let nospam = [42; NOSPAMBYTES];

        let mut friend_req = vec![0x20];
        friend_req.extend_from_slice(&nospam);
        assert!(FriendRequest::from_bytes(&friend_req).is_err());
    }

    #[test]
    fn friend_request_to_bytes_underflow() {
        let friend_req = FriendRequest {
            nospam: NoSpam([42; NOSPAMBYTES]),
            msg: "".to_string(),
        };
        let mut buf = [0; MAX_ONION_CLIENT_DATA_SIZE]; // `1` is to provide enough space for success of serializing
        assert!(friend_req.to_bytes((&mut buf, 0)).is_err());
    }
}
