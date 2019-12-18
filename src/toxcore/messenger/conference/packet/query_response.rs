/*! QueryResponse response message struct.
*/

use nom::number::complete::{be_u8, be_u16};
use std::str;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/// Length in bytes of nickname in PeerInfo.
const MAX_NAME_LENGTH_IN_CONFERENCE: usize = 128;

/** QueryResponse is a struct that holds info to response to query message from a peer.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x62`
`2`       | `conference id`
`1`       | `0x09`
variable  | `peer info list`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryResponse {
    /// Id of conference
    pub conference_id: u16,
    /// Infos of peer
    pub peer_infos: Vec<PeerInfo>,
}

impl FromBytes for QueryResponse {
    named!(from_bytes<QueryResponse>, do_parse!(
        tag!("\x62") >>
        conference_id: be_u16 >>
        tag!("\x09") >>
        peer_infos: many0!(PeerInfo::from_bytes) >>
        (QueryResponse {
            conference_id,
            peer_infos: peer_infos.to_vec()
        })
    ));
}

impl ToBytes for QueryResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x62) >>
            gen_be_u16!(self.conference_id) >>
            gen_be_u8!(0x09) >>
            gen_many_ref!(self.peer_infos.clone(), |buf, info| PeerInfo::to_bytes(info, buf))
        )
    }
}

impl QueryResponse {
    /// Create new QueryResponse object.
    pub fn new(conference_id: u16, peer_infos: Vec<PeerInfo>) -> Self {
        QueryResponse {
            conference_id,
            peer_infos,
        }
    }
}

/**

An entry of `peer info list` is

Length    | Content
--------- | --------------------
`2`       | `peer id`
`32`      | real PK
`32`      | temp PK
`1`       | `length` of nickname
variable  | nickname(UTF-8 String)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerInfo {
    peer_id: u16,
    real_pk: PublicKey,
    temp_pk: PublicKey,
    nickname: String,
}

impl FromBytes for PeerInfo {
    named!(from_bytes<PeerInfo>, do_parse!(
        peer_id: be_u16 >>
        real_pk: call!(PublicKey::from_bytes) >>
        temp_pk: call!(PublicKey::from_bytes) >>
        length: be_u8 >>
        nickname: map_res!(take!(length), str::from_utf8) >>
        (PeerInfo {
            peer_id,
            real_pk,
            temp_pk,
            nickname: nickname.to_string(),
        })
    ));
}

impl ToBytes for PeerInfo {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u16!(self.peer_id) >>
            gen_slice!(self.real_pk.as_ref()) >>
            gen_slice!(self.temp_pk.as_ref()) >>
            gen_cond!(self.nickname.len() > MAX_NAME_LENGTH_IN_CONFERENCE, |buf| gen_error(buf, 0)) >>
            gen_be_u8!(self.nickname.len() as u8) >>
            gen_slice!(self.nickname.as_bytes())
        )
    }
}

impl PeerInfo {
    /// Create new PeerInfo object.
    pub fn new(peer_id: u16, real_pk: PublicKey, temp_pk: PublicKey, nickname: String) -> Self {
        PeerInfo {
            peer_id,
            real_pk,
            temp_pk,
            nickname,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        query_response_encode_decode,
        QueryResponse::new(1, vec![
            PeerInfo {
                peer_id: 1,
                real_pk: gen_keypair().0,
                temp_pk: gen_keypair().0,
                nickname: "1234".to_owned(),
            },
            PeerInfo {
                peer_id: 2,
                real_pk: gen_keypair().0,
                temp_pk: gen_keypair().0,
                nickname: "56789".to_owned(),
            }])
    );

    #[test]
    fn peer_info_from_bytes_encoding_error() {
        let err_string = vec![0, 159, 146, 150]; // not UTF8 bytes.
        let real_pk = gen_keypair().0;
        let temp_pk = gen_keypair().0;
        let mut buf = vec![0x00, 0x01];
        let length = vec![0x04];
        buf.extend_from_slice(&real_pk.0);
        buf.extend_from_slice(&temp_pk.0);
        buf.extend_from_slice(&length);
        buf.extend_from_slice(&err_string);
        assert!(PeerInfo::from_bytes(&buf).is_err());
    }

    #[test]
    fn peer_info_to_bytes_overflow() {
        let large_string = String::from_utf8(vec![32u8; 300]).unwrap();
        let peer_info = PeerInfo {
            peer_id: 1,
            real_pk: gen_keypair().0,
            temp_pk: gen_keypair().0,
            nickname: large_string,
        };
        let mut buf = [0; MAX_NAME_LENGTH_IN_CONFERENCE + 2 + 32 + 32+ 1]; // peer_id(2) + real_pk(32) + temp_pk(32) + length(1)
        assert!(peer_info.to_bytes((&mut buf, 0)).is_err());
    }
}
