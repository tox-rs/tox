/*! BootstrapInfo packet
*/

use nom::{
    number::complete::be_u32,
    combinator::rest,
};

use crate::toxcore::binary_io::*;

/** Sent by both client and server, only server will respond.
When server receives this packet it may respond with the version of the library
plus MoTD (message of the day). The max length of MoTD is 256 bytes so the max packet
lenght of server BootstrapInfo is 261=(1+4+256) bytes.

Client must send a BootstrapInfo of exactly 78 bytes, the only 1 field is required: `packet type`
which is filled automatically. So version may be filled with any value, so does MoTD, but
it has to be exactly 73=(78-1-4) bytes long. The server should check that the size of the
packet is exactly 78 bytes long (or MoTD=73 bytes filled with any values). Frankly speaking,
there should be neither `version` nor `motd` fields in the request version, the serialized form
should be 1 byte with packet type + (78-1) bytes of trash, but this implementation is simplified.

Serialized form:

Length      | Contents
----------- | --------
`1`         | `0xF0`
`4`         | Version in BigEndian
variable    | MoTD, must not longer than 256 bytes

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapInfo {
    /// The version of DHT server
    pub version: u32,
    /// Message of the day
    pub motd: Vec<u8>,
}

/// Length of in bytes of MoTD field of [`BootstrapInfo`](./struct.BootstrapInfo.html)
/// when server responds with info.
pub const BOOSTRAP_SERVER_MAX_MOTD_LENGTH: usize = 256;
/// Length of in bytes of MoTD field of [`BootstrapInfo`](./struct.BootstrapInfo.html)
/// when client requests info. 73 = 78 (max client request len) - 1 (type) - 4 (version)
pub const BOOSTRAP_CLIENT_MAX_MOTD_LENGTH: usize = 73;

impl ToBytes for BootstrapInfo {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0xf0) >>
            gen_be_u32!(self.version) >>
            gen_slice!(self.motd.as_slice())
        )
    }
}

impl FromBytes for BootstrapInfo {
    named!(from_bytes<BootstrapInfo>, do_parse!(
        tag!(&[0xf0][..]) >>
        version: be_u32 >>
        motd: verify!(rest, |motd: &[u8]| motd.len() <= BOOSTRAP_SERVER_MAX_MOTD_LENGTH) >>
        (BootstrapInfo { version, motd: motd.to_vec() })
    ));
}

#[cfg(test)]
mod tests {
    use crate::toxcore::dht::packet::bootstrap_info::*;

    encode_decode_test!(
        bootstrap_info_encode_decode,
        BootstrapInfo {
            version: 1717,
            motd: vec![1,2,3,4],
        }
    );
}
