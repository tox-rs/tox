/*! PingRequest packet
*/

use crate::toxcore::binary_io::*;

use nom::number::streaming::be_u64;

/** Sent by both client and server, both will respond.
Ping packets are used to know if the other side of the connection is still
live. TCP when established doesn't have any sane timeouts (1 week isn't sane)
so we are obliged to have our own way to check if the other side is still live.
Ping ids can be anything except 0, this is because of how toxcore sets the
variable storing the `ping_id` that was sent to 0 when it receives a pong
response which means 0 is invalid.

The server should send ping packets every X seconds (toxcore `TCP_server` sends
them every 30 seconds and times out the peer if it doesn't get a response in 10).
The server should respond immediately to ping packets with pong packets.


Serialized form:

Length | Content
------ | ------
`1`    | `0x04`
`8`    | ping_id in BigEndian

*/
#[derive(Debug, PartialEq, Clone)]
pub struct PingRequest {
    /// The id of ping
    pub ping_id: u64
}

impl FromBytes for PingRequest {
    named!(from_bytes<PingRequest>, do_parse!(
        tag!("\x04") >>
        ping_id: be_u64 >>
        (PingRequest { ping_id })
    ));
}

impl ToBytes for PingRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x04) >>
            gen_be_u64!(self.ping_id)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        ping_request_encode_decode,
        PingRequest {
            ping_id: 12345
        }
    );
}
