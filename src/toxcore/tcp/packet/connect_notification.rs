/*! ConnectNotification packet
*/

use toxcore::binary_io::*;
use nom::be_u8;

/** Sent by server to client.
Tell the client that connection_id is now connected meaning the other
is online and data can be sent using this `connection_id`.

Serialized form:

Length | Content
------ | ------
`1`    | `0x02`
`1`    | connection_id [ `0x10` .. `0xFF` ]

*/
#[derive(Debug, PartialEq, Clone)]
pub struct ConnectNotification {
    /// The id of the connected client
    pub connection_id: u8
}

impl FromBytes for ConnectNotification {
    named!(from_bytes<ConnectNotification>, do_parse!(
        tag!("\x02") >>
        connection_id: verify!(be_u8, |id| id >= 0x10) >>
        (ConnectNotification { connection_id })
    ));
}

impl ToBytes for ConnectNotification {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x02) >>
            gen_be_u8!(self.connection_id)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        connect_notification_encode_decode,
        ConnectNotification {
            connection_id: 17
        }
    );
}
