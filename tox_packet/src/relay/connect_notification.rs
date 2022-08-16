/*! ConnectNotification packet
*/

use super::*;

use tox_binary_io::*;
use crate::relay::connection_id::ConnectionId;
use nom::bytes::complete::tag;

/** Sent by server to client.
Tell the client that connection_id is now connected meaning the other
is online and data can be sent using this `connection_id`.

Serialized form:

Length | Content
------ | ------
`1`    | `0x02`
`1`    | connection_id [ `0x10` .. `0xFF` ]

*/
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConnectNotification {
    /// The id of the connected client
    pub connection_id: ConnectionId
}

impl FromBytes for ConnectNotification {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x02")(input)?;
        let (input, connection_id) = ConnectionId::from_bytes(input)?;
        Ok((input, ConnectNotification { connection_id }))
    }
}

impl ToBytes for ConnectNotification {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x02) >>
            gen_call!(|buf, connection_id| ConnectionId::to_bytes(connection_id, buf), &self.connection_id)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        connect_notification_encode_decode,
        ConnectNotification {
            connection_id: ConnectionId::from_index(1)
        }
    );
}
