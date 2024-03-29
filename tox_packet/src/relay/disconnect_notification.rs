/*! DisconnectNotification packet
*/

use super::*;

use crate::relay::connection_id::ConnectionId;
use nom::bytes::complete::tag;
use tox_binary_io::*;

/** Sent by client to server.
Sent when client wants the server to forget about the connection related
to the connection_id in the notification. Server must remove this connection
and must be able to reuse the `connection_id` for another connection. If the
connection was connected the server must send a disconnect notification to the
other client. The other client must think that this client has simply
disconnected from the TCP server.

Sent by server to client.
Sent by the server to the client to tell them that the connection with
`connection_id` that was connected is now disconnected. It is sent either
when the other client of the connection disconnect or when they tell the
server to kill the connection (see above).

Serialized form:

Length | Content
------ | ------
`1`    | `0x03`
`1`    | connection_id [ `0x10` .. `0xFF` ]

*/
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DisconnectNotification {
    /// The id of the disconnected client
    pub connection_id: ConnectionId,
}

impl FromBytes for DisconnectNotification {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x03")(input)?;
        let (input, connection_id) = ConnectionId::from_bytes(input)?;
        Ok((input, DisconnectNotification { connection_id }))
    }
}

impl ToBytes for DisconnectNotification {
    #[rustfmt::skip]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x03) >>
            gen_call!(|buf, connection_id| ConnectionId::to_bytes(connection_id, buf), &self.connection_id)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        disconnect_notification_encode_decode,
        DisconnectNotification {
            connection_id: ConnectionId::from_index(1)
        }
    );
}
