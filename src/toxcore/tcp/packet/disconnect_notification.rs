/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2018 Roman Proskuryakov <humbug@deeptown.org>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

/*! DisconnectNotification packet
*/

use toxcore::binary_io::*;
use nom::be_u8;

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
`1`    | connection_id

*/
#[derive(Debug, PartialEq, Clone)]
pub struct DisconnectNotification {
    /// The id of the disconnected client
    pub connection_id: u8
}

impl FromBytes for DisconnectNotification {
    named!(from_bytes<DisconnectNotification>, do_parse!(
        tag!("\x03") >>
        connection_id: be_u8 >>
        (DisconnectNotification { connection_id })
    ));
}

impl ToBytes for DisconnectNotification {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x03) >>
            gen_be_u8!(self.connection_id)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        disconnect_notification_encode_decode,
        DisconnectNotification {
            connection_id: 17
        }
    );
}
