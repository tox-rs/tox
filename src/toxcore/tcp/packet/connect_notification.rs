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
`1`    | connection_id

*/
#[derive(Debug, PartialEq, Clone)]
pub struct ConnectNotification {
    /// The id of the connected client
    pub connection_id: u8
}

impl FromBytes for ConnectNotification {
    named!(from_bytes<ConnectNotification>, do_parse!(
        tag!("\x02") >>
        connection_id: be_u8 >>
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
