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

/*! PongResponse packet
*/

use toxcore::binary_io::*;

use nom::be_u64;

/** Sent by both client and server, both will respond.
The server should respond to ping packets with pong packets with the same `ping_id`
as was in the ping packet. The server should check that each pong packet contains
the same `ping_id` as was in the ping, if not the pong packet must be ignored.

Serialized form:

Length | Content
------ | ------
`1`    | `0x05`
`8`    | ping_id in BigEndian

*/
#[derive(Debug, PartialEq, Clone)]
pub struct PongResponse {
    /// The id of ping to respond
    pub ping_id: u64
}

impl FromBytes for PongResponse {
    named!(from_bytes<PongResponse>, do_parse!(
        tag!("\x05") >>
        ping_id: be_u64 >>
        (PongResponse {  ping_id })
    ));
}

impl ToBytes for PongResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x05) >>
            gen_be_u64!(self.ping_id)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        pong_response_encode_decode,
        PongResponse {
            ping_id: 12345
        }
    );
}
