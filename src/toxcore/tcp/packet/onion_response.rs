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

/*! OnionResponse packet
*/

use toxcore::binary_io::*;

use nom::rest;

/** Sent by server to client.
The server just sends data from Onion Response 1 that it got from a UDP node
to the client.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x09`
variable | Data

*/
#[derive(Debug, PartialEq, Clone)]
pub struct OnionResponse {
    /// Onion data packet
    pub data: Vec<u8>
}

impl FromBytes for OnionResponse {
    named!(from_bytes<OnionResponse>, do_parse!(
        tag!("\x09") >>
        data: rest >>
        (OnionResponse { data: data.to_vec() })
    ));
}

impl ToBytes for OnionResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x09) >>
            gen_slice!(self.data)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        onion_response_encode_decode,
        OnionResponse {
            data: vec![42, 123]
        }
    );
}
