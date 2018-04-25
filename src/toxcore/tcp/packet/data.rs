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

/*! Data packet
*/

use toxcore::binary_io::*;

use nom::{be_u8, rest};

/** Sent by client to server.
The client sends data with `connection_id` and the server
relays it to the given connection

Serialized form:

Length   | Content
-------- | ------
`1`      | connection_id [ `0x10` .. `0xF0` )
variable | Data

*/
#[derive(Debug, PartialEq, Clone)]
pub struct Data {
    /// The id of the connection of the client
    pub connection_id: u8,
    /// Data packet
    pub data: Vec<u8>
}

impl FromBytes for Data {
    named!(from_bytes<Data>, do_parse!(
        connection_id: be_u8 >>
        verify!(value!(connection_id), |id| id >= 0x10 && id < 0xF0) >>
        data: rest >>
        (Data { connection_id, data: data.to_vec() })
    ));
}

impl ToBytes for Data {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(self.connection_id) >>
            gen_slice!(self.data)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        data_encode_decode,
        Data {
            connection_id: 17,
            data: vec![42; 123]
        }
    );
}
