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

/*! OobReceive packet
*/

use toxcore::binary_io::*;
use toxcore::crypto_core::*;

use nom::rest;

/** Sent by server to client.
OOB recv are sent with the announced public key of the peer that sent the
OOB send packet and the exact data.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x07`
`32`     | Public Key
variable | Data

*/
#[derive(Debug, PartialEq, Clone)]
pub struct OobReceive {
    /// Public Key of the sender
    pub sender_pk: PublicKey,
    /// OOB data packet
    pub data: Vec<u8>
}

impl FromBytes for OobReceive {
    named!(from_bytes<OobReceive>, do_parse!(
        tag!("\x07") >>
        sender_pk: call!(PublicKey::from_bytes) >>
        data: rest >>
        (OobReceive { sender_pk, data: data.to_vec() })
    ));
}

impl ToBytes for OobReceive {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x07) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.data)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        oob_receive_encode_decode,
        OobReceive {
            sender_pk: gen_keypair().0,
            data: vec![42; 123]
        }
    );
}
