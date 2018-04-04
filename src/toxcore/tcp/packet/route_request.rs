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

/*! RouteRequest packet
*/

use toxcore::binary_io::*;
use toxcore::crypto_core::*;

/** Sent by client to server.
Send a routing request to the server that we want to connect
to peer with public key where the public key is the public the peer
announced themselves as. The server must respond to this with a `RouteResponse`.

Serialized form:

Length | Content
------ | ------
`1`    | `0x00`
`32`   | Public Key

*/
#[derive(Debug, PartialEq, Clone)]
pub struct RouteRequest {
    /// The requested PK
    pub pk: PublicKey,
}

impl FromBytes for RouteRequest {
    named!(from_bytes<RouteRequest>, do_parse!(
        tag!("\x00") >>
        pk: call!(PublicKey::from_bytes) >>
        (RouteRequest { pk })
    ));
}

impl ToBytes for RouteRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x00) >>
            gen_slice!(self.pk.as_ref())
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        route_request_encode_decode,
        RouteRequest {
            pk: gen_keypair().0
        }
    );
}
