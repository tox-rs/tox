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
use toxcore::onion::packet::InnerOnionResponse;

/** Sent by server to client.
The server just sends payload from `OnionResponse1` packet that it got from a
UDP node to the client.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x09`
variable | Payload

*/
#[derive(Debug, PartialEq, Clone)]
pub struct OnionResponse {
    /// Inner onion response
    pub payload: InnerOnionResponse
}

impl FromBytes for OnionResponse {
    named!(from_bytes<OnionResponse>, do_parse!(
        tag!("\x09") >>
        payload: call!(InnerOnionResponse::from_bytes) >>
        (OnionResponse { payload })
    ));
}

impl ToBytes for OnionResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x09) >>
            gen_call!(|buf, payload| InnerOnionResponse::to_bytes(payload, buf), &self.payload)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use toxcore::crypto_core::*;
    use toxcore::onion::packet::{AnnounceResponse, OnionDataResponse};

    encode_decode_test!(
        onion_response_with_announce_encode_decode,
        OnionResponse {
            payload: InnerOnionResponse::AnnounceResponse(AnnounceResponse {
                sendback_data: 12345,
                nonce: gen_nonce(),
                payload: vec![42; 123]
            })
        }
    );

    encode_decode_test!(
        onion_response_with_data_encode_decode,
        OnionResponse {
            payload: InnerOnionResponse::OnionDataResponse(OnionDataResponse {
                nonce: gen_nonce(),
                temporary_pk: gen_keypair().0,
                payload: vec![42; 123]
            })
        }
    );
}
