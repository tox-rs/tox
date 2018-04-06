/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2018 Evgeny Kurnevsky <kurnevsky@gmail.com>

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

/*! OnionResponse2 packet
*/

use super::*;

use toxcore::binary_io::*;

/** Second onion response packet. It's sent back from the third to the second node
from onion chain.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x8d`
`118`    | `OnionReturn`
variable | Payload

where payload is encrypted [`AnnounceResponse`](./struct.AnnounceResponse.html) or
[`OnionDataResponse`](./struct.OnionDataResponse.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionResponse2 {
    /// Return address encrypted by the second node from onion chain
    pub onion_return: OnionReturn,
    /// Encrypted payload
    pub payload: InnerOnionResponse
}

impl FromBytes for OnionResponse2 {
    named!(from_bytes<OnionResponse2>, do_parse!(
        verify!(rest_len, |len| len <= ONION_MAX_PACKET_SIZE) >>
        tag!(&[0x8d][..]) >>
        onion_return: flat_map!(take!(ONION_RETURN_2_SIZE), OnionReturn::from_bytes) >>
        payload: call!(InnerOnionResponse::from_bytes) >>
        (OnionResponse2 { onion_return, payload })
    ));
}

impl ToBytes for OnionResponse2 {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x8d) >>
            gen_call!(|buf, onion_return| OnionReturn::to_bytes(onion_return, buf), &self.onion_return) >>
            gen_call!(|buf, payload| InnerOnionResponse::to_bytes(payload, buf), &self.payload)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION_RETURN_2_PAYLOAD_SIZE: usize = ONION_RETURN_2_SIZE - NONCEBYTES;

    encode_decode_test!(
        onion_response_2_encode_decode,
        OnionResponse2 {
            onion_return: OnionReturn {
                nonce: gen_nonce(),
                payload: vec![42; ONION_RETURN_2_PAYLOAD_SIZE]
            },
            payload: InnerOnionResponse::AnnounceResponse(AnnounceResponse {
                sendback_data: 12345,
                nonce: gen_nonce(),
                payload: vec![42, 123]
            })
        }
    );
}
