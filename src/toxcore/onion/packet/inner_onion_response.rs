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

/*! InnerOnionResponse enum
*/

use super::*;

use toxcore::binary_io::*;

/** Onion responses that can be enclosed in onion packets and sent through onion
path.

Onion allows only two types of packets to be sent as a response through onion
paths: `AnnounceResponse` and `OnionDataResponse`.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InnerOnionResponse {
    /// [`AnnounceResponse`](./struct.AnnounceResponse.html) structure.
    AnnounceResponse(AnnounceResponse),
    /// [`OnionDataResponse`](./struct.OnionDataResponse.html) structure.
    OnionDataResponse(OnionDataResponse)
}

impl ToBytes for InnerOnionResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            InnerOnionResponse::AnnounceResponse(ref inner) => inner.to_bytes(buf),
            InnerOnionResponse::OnionDataResponse(ref inner) => inner.to_bytes(buf),
        }
    }
}

impl FromBytes for InnerOnionResponse {
    named!(from_bytes<InnerOnionResponse>, alt!(
        map!(AnnounceResponse::from_bytes, InnerOnionResponse::AnnounceResponse) |
        map!(OnionDataResponse::from_bytes, InnerOnionResponse::OnionDataResponse)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        inner_announce_response_encode_decode,
        InnerOnionResponse::AnnounceResponse(AnnounceResponse {
            sendback_data: 12345,
            nonce: gen_nonce(),
            payload: vec![42; 123]
        })
    );

    encode_decode_test!(
        inner_onion_data_response_encode_decode,
        InnerOnionResponse::OnionDataResponse(OnionDataResponse {
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123]
        })
    );
}
