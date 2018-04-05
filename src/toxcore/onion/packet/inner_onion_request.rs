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

/*! InnerOnionRequest enum
*/

use super::*;

use toxcore::binary_io::*;

/** Onion requests that can be enclosed in onion packets and sent through onion
path.

Onion allows only two types of packets to be sent as a request through onion
paths: `AnnounceRequest` and `OnionDataRequest`.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InnerOnionRequest {
    /// [`InnerAnnounceRequest`](./struct.InnerAnnounceRequest.html) structure.
    InnerAnnounceRequest(InnerAnnounceRequest),
    /// [`InnerOnionDataRequest`](./struct.InnerOnionDataRequest.html) structure.
    InnerOnionDataRequest(InnerOnionDataRequest)
}

impl ToBytes for InnerOnionRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            InnerOnionRequest::InnerAnnounceRequest(ref inner) => inner.to_bytes(buf),
            InnerOnionRequest::InnerOnionDataRequest(ref inner) => inner.to_bytes(buf),
        }
    }
}

impl FromBytes for InnerOnionRequest {
    named!(from_bytes<InnerOnionRequest>, alt!(
        map!(InnerAnnounceRequest::from_bytes, InnerOnionRequest::InnerAnnounceRequest) |
        map!(InnerOnionDataRequest::from_bytes, InnerOnionRequest::InnerOnionDataRequest)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        inner_announce_request_encode_decode,
        InnerOnionRequest::InnerAnnounceRequest(InnerAnnounceRequest {
            nonce: gen_nonce(),
            pk: gen_keypair().0,
            payload: vec![42, 123]
        })
    );

    encode_decode_test!(
        inner_onion_data_request_encode_decode,
        InnerOnionRequest::InnerOnionDataRequest(InnerOnionDataRequest {
            destination_pk: gen_keypair().0,
            nonce: gen_nonce(),
            temporary_pk: gen_keypair().0,
            payload: vec![42, 123]
        })
    );
}
