/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2016-2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2018 Namsoo CHO <nscho66@gmail.com>
    Copyright © 2018 Evgeny Kurnevsky <kurnevsky@gmail.com>
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

/*! CookieRequest packet
*/

use nom::be_u64;

use std::io::{Error, ErrorKind};

use toxcore::binary_io::*;
use toxcore::crypto_core::*;

/** CookieRequest packet struct.
According to https://zetok.github.io/tox-spec/#net-crypto

CookieRequest packet (145 bytes):

[uint8_t 24]
[Sender's DHT Public key (32 bytes)]
[Random nonce (24 bytes)]
[Encrypted message containing:
    [Sender's real public key (32 bytes)]
    [padding (32 bytes)]
    [uint64_t echo id (must be sent back untouched in cookie response)]
]

Serialized form:

Length | Content
------ | ------
`1`    | `0x18`
`32`   | DHT Public Key
`24`   | Random nonce
`88`   | Payload

where Payload is encrypted [`CookieRequestPayload`](./struct.CookieRequestPayload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CookieRequest {
    /// DHT public key
    pub pk: PublicKey,
    /// Random nonce
    pub nonce: Nonce,
    /// Encrypted payload of CookieRequest
    pub payload: Vec<u8>,
}

impl ToBytes for CookieRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x18) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl FromBytes for CookieRequest {
    named!(from_bytes<CookieRequest>, do_parse!(
        tag!("\x18") >>
        pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        payload: take!(88) >>
        (CookieRequest { pk, nonce, payload: payload.to_vec() })
    ));
}

impl CookieRequest {
    /// Create `CookieRequest` from `CookieRequestPayload` encrypting in with `shared_key`
    pub fn new(shared_secret: &PrecomputedKey, pk: &PublicKey, payload: CookieRequestPayload) -> CookieRequest {
        let nonce = gen_nonce();
        let mut buf = [0; 88];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], &nonce, shared_secret);

        CookieRequest {
            pk: *pk,
            nonce,
            payload,
        }
    }
    /** Decrypt payload with symmetric key and try to parse it as `CookieRequestPayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse `CookieRequestPayload`
    */
    pub fn get_payload(&self, own_secret_key: &SecretKey) -> Result<CookieRequestPayload, Error> {
        let decrypted = open(&self.payload, &self.nonce, &self.pk, own_secret_key)
            .map_err(|()| {
                debug!("Decrypting CookieRequest failed!");
                Error::new(ErrorKind::Other, "CookieRequest decrypt error.")
            })?;
        match CookieRequestPayload::from_bytes(&decrypted) {
            IResult::Incomplete(e) => {
                debug!(target: "Dht", "CookieRequestPayload return deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("CookieRequestPayload return deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                debug!(target: "Dht", "CookieRequestPayload return deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("CookieRequestPayload return deserialize error: {:?}", e)))
            },
            IResult::Done(_, payload) => {
                Ok(payload)
            }
        }
    }
}

/** CookieRequestPayload packet struct.

Serialized form:

Length      | Contents
----------- | --------
`32`        | Sender's real public key
`32`        | Padding (zeros)
`8`         | Request ID in BigEndian

Serialized form should be put in the encrypted part of `CookieRequest` packet.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CookieRequestPayload {
    /// Sender's real public key
    pub pk: PublicKey,
    /// Request id
    pub id: u64,
}

impl ToBytes for CookieRequestPayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(&[0; 32]) >> // padding
            gen_be_u64!(self.id)
        )
    }
}

impl FromBytes for CookieRequestPayload {
    named!(from_bytes<CookieRequestPayload>, do_parse!(
        pk: call!(PublicKey::from_bytes) >>
        take!(32) >> // padding
        id: be_u64 >>
        eof!() >>
        (CookieRequestPayload { pk, id })
    ));
}

#[cfg(test)]
mod tests {
    use toxcore::dht::packet::cookie_request::*;

    dht_packet_encrypt_decrypt!(
        cookie_request_payload_encrypt_decrypt,
        CookieRequest,
        CookieRequestPayload { pk: gen_keypair().0, id: 42 }
    );

    dht_packet_encrypt_decrypt_invalid_key!(
        cookie_request_payload_encrypt_decrypt_invalid_key,
        CookieRequest,
        CookieRequestPayload { pk: gen_keypair().0, id: 42 }
    );

    dht_packet_decode_invalid!(cookie_request_decode_invalid, CookieRequest);
}
