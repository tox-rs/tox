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

/*! PinResponse packet
*/

use nom::{be_u64, rest};

use std::io::{Error, ErrorKind};

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::dht::codec::*;

/** Ping response packet struct. When `PingRequest` is received DHT node should
respond with `PingResponse` that contains the same ping id inside it's encrypted
payload as it got from `PingRequest`.

https://zetok.github.io/tox-spec/#dht-packet

Length  | Content
------- | -------------------------
`1`     | `0x01`
`32`    | Public Key
`24`    | Nonce
`15`    | Payload

where Payload is encrypted [`PingResponsePayload`](./struct.PingResponsePayload.html)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PingResponse {
    /// public key used for payload encryption
    pub pk: PublicKey,
    /// one time serial number
    pub nonce: Nonce,
    /// encrypted payload
    pub payload: Vec<u8>,
}

impl ToBytes for PingResponse {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x01) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

impl FromBytes for PingResponse {
    named!(from_bytes<PingResponse>, do_parse!(
        tag!("\x01") >>
        pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        payload: map!(rest, |bytes| bytes.to_vec() ) >>
        (PingResponse { pk, nonce, payload })
    ));
}

impl PingResponse {
    /// create new PingResponse object
    pub fn new(shared_secret: &PrecomputedKey, pk: &PublicKey, payload: PingResponsePayload) -> PingResponse {
        let nonce = &gen_nonce();
        let mut buf = [0; MAX_DHT_PACKET_SIZE];
        let (_, size) = payload.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size] , nonce, shared_secret);

        PingResponse {
            pk: *pk,
            nonce: *nonce,
            payload,
        }
    }
    /** Decrypt payload and try to parse it as `PingResponsePayload`.

    Returns `Error` in case of failure:

    - fails to decrypt
    - fails to parse as given packet type
    */
    pub fn get_payload(&self, own_secret_key: &SecretKey) -> Result<PingResponsePayload, Error> {
        debug!(target: "PingResponse", "Getting packet data from PingResponse.");
        trace!(target: "PingResponse", "With PingResponse: {:?}", self);
        let decrypted = open(&self.payload, &self.nonce, &self.pk, own_secret_key)
            .map_err(|()| {
                debug!("Decrypting PingResponse failed!");
                Error::new(ErrorKind::Other, "PingResponse decrypt error.")
            })?;

        match PingResponsePayload::from_bytes(&decrypted) {
            IResult::Incomplete(e) => {
                debug!(target: "PingResponse", "PingResponsePayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("PingResponsePayload deserialize error: {:?}", e)))
            },
            IResult::Error(e) => {
                debug!(target: "PingResponse", "PingRequestPayload deserialize error: {:?}", e);
                Err(Error::new(ErrorKind::Other,
                    format!("PingResponsePayload deserialize error: {:?}", e)))
            },
            IResult::Done(_, payload) => {
                Ok(payload)
            }
        }
    }
}

/**
Used to request/respond to ping. Used in an encrypted form. Request id is used
for resistance against replay attacks.

Serialized form:

Ping Packet (request and response)

Packet type `0x01` for response.

Response ID must match ID of the request, otherwise ping is invalid.

Length      | Contents
----------- | --------
`1`         | `0x01`
`8`         | Ping ID

Serialized form should be put in the encrypted part of `PingResponse` packet.

[`PingResponsePayload`](./struct.PingResponsePayload.html) can only be created as a response
to [`PingRequestPayload`](./struct.PingRequestPayload.html).
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PingResponsePayload {
    /// Ping id same as requested from PingRequest
    pub id: u64,
}

impl FromBytes for PingResponsePayload {
    named!(from_bytes<PingResponsePayload>, do_parse!(
        tag!("\x01") >>
        id: be_u64 >>
        eof!() >>
        (PingResponsePayload { id })
    ));
}

impl ToBytes for PingResponsePayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x01) >>
            gen_be_u64!(self.id)
        )
    }
}

#[cfg(test)]
mod tests {
    use toxcore::dht::packet::ping_response::*;
    use toxcore::dht::packet::DhtPacket;

    encode_decode_test!(
        ping_response_payload_encode_decode,
        PingResponsePayload { id: 42 }
    );

    dht_packet_encode_decode!(ping_response_encode_decode, PingResponse);

    dht_packet_encrypt_decrypt!(
        ping_response_payload_encrypt_decrypt,
        PingResponse,
        PingResponsePayload { id: 42 }
    );

    dht_packet_encrypt_decrypt_invalid_key!(
        ping_response_payload_encrypt_decrypt_invalid_key,
        PingResponse,
        PingResponsePayload { id: 42 }
    );

    dht_packet_decode_invalid!(ping_response_decode_invalid, PingResponse);
}
