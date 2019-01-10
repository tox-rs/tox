/*! Handshake packets to establish a confirmed connection via
handshake using [`diagram`](https://zetok.github.io/tox-spec/#handshake-diagram)

*/

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/** The request of the client to create a TCP handshake.

According to [Tox spec](https://zetok.github.io/tox-spec/#handshake-request).

Serialized form:

Length  | Contents
------- | --------
`32`    | PK of the client
`24`    | Nonce of the encrypted payload
`72`    | Encrypted payload (plus MAC)

*/

#[derive(PartialEq, Debug, Clone)]
pub struct ClientHandshake {
    /// Client's Public Key
    pub pk: PublicKey,
    /// Nonce for the current encrypted payload
    pub nonce: Nonce,
    /// Encrypted payload according to
    /// [Tox spec](https://zetok.github.io/tox-spec/#handshake-request-packet-payload).
    pub payload: Vec<u8>
}

/// A serialized client handshake must be equal to 32 (PK) + 24 (nonce)
/// \+ 72 (encrypted payload) bytes
pub const CLIENT_HANDSHAKE_SIZE: usize = 128;

impl FromBytes for ClientHandshake {
    named!(from_bytes<ClientHandshake>, do_parse!(
        pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        payload: take!(ENC_PAYLOAD_SIZE) >>
        (ClientHandshake { pk, nonce, payload: payload.to_vec() })
    ));
}

impl ToBytes for ClientHandshake {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

/** The response of the server to a TCP handshake.

According to [Tox spec](https://zetok.github.io/tox-spec/#handshake-response).

Serialized form:

Length  | Contents
------- | --------
`24`    | Nonce for the encrypted payload
`72`    | Encrypted payload (plus MAC)

*/

#[derive(PartialEq, Debug, Clone)]
pub struct ServerHandshake {
    /// Nonce of the encrypted payload
    pub nonce: Nonce,
    /// Encrypted payload according to
    /// [Tox spec](https://zetok.github.io/tox-spec/#handshake-response-payload).
    pub payload: Vec<u8>
}

/// A serialized server handshake must be equal to 24 (nonce)
/// \+ 72 (encrypted payload) bytes
pub const SERVER_HANDSHAKE_SIZE: usize = 96;

impl FromBytes for ServerHandshake {
    named!(from_bytes<ServerHandshake>, do_parse!(
        nonce: call!(Nonce::from_bytes) >>
        payload: take!(ENC_PAYLOAD_SIZE) >>
        (ServerHandshake { nonce, payload: payload.to_vec() })
    ));
}

impl ToBytes for ServerHandshake {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.nonce.as_ref()) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}

/** The payload of a TCP handshake.

The payload is encrypted with algo:

```text
precomputed_key = precomputed(self_pk, other_sk);
encrypted_payload = encrypt_data_symmetric(precomputed_key, nonce, payload);
```

According to [Request payload](https://zetok.github.io/tox-spec/#handshake-request-packet-payload)
or [Response payload](https://zetok.github.io/tox-spec/#handshake-response-payload).

Serialized and decrypted form:

Length  | Contents
------- | --------
`32`    | PublicKey for the current session
`24`    | Nonce of the current session

*/

pub struct HandshakePayload {
    /// Temporary Session PK
    pub session_pk: PublicKey,
    /// Temporary Session Nonce
    pub session_nonce: Nonce
}

/// A serialized payload must be equal to 32 (PK) + 24 (nonce) bytes
pub const PAYLOAD_SIZE: usize = 56;

/// A serialized encrypted payload must be equal to 32 (PK) + 24 (nonce) + 16 (MAC) bytes
pub const ENC_PAYLOAD_SIZE: usize = 72;

impl FromBytes for HandshakePayload {
    named!(from_bytes<HandshakePayload>, do_parse!(
        pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        (HandshakePayload { session_pk: pk, session_nonce: nonce })
    ));
}

impl ToBytes for HandshakePayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.session_pk.as_ref()) >>
            gen_slice!(self.session_nonce.as_ref())
        )
    }
}
