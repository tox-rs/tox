/*! A tls-like module for relay packets

Establish a secure [`Channel`](./struct.Channel.html)
between two people using temporary [`Session`](./struct.Session.html)s.

# Example

```no_run
use tox::toxcore::tcp::secure::*;

let alice_session = Session::random();
let bob_session = Session::random();

// assume we got Alice's PK & Nonce via handshake
let alice_pk = *alice_session.pk();
let alice_nonce = *alice_session.nonce();

// assume we got Bob's PK & Nonce via handshake
let bob_pk = *bob_session.pk();
let bob_nonce = *bob_session.nonce();

// Now both Alice and Bob may create secure Channels
let alice_channel = Channel::new(&alice_session, &bob_pk, &bob_nonce);
let bob_channel = Channel::new(&bob_session, &alice_pk, &alice_nonce);

// And now they may communicate sending encrypted data to each other

// Alice encrypts the message
let alice_msg = "Hello Bob!";
let alice_msg_encrypted = alice_channel.encrypt(alice_msg.as_bytes());
assert_ne!(alice_msg.as_bytes().to_vec(), alice_msg_encrypted);
// Alice sends it somehow

// Bob receives and decrypts
assert_eq!( alice_msg.as_bytes().to_vec(), bob_channel.decrypt(alice_msg_encrypted.as_ref()).unwrap() );

// Now Bob encrypts his message
let bob_msg = "Oh hello Alice!";
let bob_msg_encrypted = bob_channel.encrypt(bob_msg.as_bytes());
assert_ne!(bob_msg.as_bytes().to_vec(), bob_msg_encrypted);
// And sends it back to Alice

assert_eq!( bob_msg.as_bytes().to_vec(), alice_channel.decrypt(bob_msg_encrypted.as_ref()).unwrap() );
```

*/

use crate::toxcore::crypto_core::*;

use std::cell::RefCell;

/** A Session is created on both sides.
Its PK and Nonce is sent from a client to server via handshake.
A server creates its own `Session`, creates [`Channel`](./struct.Channel.html)
and replies with its Session PK and Nonce to the client, the client creates `Channel`.

After the handshake is complited, they may both encrypt and decrypt messages using
their `Channel`s.
*/

pub struct Session {
    /// pk must be sent to another person
    pk: PublicKey,
    /// sk is used with `other_pk` to create a `PrecomputedKey`
    /// to establish a secure [`Channel`](./struct.Channel.html)
    sk: SecretKey,
    /// nonce must be sent to another person
    nonce: Nonce
}

impl Session {
    /** Create a new `Session` with random pk, sk and nonce.
    You should send it to establish a secure [`Channel`](./struct.Channel.html)
    */
    pub fn random() -> Session {
        let (pk, sk) = gen_keypair();
        let nonce = gen_nonce();
        Session { pk, sk, nonce }
    }

    /// Get the PK of the Session
    pub fn pk(&self) -> &PublicKey {
        &self.pk
    }

    /// Get the Nonce of the Session
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /** Create `PrecomputedKey` to encrypt/decrypt data
    using secure [`Channel`](./struct.Channel.html)
    */
    pub fn create_precomputed_key(&self, other_pk: &PublicKey) -> PrecomputedKey {
        encrypt_precompute(other_pk, &self.sk)
    }
}

/** Encrypt TCP packets with credentials.
Increment `sent_nonce` after data was encrypted.
increment `recv_nonce` after data was decrypted.

*/

pub struct Channel {
    precomputed_key: PrecomputedKey,
    sent_nonce: RefCell<Nonce>,
    recv_nonce: RefCell<Nonce>
}

impl Channel {
    /** Create a secure channel with `our_session` and `their_pk` & `their_nonce`
    */
    pub fn new(our_session: &Session, their_pk: &PublicKey, their_nonce: &Nonce) -> Channel {
        let precomputed = our_session.create_precomputed_key(their_pk);
        let sent_n = RefCell::new(*our_session.nonce());
        let recv_n = RefCell::new(*their_nonce);
        Channel { precomputed_key: precomputed, sent_nonce: sent_n, recv_nonce: recv_n }
    }
    /** Encrypt data, increment sent_nonce
    */
    pub fn encrypt(&self, plain: &[u8]) -> Vec<u8> {
        let mut nonce = self.sent_nonce.borrow_mut();
        let encrypted = encrypt_data_symmetric(&self.precomputed_key, &nonce, plain);
        increment_nonce( &mut nonce );
        encrypted
    }
    /** Decrypt data, increment recv_nonce
    */
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, ()> {
        let mut nonce = self.recv_nonce.borrow_mut();
        let decrypted = decrypt_data_symmetric(&self.precomputed_key, &nonce, encrypted);
        increment_nonce( &mut nonce );
        decrypted
    }
}

#[cfg(test)]
mod tests {
    use crate::toxcore::tcp::secure::*;

    fn create_channels() -> (Channel, Channel) {
        crypto_init().unwrap();
        let alice_session = Session::random();
        let bob_session = Session::random();

        // assume we got Alice's PK & Nonce via handshake
        let alice_pk = *alice_session.pk();
        let alice_nonce = *alice_session.nonce();

        // assume we got Bob's PK & Nonce via handshake
        let bob_pk = *bob_session.pk();
        let bob_nonce = *bob_session.nonce();

        // Now both Alice and Bob may create secure Channels
        let alice_channel = Channel::new(&alice_session, &bob_pk, &bob_nonce);
        let bob_channel = Channel::new(&bob_session, &alice_pk, &alice_nonce);

        (alice_channel, bob_channel)
    }
    #[test]
    fn test_secure_communication() {
        crypto_init().unwrap();
        let (alice_channel, bob_channel) = create_channels();

        // And now they may communicate sending encrypted data to each other

        // Alice encrypts the message
        let alice_msg = "Hello Bob!";
        let alice_msg_encrypted = alice_channel.encrypt(alice_msg.as_bytes());
        assert_ne!(alice_msg.as_bytes().to_vec(), alice_msg_encrypted);
        // Alice sends it somehow

        // Bob receives and decrypts
        assert_eq!( alice_msg.as_bytes().to_vec(), bob_channel.decrypt(alice_msg_encrypted.as_ref()).unwrap() );

        // Now Bob encrypts his message
        let bob_msg = "Oh hello Alice!";
        let bob_msg_encrypted = bob_channel.encrypt(bob_msg.as_bytes());
        assert_ne!(bob_msg.as_bytes().to_vec(), bob_msg_encrypted);
        // And sends it back to Alice

        assert_eq!( bob_msg.as_bytes().to_vec(), alice_channel.decrypt(bob_msg_encrypted.as_ref()).unwrap() );
    }
}
