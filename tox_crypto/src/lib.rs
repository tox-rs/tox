//! Functions for the core crypto.

use crypto_box::{SalsaBox, aead::generic_array::typenum::marker_traits::Unsigned};
use crypto_box::aead::{Aead, AeadCore};
pub use crypto_box::{PublicKey, SecretKey};

pub type Nonce2 = crypto_box::aead::Nonce<SalsaBox>;
pub type Nonce = [u8; <SalsaBox as AeadCore>::NonceSize::USIZE];

pub const PUBLICKEYBYTES: usize = crypto_box::KEY_SIZE;
pub const NONCEBYTES: usize = <SalsaBox as AeadCore>::NonceSize::USIZE;

// TODO: check if `#[inline]` is actually useful

/** Check if Tox public key is valid. Should be used only for input
    validation.

    Returns `true` if valid, `false` otherwise.
*/
pub fn public_key_valid(pk: &PublicKey) -> bool {
    pk.as_bytes()[PUBLICKEYBYTES - 1] <= 127 // Last bit of key is always zero.
}


/** Returns encrypted data from `plain`, with length of `plain + 16` due to
    padding.

    Encryption is done using precomputed key (from the public key (32 bytes)
    of receiver and the secret key of sender) and a 24 byte nonce.

    `sodiumoxide` takes care of padding the data, so the resulting encrypted
    data has length of `plain + 16`.

    A wrapper for the
    [`seal_precomputed()`](../../../sodiumoxide/crypto/box_/curve25519xsalsa20poly1305/fn.seal_precomputed.html)
    function from `sodiumoxide`.
*/
#[inline]
pub fn encrypt_data_symmetric(precomputed_key: &SalsaBox,
                              nonce: &Nonce,
                              plain: &[u8]) -> Vec<u8> {
    precomputed_key.encrypt(nonce.into(), plain).unwrap()
}
// not using ↓ since it doesn't allow to add additional documentation
//pub use sodiumoxide::crypto::box_::seal_precomputed as encrypt_data_symmetric;


/** Returns plain data from `encrypted`, with length of `encrypted - 16` due to
    padding, or `()` if data couldn't be decrypted.

    Decryption is done using precomputed key (from the secret key of receiver
    and the public key of sender) and a 24 byte nonce.

    `sodiumoxide` takes care of removing padding from the data, so the
    resulting plain data has length of `encrypted - 16`.

    This function is a wrapper for the
    [`open_precomputed()`](../../../sodiumoxide/crypto/box_/curve25519xsalsa20poly1305/fn.open_precomputed.html)
    function from `sodiumoxide`.
*/
#[inline]
pub fn decrypt_data_symmetric(precomputed_key: &SalsaBox,
                              nonce: &Nonce,
                              encrypted: &[u8]) -> Result<Vec<u8>, ()> {
    precomputed_key.decrypt(nonce.into(), encrypted).map_err(|_| ())
}


/** Inrement given nonce by 1.

    Treats `Nonce` as BE number.

    If nonce can't be incremented (all bits are `1`), nonce is zeroed.

    *Note that behaviour of this function might change to not increment supplied
    nonces, but rather, return an increased nonce.*

    Spec: https://zetok.github.io/tox-spec#nonce-2
*/
#[inline]
pub fn increment_nonce(nonce: &mut Nonce) {
    increment_nonce_number(nonce, 1)
}

/// Inrement given nonce by number `num`.
pub fn increment_nonce_number(nonce: &mut Nonce, num: u16) {
    let mut c = num as u32;
    for i in (0 .. NONCEBYTES).rev() {
        c += nonce[i] as u32;
        nonce[i] = c as u8;
        c >>= 8;
    }
}

pub fn gen_keypair() -> (PublicKey, SecretKey) {
    // let sk = SecretKey::generate(&mut rand::thread_rng());
    // let pk = sk.public_key();
    // (pk, sk)
    unimplemented!()
}

pub fn gen_nonce() -> Nonce2 {
    unimplemented!()
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    // test comparing empty keys
    // testing since it would appear that sodiumoxide doesn't do testing for it
    fn public_key_cmp_test_empty() {
        let alice_publickey = PublicKey::from([0; PUBLICKEYBYTES]);
        let bob_publickey = PublicKey::from([0; PUBLICKEYBYTES]);

        assert_eq!(alice_publickey.eq(&bob_publickey), true);
        assert_eq!(bob_publickey.eq(&alice_publickey), true);
    }

    #[test]
    // test comparing random public keys
    // testing since it would appear that sodiumoxide doesn't do testing for it
    fn public_key_cmp_test_random() {
        let (alice_publickey, _alice_secretkey) = gen_keypair();
        let (bob_publickey, _bob_secretkey) = gen_keypair();

        assert_eq!(alice_publickey.eq(&bob_publickey), false);
        assert_eq!(bob_publickey.eq(&alice_publickey), false);

        assert_eq!(alice_publickey.eq(&alice_publickey), true);
        assert_eq!(bob_publickey.eq(&bob_publickey), true);
    }


    #[test]
    fn public_key_valid_test() {
        let (pk, _) = gen_keypair();
        assert!(public_key_valid(&pk));

        assert!(public_key_valid(&PublicKey::from([0; PUBLICKEYBYTES]))); // 0
        assert!(public_key_valid(&PublicKey::from([0b01_11_11_11; PUBLICKEYBYTES]))); // 127
        assert!(!public_key_valid(&PublicKey::from([0b10_00_00_00; PUBLICKEYBYTES]))); // 128
        assert!(!public_key_valid(&PublicKey::from([0b11_11_11_11; PUBLICKEYBYTES]))); // 255
    }


    #[test]
    fn increment_nonce_test_zero_plus_one() {
        let cmp_nonce = [0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 1];

        let mut nonce = [0; NONCEBYTES];
        increment_nonce(&mut nonce);
        assert_eq!(nonce, cmp_nonce);
    }

    #[test]
    fn increment_nonce_test_0xf_plus_one() {
        let cmp_nonce = [0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0x10];

        let mut nonce = [0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0xf];
        increment_nonce(&mut nonce);
        assert_eq!(nonce, cmp_nonce);
    }

    #[test]
    fn increment_nonce_test_0xff_plus_one() {
        let cmp_nonce = [0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 1, 0];

        let mut nonce = [0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0xff];
        increment_nonce(&mut nonce);
        assert_eq!(nonce, cmp_nonce);
    }

    #[test]
    fn increment_nonce_test_0xff_max() {
        let cmp_nonce = [0; NONCEBYTES];
        let mut nonce = [0xff; NONCEBYTES];
        increment_nonce(&mut nonce);
        assert_eq!(cmp_nonce, nonce);
    }

    #[test]
    fn increment_nonce_test_random() {
        let mut nonce = gen_nonce().into();
        let cmp_nonce = nonce;
        increment_nonce(&mut nonce);
        assert_ne!(nonce, cmp_nonce);
    }

    // increment_nonce_number()

    #[test]
    fn increment_nonce_number_test_zero_plus_0xff00() {
        let cmp_nonce = [0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0xff, 0];
        let mut nonce = [0; NONCEBYTES];

        increment_nonce_number(&mut nonce, 0xff00);
        assert_eq!(nonce, cmp_nonce);
    }

    #[test]
    fn increment_nonce_number_test_0xff00_plus_0x0110() {
        let cmp_nonce = [0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 1, 0, 0x10];

        let mut nonce = [0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0xff, 0];

        increment_nonce_number(&mut nonce, 0x01_10);
        assert_eq!(nonce, cmp_nonce);
    }
}
