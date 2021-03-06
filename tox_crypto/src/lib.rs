//! Functions for the core crypto.

#![allow(clippy::result_unit_err)]

pub use sodiumoxide::crypto::box_::*;

// TODO: check if `#[inline]` is actually useful

/** Run before using crypto.

Runs [`sodiumoxide::init()`](../../../sodiumoxide/fn.init.html).

Returns `Ok` on success, `Err` otherwise.

E.g.

```
use tox_crypto::crypto_init;

crypto_init().unwrap();
// second call should yield same result
crypto_init().unwrap();
```
*/
pub fn crypto_init() -> Result<(), ()> {
    ::sodiumoxide::init()
}


/** Check if Tox public key `PUBLICKEYBYTES` is valid. Should be used only for
    input validation.

    Returns `true` if valid, `false` otherwise.
*/
pub fn public_key_valid(&PublicKey(ref pk): &PublicKey) -> bool {
    pk[PUBLICKEYBYTES - 1] <= 127 // Last bit of key is always zero.
}


/** Precomputes the shared key from `their_public_key` and `our_secret_key`.

    For fast encrypt/decrypt - this way we can avoid an expensive elliptic
    curve scalar multiply for each encrypt/decrypt operation.

    Use if communication is not one-time.

    `encrypt_precompute` does the shared-key generation once, so that it does
    not have to be performed on every encrypt/decrypt.

    This a wrapper for the
    [`precompute()`](../../../sodiumoxide/crypto/box_/curve25519xsalsa20poly1305/fn.precompute.html)
    function from `sodiumoxide` crate.
*/
#[inline]
pub fn encrypt_precompute(their_public_key: &PublicKey,
                          our_secret_key: &SecretKey) -> PrecomputedKey {
    precompute(their_public_key, our_secret_key)
}
// ↓ can't use, since there's no way to add additional docs
//pub use sodiumoxide::crypto::box_::precompute as encrypt_precompute;


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
pub fn encrypt_data_symmetric(precomputed_key: &PrecomputedKey,
                              nonce: &Nonce,
                              plain: &[u8]) -> Vec<u8> {
    seal_precomputed(plain, nonce, precomputed_key)
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
pub fn decrypt_data_symmetric(precomputed_key: &PrecomputedKey,
                              nonce: &Nonce,
                              encrypted: &[u8]) -> Result<Vec<u8>, ()> {
    open_precomputed(encrypted, nonce, precomputed_key)
}


/** Inrement given nonce by 1.

    Treats `Nonce` as BE number.

    If nonce can't be incremented (all bits are `1`), nonce is zeroed.

    *Note that behaviour of this function might change to not increment supplied
    nonces, but rather, return an increased nonce.*

    Spec: https://zetok.github.io/tox-spec#nonce-2
*/
// TODO: needs to be tested on BE arch
#[inline]
pub fn increment_nonce(nonce: &mut Nonce) {
    let Nonce(ref mut bytes) = *nonce;
    bytes.reverse(); // treat nonce as LE number
    ::sodiumoxide::utils::increment_le(bytes);
    bytes.reverse(); // treat nonce as BE number again
}

/// Inrement given nonce by number `num`.
pub fn increment_nonce_number(nonce: &mut Nonce, num: u64) {
    let Nonce(ref mut bytes) = *nonce;
    bytes.reverse(); // treat nonce as LE number
    let mut num_bytes = [0; NONCEBYTES];
    num_bytes[..8].copy_from_slice(&u64::to_le_bytes(num));
    ::sodiumoxide::utils::add_le(bytes, &num_bytes).unwrap(); // sizes are equal
    bytes.reverse(); // treat nonce as BE number again
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    // test comparing empty keys
    // testing since it would appear that sodiumoxide doesn't do testing for it
    fn public_key_cmp_test_empty() {
        let alice_publickey = PublicKey([0; PUBLICKEYBYTES]);
        let bob_publickey = PublicKey([0; PUBLICKEYBYTES]);

        assert_eq!(alice_publickey.eq(&bob_publickey), true);
        assert_eq!(bob_publickey.eq(&alice_publickey), true);
    }

    #[test]
    // test comparing random public keys
    // testing since it would appear that sodiumoxide doesn't do testing for it
    fn public_key_cmp_test_random() {
        crypto_init().unwrap();
        let (alice_publickey, _alice_secretkey) = gen_keypair();
        let (bob_publickey, _bob_secretkey) = gen_keypair();

        assert_eq!(alice_publickey.eq(&bob_publickey), false);
        assert_eq!(bob_publickey.eq(&alice_publickey), false);

        assert_eq!(alice_publickey.eq(&alice_publickey), true);
        assert_eq!(bob_publickey.eq(&bob_publickey), true);
    }


    #[test]
    fn public_key_valid_test() {
        crypto_init().unwrap();
        let (pk, _) = gen_keypair();
        assert!(public_key_valid(&pk));

        assert!(public_key_valid(&PublicKey([0; PUBLICKEYBYTES]))); // 0
        assert!(public_key_valid(&PublicKey([0b01_11_11_11; PUBLICKEYBYTES]))); // 127
        assert!(!public_key_valid(&PublicKey([0b10_00_00_00; PUBLICKEYBYTES]))); // 128
        assert!(!public_key_valid(&PublicKey([0b11_11_11_11; PUBLICKEYBYTES]))); // 255
    }


    #[test]
    // test uses "bare" functions provided by `sodiumoxide`, with an exception
    // of the tested function
    fn encrypt_precompute_test() {
        crypto_init().unwrap();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();

        let alice_plaintext = b"Hi, Bob.";
        let alice_precomputed_key = encrypt_precompute(&bob_pk, &alice_sk);

        let nonce = gen_nonce();

        let ciphertext = seal_precomputed(alice_plaintext, &nonce, &alice_precomputed_key);

        let bob_precomputed_key = encrypt_precompute(&alice_pk, &bob_sk);
        let bob_plaintext = open_precomputed(&ciphertext, &nonce, &bob_precomputed_key).unwrap();

        assert_eq!(alice_plaintext, &bob_plaintext[..]);
    }


    #[test]
    // test uses "bare" functions provided by `sodiumoxide`, with an "exception"
    // of the tested function
    fn encrypt_data_symmetric_test() {
        crypto_init().unwrap();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();

        let alice_plain = b"Hi, Bob.";

        let precomputed_key = precompute(&bob_pk, &alice_sk);
        let nonce = gen_nonce();

        let ciphertext = encrypt_data_symmetric(&precomputed_key, &nonce, alice_plain);

        let bob_plain = open(&ciphertext, &nonce, &alice_pk, &bob_sk).unwrap();

        assert_eq!(alice_plain, &bob_plain[..]);
    }

    /* TODO: test for pubkey/skey/nonce being all `0`s, which would produce
       ciphertext that should be compared to already known result of this
       computation. This way it would be ensured that cipher algorithm is
       actually working as it should.
       There should be also some additional variations of this test, with different
       pkey/skey/nonce values that would produce known ciphertext.

       Also, similar test for decrypting.
    */


    #[test]
    // test uses "bare" functions provided by `sodiumoxide`, with an exception
    // of the tested function
    fn decrypt_data_symmetric_test() {
        crypto_init().unwrap();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();

        let alice_plain = b"Hi, Bob.";

        let precomputed_key = precompute(&alice_pk, &bob_sk);
        let nonce = gen_nonce();

        let ciphertext = seal(alice_plain, &nonce, &bob_pk, &alice_sk);

        let bob_plain = decrypt_data_symmetric(&precomputed_key, &nonce, &ciphertext).unwrap();

        assert_eq!(alice_plain, &bob_plain[..]);
    }

    #[test]
    fn increment_nonce_test_zero_plus_one() {
        crypto_init().unwrap();
        let cmp_nonce = Nonce([0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 1]);

        let mut nonce = Nonce([0; NONCEBYTES]);
        increment_nonce(&mut nonce);
        assert_eq!(nonce, cmp_nonce);
    }

    #[test]
    fn increment_nonce_test_0xf_plus_one() {
        crypto_init().unwrap();
        let cmp_nonce = Nonce([0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0x10]);

        let mut nonce = Nonce([0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0xf]);
        increment_nonce(&mut nonce);
        assert_eq!(nonce, cmp_nonce);
    }

    #[test]
    fn increment_nonce_test_0xff_plus_one() {
        crypto_init().unwrap();
        let cmp_nonce = Nonce([0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 1, 0]);

        let mut nonce = Nonce([0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0xff]);
        increment_nonce(&mut nonce);
        assert_eq!(nonce, cmp_nonce);
    }

    #[test]
    fn increment_nonce_test_0xff_max() {
        crypto_init().unwrap();
        let cmp_nonce = Nonce([0; NONCEBYTES]);
        let mut nonce = Nonce([0xff; NONCEBYTES]);
        increment_nonce(&mut nonce);
        assert_eq!(cmp_nonce, nonce);
    }

    #[test]
    fn increment_nonce_test_random() {
        crypto_init().unwrap();
        let mut nonce = gen_nonce();
        let cmp_nonce = nonce;
        increment_nonce(&mut nonce);
        assert_ne!(nonce, cmp_nonce);
    }

    // increment_nonce_number()

    #[test]
    fn increment_nonce_number_test_zero_plus_0xff00() {
        crypto_init().unwrap();
        let cmp_nonce = Nonce([0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0xff, 0]);
        let mut nonce = Nonce([0; NONCEBYTES]);

        increment_nonce_number(&mut nonce, 0xff00);
        assert_eq!(nonce, cmp_nonce);
    }

    #[test]
    fn increment_nonce_number_test_0xff0000_plus_0x011000() {
        crypto_init().unwrap();
        let cmp_nonce = Nonce([0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 1, 0, 0x10, 0]);

        let mut nonce = Nonce([0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0xff, 0, 0]);

        increment_nonce_number(&mut nonce, 0x01_10_00);
        assert_eq!(nonce, cmp_nonce);
    }
}
