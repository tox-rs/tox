//! Functions for the core crypto.

pub use sodiumoxide::randombytes::randombytes_into;
pub use sodiumoxide::crypto::box_::*;
pub use sodiumoxide::crypto::hash::{sha256, sha512};
pub use sodiumoxide::crypto::secretbox;

use std::sync::{Once, ONCE_INIT};
use byteorder::{ByteOrder, NativeEndian};

use toxcore::binary_io::*;

// TODO: check if `#[inline]` is actually useful


static CRYPTO_INIT_ONCE: Once = ONCE_INIT;
static mut CRYPTO_INIT: bool = false;

/** Run before using crypto.

Runs [`sodiumoxide::init()`](../../../sodiumoxide/fn.init.html).

Returns `true` on success, `false` otherwise.

E.g.

```
use ::tox::toxcore::crypto_core::crypto_init;

assert_eq!(true, crypto_init());
// second call should yield same result
assert_eq!(true, crypto_init());
```
*/
pub fn crypto_init() -> bool {
    // NOTE: `init()` could be run more than once, but not in parallel, and
    //       `CRYPTO_INIT` *can't* be modified while it may be read by
    //       something else.
    CRYPTO_INIT_ONCE.call_once(|| {
        let initialized = ::sodiumoxide::init();
        unsafe { CRYPTO_INIT = initialized; }
    });
    unsafe { CRYPTO_INIT }
}


/// Return a random number.
pub fn random_u32() -> u32 {
    trace!("Generating random u32");
    let mut array = [0; 4];
    randombytes_into(&mut array);
    NativeEndian::read_u32(&array)
}

/// Return a random number.
pub fn random_u64() -> u64 {
    trace!("Generating random u64");
    let mut array = [0; 8];
    randombytes_into(&mut array);
    NativeEndian::read_u64(&array)
}

/// Return a random number.
#[cfg(target_pointer_width = "32")]
pub fn random_usize() -> usize {
    trace!("Generating random usize");
    random_u32() as usize
}

/// Return a random number.
#[cfg(target_pointer_width = "64")]
pub fn random_usize() -> usize {
    trace!("Generating random usize");
    random_u64() as usize
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
    trace!(target: "Nonce", "Incrementing Nonce: {:?}", &nonce);
    let Nonce(ref mut bytes) = *nonce;
    bytes.reverse(); // treat nonce as LE number
    ::sodiumoxide::utils::increment_le(bytes);
    bytes.reverse(); // treat nonce as BE number again
}

/// Inrement given nonce by number `num`.
pub fn increment_nonce_number(mut nonce: &mut Nonce, num: usize) {
    for _ in 0..num {
        increment_nonce(&mut nonce);
    }
}

/// Convert `PublicKey` to sha256 `Digest` type.
pub fn pk_as_digest(pk: PublicKey) -> sha256::Digest {
    // can not fail since PublicKey has the same length as sha256 Digest
    sha256::Digest::from_slice(pk.as_ref()).unwrap()
}

/// Convert sha256 `Digest` to `PublicKey` type.
pub fn digest_as_pk(d: sha256::Digest) -> PublicKey {
    // can not fail since sha256 Digest has the same length as PublicKey
    PublicKey::from_slice(d.as_ref()).unwrap()
}

impl FromBytes for PublicKey {
    named!(from_bytes<PublicKey>, verify!(
        map_opt!(take!(PUBLICKEYBYTES), PublicKey::from_slice),
        |pk| public_key_valid(&pk)
    ));
}

impl FromBytes for SecretKey {
    named!(from_bytes<SecretKey>, map_opt!(take!(SECRETKEYBYTES), SecretKey::from_slice));
}

impl FromBytes for Nonce {
    named!(from_bytes<Nonce>, map_opt!(take!(NONCEBYTES), Nonce::from_slice));
}

impl FromBytes for secretbox::Nonce {
    named!(from_bytes<secretbox::Nonce>, map_opt!(take!(secretbox::NONCEBYTES), secretbox::Nonce::from_slice));
}

impl FromBytes for sha256::Digest {
    named!(from_bytes<sha256::Digest>, map_opt!(take!(sha256::DIGESTBYTES), sha256::Digest::from_slice));
}

impl FromBytes for sha512::Digest {
    named!(from_bytes<sha512::Digest>, map_opt!(take!(sha512::DIGESTBYTES), sha512::Digest::from_slice));
}
