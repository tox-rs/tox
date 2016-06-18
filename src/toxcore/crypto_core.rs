/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2016 Roman <humbug@deeptown.org>
    Copyright © 2016 Zetok Zalbavar <zexavexxe@gmail.com>

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

//! Functions for the core crypto.

pub use sodiumoxide::randombytes::randombytes_into;
pub use sodiumoxide::crypto::box_::*;

use super::binary_io::*;

// TODO: check if `#[inline]` is actually useful

/// Return a random number.
pub fn random_u32() -> u32 {
    trace!("Generating random u32");
    let mut array = [0; 4];
    randombytes_into(&mut array);
    array_to_u32(&array)
}

/// Return a random number.
pub fn random_u64() -> u64 {
    trace!("Generating random u64");
    let mut array = [0; 8];
    randombytes_into(&mut array);
    array_to_u64(&array)
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

    Spec: https://toktok.github.io/spec#nonce-2
*/
// TODO: needs to be tested on BE arch
#[inline]
pub fn increment_nonce(nonce: &mut Nonce) {
    trace!(target: "Nonce", "Incrementing Nonce: {:?}", &nonce);
    let Nonce(ref mut nonce) = *nonce;
    for num in nonce.iter_mut().rev() {
        if *num < ::std::u8::MAX {
            *num += 1;
            return
        } else {
            // zero if it can't be incremented
            *num = 0;
        }
    }
}


/// Inrement given nonce by number `num`.
pub fn increment_nonce_number(mut nonce: &mut Nonce, num: usize) {
    for _ in 0..num {
        increment_nonce(&mut nonce);
    }
}

impl FromBytes for PublicKey {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        debug!(target: "PublicKey", "Creating PublicKey from bytes.");
        trace!(target: "PublicKey", "Bytes: {:?}", bytes);

        if bytes.len() < PUBLICKEYBYTES {
            return parse_error!("Not enough bytes for PublicKey.");
        }
        
        let pk = match PublicKey::from_slice(&bytes[..PUBLICKEYBYTES]) {
            Some(p) => p,
            None    =>
                return parse_error!("Failed; de-serializing PublicKey! \
                                     With bytes for PublicKey: {:?}",
                                     &bytes[..PUBLICKEYBYTES])
        };

        Ok(Parsed(pk, &bytes[PUBLICKEYBYTES..]))
    }
}

impl FromBytes for SecretKey {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        debug!(target: "SecretKey", "Creating SecretKey from bytes.");

        if bytes.len() < SECRETKEYBYTES {
            return parse_error!("Not enough bytes for SecretKey.");
        }
        
        let pk = match SecretKey::from_slice(&bytes[..SECRETKEYBYTES]) {
            Some(p) => p,
            None    =>
                return parse_error!("Failed; de-serializing SecretKey! \
                                     With bytes for SecretKey: {:?}",
                                     &bytes[..SECRETKEYBYTES])
        };

        Ok(Parsed(pk, &bytes[SECRETKEYBYTES..]))
    }
}

impl FromBytes for Nonce {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        debug!(target: "Nonce", "Creating Nonce from bytes.");
        trace!(target: "Nonce", "Bytes: {:?}", bytes);

        if bytes.len() < NONCEBYTES {
            return parse_error!("Not enough bytes for Nonce.");
        }
        
        let nonce = match Nonce::from_slice(&bytes[..NONCEBYTES]) {
            Some(n) => n,
            None    =>
                return parse_error!("Failed; de-serializing nonce! \
                                     With bytes for nonce: {:?}",
                                     &bytes[..NONCEBYTES])
        };

        Ok(Parsed(nonce, &bytes[NONCEBYTES..]))
    }
}
