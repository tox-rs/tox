//! Functions for the core crypto.

use crypto_box::{SalsaBox, aead::generic_array::typenum::marker_traits::Unsigned};
use crypto_box::aead::AeadCore;
pub use crypto_box::{PublicKey, SecretKey};

pub type Nonce = [u8; <SalsaBox as AeadCore>::NonceSize::USIZE];
pub const NONCEBYTES: usize = <SalsaBox as AeadCore>::NonceSize::USIZE;

// TODO: check if `#[inline]` is actually useful

/** Check if Tox public key is valid. Should be used only for input
    validation.

    Returns `true` if valid, `false` otherwise.
*/
pub fn public_key_valid(pk: &PublicKey) -> bool {
    pk.as_bytes()[crypto_box::KEY_SIZE - 1] <= 127 // Last bit of key is always zero.
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

#[cfg(test)]
pub mod tests {
    use super::*;

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
