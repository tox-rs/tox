use nom::named;

use nom::{map_opt, take};

use sodiumoxide::crypto::box_::{
    PublicKey,
    SecretKey,
    Nonce,
    PUBLICKEYBYTES,
    SECRETKEYBYTES,
    NONCEBYTES
};

use sodiumoxide::crypto::hash::{sha256, sha512};
use sodiumoxide::crypto::secretbox;

use super::FromBytes;


#[cfg(feature = "sodiumoxide")]
impl FromBytes for PublicKey {
    named!(from_bytes<PublicKey>, map_opt!(take!(PUBLICKEYBYTES), PublicKey::from_slice));
}

/* TODO
Use the following implementation when https://github.com/TokTok/c-toxcore/issues/1169 is fixed.
And when most of tox network will send valid PK for fake friends.

impl FromBytes for PublicKey {
    named!(from_bytes<PublicKey>, verify!(
        map_opt!(take!(PUBLICKEYBYTES), PublicKey::from_slice),
        |pk| public_key_valid(&pk)
    ));
}
*/

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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn public_key_parse_bytes_test() {
        let bytes = [42; PUBLICKEYBYTES];
        let (_rest, PublicKey(pk_bytes)) = PublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(pk_bytes, &bytes as &[u8]);
    }

    #[test]
    fn secret_key_parse_bytes_test() {
        let bytes = [42; SECRETKEYBYTES];
        let (_rest, SecretKey(sk_bytes)) = SecretKey::from_bytes(&bytes).unwrap();

        assert_eq!(sk_bytes, &bytes as &[u8]);
    }

    #[test]
    fn nonce_parse_bytes_test() {
        let bytes = [42; NONCEBYTES];
        let (_rest, Nonce(nonce_bytes)) = Nonce::from_bytes(&bytes).unwrap();

        assert_eq!(nonce_bytes, &bytes as &[u8]);
    }
}
