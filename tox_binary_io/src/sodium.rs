use std::convert::TryInto;

use nom::{map, map_opt, named, take};

use crypto_box::{PublicKey, SecretKey, KEY_SIZE};

use super::FromBytes;


impl FromBytes for PublicKey {
    // TODO: use map_from with new nom version
    named!(from_bytes<PublicKey>, map!(map_opt!(take!(KEY_SIZE), |pk: &[u8]| pk.try_into().ok()), |pk: [u8; KEY_SIZE]| pk.into()));
}

/* TODO
Use the following implementation when https://github.com/TokTok/c-toxcore/issues/1169 is fixed.
And when most of tox network will send valid PK for fake friends.

impl FromBytes for PublicKey {
    named!(from_bytes<PublicKey>, verify!(
        // TODO: use map_from with new nom version
        map!(map_opt!(take!(KEY_SIZE), |pk: &[u8]| pk.try_into().ok()), |pk: [u8; KEY_SIZE]| pk.into()),
        |pk| public_key_valid(&pk)
    ));
}
*/

impl FromBytes for SecretKey {
    // TODO: use map_from with new nom version
    named!(from_bytes<SecretKey>, map!(map_opt!(take!(KEY_SIZE), |sk: &[u8]| sk.try_into().ok()), |sk: [u8; KEY_SIZE]| sk.into()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_parse_bytes_test() {
        let bytes = [42; KEY_SIZE];
        let (_rest, pk) = PublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(pk.as_bytes(), &bytes as &[u8]);
    }

    #[test]
    fn secret_key_parse_bytes_test() {
        let bytes = [42; KEY_SIZE];
        let (_rest, sk) = SecretKey::from_bytes(&bytes).unwrap();

        assert_eq!(&sk.to_bytes()[..], &bytes as &[u8]);
    }
}
