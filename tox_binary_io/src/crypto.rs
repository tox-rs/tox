use std::convert::TryInto;

use nom::IResult;
use nom::bytes::streaming::take;
use nom::combinator::{map, map_opt};

use crypto_box::{PublicKey, SecretKey, KEY_SIZE};

use super::FromBytes;


impl FromBytes for PublicKey {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        map(map_opt(take(KEY_SIZE), |pk: &[u8]| pk.try_into().ok()), |pk: [u8; KEY_SIZE]| pk.into())(input)
    }
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
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        map(map_opt(take(KEY_SIZE), |sk: &[u8]| sk.try_into().ok()), |sk: [u8; KEY_SIZE]| sk.into())(input)
    }
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

        assert_eq!(sk.as_bytes(), &bytes as &[u8]);
    }
}
