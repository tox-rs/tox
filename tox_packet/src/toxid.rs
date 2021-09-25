/*! `Tox ID` and stuff related to it.

    https://zetok.github.io/tox-spec/#tox-id
*/
// FIXME: ↑ improve
// TODO: ↓ add logging


use std::fmt;

use nom::{
    named,
    do_parse, map, call, take,
};
use rand::{CryptoRng, Rng, distributions::{Distribution, Standard}};
use cookie_factory::{do_gen, gen_slice};

use tox_binary_io::*;
use tox_crypto::*;

/** Calculate XOR checksum for 2 [u8; 2].

    Used for calculating checksum of ToxId.

    https://zetok.github.io/tox-spec/#tox-id , 4th paragraph.
*/
pub fn xor_checksum(lhs: [u8; 2], rhs: [u8; 2]) -> [u8; 2] {
    [lhs[0] ^ rhs[0], lhs[1] ^ rhs[1]]
}

/** `NoSpam` used in [`ToxId`](./struct.ToxId.html).

Number is used to make sure that there is no friend requests from peers
that know out long term PK, but don't actually know Tox ID.

The preferred way of creating `NoSpam` is to generate a random one.

Additionally, it should be possible to set a custom `NoSpam`.

https://zetok.github.io/tox-spec/#tox-id
*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoSpam(pub [u8; NOSPAMBYTES]);

impl Distribution<NoSpam> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> NoSpam {
        NoSpam(rng.gen())
    }
}

/// Number of bytes that [`NoSpam`](./struct.NoSpam.html) has.
pub const NOSPAMBYTES: usize = 4;

/** The default formatting of `NoSpam`.

E.g.:

```
use tox_packet::toxid::NoSpam;

assert_eq!(format!("{:X}", NoSpam([0, 0, 0, 0])), "00000000");
assert_eq!(format!("{:X}", NoSpam([255, 255, 255, 255])), "FFFFFFFF");
```
*/
impl fmt::UpperHex for NoSpam {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:02X}{:02X}{:02X}{:02X}",
               self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

/** `Display` should always be the same as `UpperHex`.

```
use tox_packet::toxid::NoSpam;

let nospam = NoSpam([255, 255, 255, 255]);
assert_eq!(format!("{}", nospam), format!("{:X}", nospam));
```
*/
impl fmt::Display for NoSpam {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:X}", self)
    }
}

impl FromBytes for NoSpam {
    named!(from_bytes<NoSpam>, map!(take!(NOSPAMBYTES), |bytes| {
        NoSpam([bytes[0], bytes[1], bytes[2], bytes[3]])
    }));
}

impl ToBytes for NoSpam {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(&self.0)
        )
    }
}

/** `Tox ID`.

Length | Contents
------ | --------
32     | long term `PublicKey`
4      | `NoSpam`
2      | Checksum

https://zetok.github.io/tox-spec/#tox-id
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToxId {
    /// Long-term `PublicKey`.
    pub pk: PublicKey,
    /// `NoSpam`.
    nospam: NoSpam,
    checksum: [u8; 2],
}

/// Number of bytes that checksum of [`ToxId`](./struct.ToxId.html) has.
pub const CHECKSUMBYTES: usize = 2;

/// Number of bytes of serialized [`ToxId`](./struct.ToxId.html).
pub const TOXIDBYTES: usize = crypto_box::KEY_SIZE + NOSPAMBYTES + 2;

impl ToxId {
    /** Checksum of `PublicKey` and `NoSpam`.

    https://zetok.github.io/tox-spec/#tox-id , 4th paragraph.

    E.g.

    ```
    use crypto_box::{PublicKey, SecretKey, KEY_SIZE};
    use rand::{Rng, thread_rng};
    use tox_packet::toxid::{NoSpam, NOSPAMBYTES, ToxId};

    let mut rng = thread_rng();
    let pk = SecretKey::generate(&mut rng).public_key();
    let nospam = rng.gen();

    let _checksum = ToxId::checksum(&pk, nospam);

    assert_eq!(ToxId::checksum(&PublicKey::from([0; KEY_SIZE]),
               NoSpam([0; NOSPAMBYTES])), [0; 2]);
    assert_eq!(ToxId::checksum(&PublicKey::from([0xff; KEY_SIZE]),
               NoSpam([0xff; NOSPAMBYTES])), [0; 2]);
    ```
    */
    pub fn checksum(pk: &PublicKey, nospam: NoSpam) -> [u8; 2] {
        let mut bytes = Vec::with_capacity(TOXIDBYTES - 2);
        bytes.extend_from_slice(pk.as_bytes());
        bytes.extend_from_slice(nospam.0.as_ref());

        let mut checksum = [0; 2];

        for pair in bytes.chunks(2) {
            checksum = xor_checksum(checksum, [pair[0], pair[1]]);
        }
        checksum
    }

    /** Create new `ToxId`.

    E.g.

    ```
    use crypto_box::SecretKey;
    use rand::thread_rng;
    use tox_packet::toxid::ToxId;

    let mut rng = thread_rng();
    let pk = SecretKey::generate(&mut rng).public_key();
    let _toxid = ToxId::new(&mut rng, pk);
    ```
    */
    pub fn new<R: Rng + CryptoRng>(rng: &mut R, pk: PublicKey) -> Self {
        let nospam = rng.gen();
        let checksum = Self::checksum(&pk, nospam);
        ToxId { pk, nospam, checksum }
    }

    /** Change `NoSpam`. If provided, change to provided value. If not provided
    (`None`), generate random `NoSpam`.

    After `NoSpam` change PublicKey is always the same, but `NoSpam` and
    `checksum` differ:

    ```
    use crypto_box::SecretKey;
    use rand::{Rng, thread_rng};
    use tox_packet::toxid::{NoSpam, ToxId};

    let mut rng = thread_rng();
    let pk = SecretKey::generate(&mut rng).public_key();
    let toxid = ToxId::new(&mut rng, pk);
    let mut toxid2 = toxid.clone();
    toxid2.new_nospam(&mut rng, None);

    assert_ne!(toxid, toxid2);
    assert_eq!(toxid.pk, toxid2.pk);

    let mut toxid3 = toxid;

    // with same `NoSpam` IDs are identical
    let nospam = rng.gen();
    toxid2.new_nospam(&mut rng, Some(nospam));
    toxid3.new_nospam(&mut rng, Some(nospam));
    assert_eq!(toxid2, toxid3);
    ```
    */
    // TODO: more tests
    // TODO: ↓ split into `new_nospam()` and `set_nospam(NoSpam)` ?
    pub fn new_nospam<R: Rng + CryptoRng>(&mut self, rng: &mut R, nospam: Option<NoSpam>) {
        if let Some(nospam) = nospam {
            self.nospam = nospam;
        } else {
            self.nospam = rng.gen();
        }
        self.checksum = Self::checksum(&self.pk, self.nospam);
    }
}

impl FromBytes for ToxId {
    named!(from_bytes<ToxId>, do_parse!(
        pk: call!(PublicKey::from_bytes) >>
        nospam: call!(NoSpam::from_bytes) >>
        checksum: map!(take!(CHECKSUMBYTES), |bytes| { [bytes[0], bytes[1]] }) >>
        (ToxId { pk, nospam, checksum })
    ));
}

impl ToBytes for ToxId {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(&self.nospam.0) >>
            gen_slice!(&self.checksum)
        )
    }
}

/** The default formatting for `ToxId`.

E.g.

```
use rand::thread_rng;
use crypto_box::{PublicKey, KEY_SIZE};
use tox_packet::toxid::{NoSpam, NOSPAMBYTES, ToxId};

let mut rng = thread_rng();
let mut toxid = ToxId::new(&mut rng, PublicKey::from([0; KEY_SIZE]));
toxid.new_nospam(&mut rng, Some(NoSpam([0; NOSPAMBYTES])));
// 76 `0`s
assert_eq!(&format!("{:X}", toxid),
    "0000000000000000000000000000000000000000000000000000000000000000000000000000");

let mut toxid = ToxId::new(&mut rng, PublicKey::from([255; KEY_SIZE]));
toxid.new_nospam(&mut rng, Some(NoSpam([255; NOSPAMBYTES])));
// 72 `F`s + 4 `0`s
assert_eq!(&format!("{:X}", toxid),
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000");
```
*/
impl fmt::UpperHex for ToxId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut string = String::with_capacity(TOXIDBYTES * 2);
        for byte in self.pk.as_bytes() {
            string.push_str(&format!("{:02X}", byte));
        }
        for byte in &self.nospam.0 {
            string.push_str(&format!("{:02X}", byte));
        }
        string.push_str(&format!("{:02X}{:02X}", self.checksum[0],
                                    self.checksum[1]));
        write!(f, "{}", string)
    }
}

/** Same as `UpperHex`.

E.g.

```
use crypto_box::SecretKey;
use rand::thread_rng;
use tox_packet::toxid::ToxId;

let mut rng = thread_rng();
let pk = SecretKey::generate(&mut rng).public_key();
let toxid = ToxId::new(&mut rng, pk);
assert_eq!(format!("{}", toxid), format!("{:X}", toxid));
```
*/
impl fmt::Display for ToxId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:X}", self)
    }
}

#[cfg(test)]
mod tests {
    use crate::toxid::*;
    use rand::thread_rng;

    fn test_is_hexdump_uppercase(s: &str) -> bool {
        fn test_is_hexdump_uppercase_b(b: u8) -> bool {
            matches!(b, b'A' ..= b'F') || matches!(b, b'0' ..= b'9')
        }
        s.bytes().all(test_is_hexdump_uppercase_b)
    }

    // NoSpam::

    // NoSpam::fmt()

    #[test]
    fn no_spam_fmt() {
        // check if formatted NoSpam is always upper-case hexadecimal with matching
        // length
        assert!(!test_is_hexdump_uppercase("Not HexDump"));
        assert!(test_is_hexdump_uppercase(&format!("{:X}", NoSpam([42; NOSPAMBYTES]))));
        assert!(test_is_hexdump_uppercase(&format!("{}", NoSpam([42; NOSPAMBYTES]))));
        assert!(test_is_hexdump_uppercase(&format!("{:X}", NoSpam([0, 0, 0, 0]))));
        assert!(test_is_hexdump_uppercase(&format!("{}", NoSpam([0, 0, 0, 0]))));
        assert!(test_is_hexdump_uppercase(&format!("{:X}", NoSpam([15, 15, 15, 15]))));
        assert!(test_is_hexdump_uppercase(&format!("{}", NoSpam([15, 15, 15, 15]))));
    }

    // NoSpam::from_bytes()

    encode_decode_test!(
        no_spam_encode_decode,
        NoSpam([42; NOSPAMBYTES])
    );

    // ToxId::

    // ToxId::new_nospam

    #[test]
    fn tox_id_new_nospam() {
        let mut rng = thread_rng();

        let pk = SecretKey::generate(&mut rng).public_key();
        let toxid = ToxId::new(&mut rng, pk);
        let mut toxid2 = toxid.clone();
        toxid2.new_nospam(&mut rng, None);

        assert_ne!(toxid, toxid2);
        assert_eq!(toxid.pk, toxid2.pk);

        let mut toxid3 = toxid;

        // with same `NoSpam` IDs are identical
        let nospam = rng.gen();
        toxid2.new_nospam(&mut rng, Some(nospam));
        toxid3.new_nospam(&mut rng, Some(nospam));
        assert_eq!(toxid2, toxid3);
    }

    // ToxId::fmt()

    #[test]
    fn tox_id_fmt() {
        // check if formatted ToxId is always upper-case hexadecimal with matching
        // length
        let pk = SecretKey::generate(&mut thread_rng()).public_key();
        let toxid = ToxId::new(&mut thread_rng(), pk);
        assert!(test_is_hexdump_uppercase(&format!("{:X}", toxid)));
        assert!(test_is_hexdump_uppercase(&format!("{}", toxid)));
    }

    encode_decode_test!(
        toxid_encode_decode,
        ToxId::new(&mut thread_rng(), SecretKey::generate(&mut thread_rng()).public_key())
    );
}
