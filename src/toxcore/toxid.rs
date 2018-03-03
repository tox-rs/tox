/*
    Copyright © 2016 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2018 Roman Proskuryakov <humbug@deeptown.org>

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

/*! `Tox ID` and stuff related to it.

    https://zetok.github.io/tox-spec/#tox-id
*/
// FIXME: ↑ improve
// TODO: ↓ add logging


use std::default::Default;
use std::fmt;

use toxcore::binary_io_new::*;
use toxcore::crypto_core::*;

/** Calculate XOR checksum for 2 [u8; 2].

    Used for calculating checksum of ToxId.

    https://zetok.github.io/tox-spec/#tox-id , 4th paragraph.
*/
pub fn xor_checksum(lhs: &[u8; 2], rhs: &[u8; 2]) -> [u8; 2] {
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

/// Number of bytes that [`NoSpam`](./struct.NoSpam.html) has.
pub const NOSPAMBYTES: usize = 4;

impl NoSpam {
    /** Create new `NoSpam` with random bytes.

    Two `new()` `NoSpam`s will always be different:

    ```
    use self::tox::toxcore::toxid::NoSpam;

    assert!(NoSpam::new() != NoSpam::new());
    ```
    */
    pub fn new() -> Self {
        let mut nospam = [0; NOSPAMBYTES];
        randombytes_into(&mut nospam);
        NoSpam(nospam)
    }
}

/** Always returns a random `NoSpam`. Equivalent to the [`NoSpam::new()`]
(#method.new).
*/
impl Default for NoSpam {
    fn default() -> Self {
        NoSpam::new()
    }
}

/** The default formatting of `NoSpam`.

E.g.:

```
use self::tox::toxcore::toxid::NoSpam;

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
use self::tox::toxcore::toxid::NoSpam;

let nospam = NoSpam::new();
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
pub const TOXIDBYTES: usize = PUBLICKEYBYTES + NOSPAMBYTES + 2;

impl ToxId {
    /** Checksum of `PublicKey` and `NoSpam`.

    https://zetok.github.io/tox-spec/#tox-id , 4th paragraph.

    E.g.

    ```
    use self::tox::toxcore::crypto_core::{
            gen_keypair,
            PublicKey,
            PUBLICKEYBYTES,
    };
    use self::tox::toxcore::toxid::{NoSpam, NOSPAMBYTES, ToxId};

    let (pk, _) = gen_keypair();
    let nospam = NoSpam::new();

    let _checksum = ToxId::checksum(&pk, &nospam);

    assert_eq!(ToxId::checksum(&PublicKey([0; PUBLICKEYBYTES]),
               &NoSpam([0; NOSPAMBYTES])), [0; 2]);
    assert_eq!(ToxId::checksum(&PublicKey([0xff; PUBLICKEYBYTES]),
               &NoSpam([0xff; NOSPAMBYTES])), [0; 2]);
    ```
    */
    pub fn checksum(&PublicKey(ref pk): &PublicKey, nospam: &NoSpam) -> [u8; 2] {
        let mut bytes = Vec::with_capacity(TOXIDBYTES - 2);
        bytes.extend_from_slice(pk);
        bytes.extend_from_slice(nospam.0.as_ref());

        let mut checksum = [0; 2];

        for pair in bytes.chunks(2) {
            checksum = xor_checksum(&checksum, &[pair[0], pair[1]]);
        }
        checksum
    }

    /** Create new `ToxId`.

    E.g.

    ```
    use self::tox::toxcore::crypto_core::gen_keypair;
    use self::tox::toxcore::toxid::ToxId;

    let (pk, _) = gen_keypair();
    let _toxid = ToxId::new(pk);
    ```
    */
    pub fn new(pk: PublicKey) -> Self {
        let nospam = NoSpam::new();
        let checksum = Self::checksum(&pk, &nospam);
        ToxId { pk, nospam, checksum }
    }

    /** Change `NoSpam`. If provided, change to provided value. If not provided
    (`None`), generate random `NoSpam`.

    After `NoSpam` change PublicKey is always the same, but `NoSpam` and
    `checksum` differ:

    ```
    use self::tox::toxcore::crypto_core::gen_keypair;
    use self::tox::toxcore::toxid::{NoSpam, ToxId};

    let (pk, _) = gen_keypair();
    let toxid = ToxId::new(pk);
    let mut toxid2 = toxid;
    toxid2.new_nospam(None);

    assert!(toxid != toxid2);
    assert_eq!(toxid.pk, toxid2.pk);

    let mut toxid3 = toxid;

    // with same `NoSpam` IDs are identical
    let nospam = NoSpam::new();
    toxid2.new_nospam(Some(nospam));
    toxid3.new_nospam(Some(nospam));
    assert_eq!(toxid2, toxid3);
    ```
    */
    // TODO: more tests
    // TODO: ↓ split into `new_nospam()` and `set_nospam(NoSpam)` ?
    pub fn new_nospam(&mut self, nospam: Option<NoSpam>) {
        if let Some(nospam) = nospam {
            self.nospam = nospam;
        } else {
            self.nospam = NoSpam::new();
        }
        self.checksum = Self::checksum(&self.pk, &self.nospam);
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
use self::tox::toxcore::crypto_core::{PublicKey, PUBLICKEYBYTES};
use self::tox::toxcore::toxid::{NoSpam, NOSPAMBYTES, ToxId};

let mut toxid = ToxId::new(PublicKey([0; PUBLICKEYBYTES]));
toxid.new_nospam(Some(NoSpam([0; NOSPAMBYTES])));
// 76 `0`s
assert_eq!(&format!("{:X}", toxid),
    "0000000000000000000000000000000000000000000000000000000000000000000000000000");

let mut toxid = ToxId::new(PublicKey([255; PUBLICKEYBYTES]));
toxid.new_nospam(Some(NoSpam([255; NOSPAMBYTES])));
// 72 `F`s + 4 `0`s
assert_eq!(&format!("{:X}", toxid),
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000");
```
*/
impl fmt::UpperHex for ToxId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut string = String::with_capacity(TOXIDBYTES * 2);
        let PublicKey(ref pk_bytes) = self.pk;
        for byte in pk_bytes {
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
use self::tox::toxcore::crypto_core::gen_keypair;
use self::tox::toxcore::toxid::ToxId;

let (pk, _) = gen_keypair();
let toxid = ToxId::new(pk);
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
    extern crate rand;
    extern crate rustc_serialize;

    use quickcheck::quickcheck;

    use ::toxcore::binary_io_new::*;
    use ::toxcore::crypto_core::*;
    use ::toxcore::toxid::*;

    fn test_is_hexdump_uppercase(s: &str) -> bool {
        fn test_is_hexdump_uppercase_b(b: u8) -> bool {
            if let b'A' ... b'F' = b {
                true
            } else if let b'0' ... b'9' = b {
                true
            } else {
                false
            }
        }
        s.bytes().all(test_is_hexdump_uppercase_b)
    }

    // NoSpam::

    #[cfg(test)]
    fn no_spam_no_empty(ns: &NoSpam) {
        // shouldn't be empty, unless your PRNG is crappy
        assert!(ns.0 != [0; NOSPAMBYTES])
    }

    // NoSpam::new()

    #[test]
    fn no_spam_new_test() {
        let ns = NoSpam::new();
        no_spam_no_empty(&ns);
    }

    // NoSpam::default()

    #[test]
    fn no_spam_default_test() {
        let ns = NoSpam::default();
        no_spam_no_empty(&ns);
    }

    // NoSpam::fmt()

    #[test]
    fn no_spam_fmt_test() {
        // check if formatted NoSpam is always upper-case hexadecimal with matching
        // length
        let nospam = NoSpam::new();
        assert_eq!(false, test_is_hexdump_uppercase("Not HexDump"));
        assert_eq!(true, test_is_hexdump_uppercase(&format!("{:X}", nospam)));
        assert_eq!(true, test_is_hexdump_uppercase(&format!("{}", nospam)));
        assert_eq!(true, test_is_hexdump_uppercase(&format!("{:X}", NoSpam([0, 0, 0, 0]))));
        assert_eq!(true, test_is_hexdump_uppercase(&format!("{}", NoSpam([0, 0, 0, 0]))));
        assert_eq!(true, test_is_hexdump_uppercase(&format!("{:X}", NoSpam([15, 15, 15, 15]))));
        assert_eq!(true, test_is_hexdump_uppercase(&format!("{}", NoSpam([15, 15, 15, 15]))));
    }

    // NoSpam::from_bytes()

    #[test]
    fn no_spam_from_bytes_test() {
        fn with_bytes(bytes: Vec<u8>) {
            if bytes.len() < NOSPAMBYTES {
                assert!(NoSpam::from_bytes(&bytes).is_incomplete());
            } else {
                let nospam = NoSpam::from_bytes(&bytes)
                                .to_result()
                                .expect("Failed to get NoSpam!");
                assert_eq!(bytes[0], nospam.0[0]);
                assert_eq!(bytes[1], nospam.0[1]);
                assert_eq!(bytes[2], nospam.0[2]);
                assert_eq!(bytes[3], nospam.0[3]);
            }
        }
        quickcheck(with_bytes as fn(Vec<u8>));
    }

    encode_decode_test!(
        no_spam_encode_decode,
        NoSpam::new()
    );

    // ToxId::

    // ToxId::new_nospam

    #[test]
    fn tox_id_new_nospam_test() {
        let (pk, _) = gen_keypair();
        let toxid = ToxId::new(pk);
        let mut toxid2 = toxid;
        toxid2.new_nospam(None);

        assert!(toxid != toxid2);
        assert_eq!(toxid.pk, toxid2.pk);

        let mut toxid3 = toxid;

        // with same `NoSpam` IDs are identical
        let nospam = NoSpam::new();
        toxid2.new_nospam(Some(nospam));
        toxid3.new_nospam(Some(nospam));
        assert_eq!(toxid2, toxid3);
    }

    // ToxId::fmt()

    #[test]
    fn tox_id_fmt_test() {
        // check if formatted ToxId is always upper-case hexadecimal with matching
        // length
        let (pk, _) = gen_keypair();
        let toxid = ToxId::new(pk);
        assert_eq!(true, test_is_hexdump_uppercase(&format!("{:X}", toxid)));
        assert_eq!(true, test_is_hexdump_uppercase(&format!("{}", toxid)));
    }

    encode_decode_test!(
        toxid_encode_decode,
        ToxId::new(gen_keypair().0)
    );
}
