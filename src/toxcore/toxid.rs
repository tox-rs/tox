/*
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

/*! `Tox ID` and stuff related to it.

    https://zetok.github.io/tox-spec/#tox-id
*/
// FIXME: ↑ improve
// TODO: ↓ add logging


use std::default::Default;
use std::fmt;

use super::binary_io::*;
use super::crypto_core::*;


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
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        debug!(target: "NoSpam", "Creating NoSpam from bytes.");
        trace!(target: "NoSpam", "Bytes: {:?}", bytes);

        if bytes.len() < NOSPAMBYTES {
            return parse_error!("Not enough bytes for NoSpam.");
        }

        let nospam = NoSpam([bytes[0], bytes[1], bytes[2], bytes[3]]);

        Ok(Parsed(nospam, &bytes[NOSPAMBYTES..]))
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
        ToxId {
            pk: pk,
            nospam: nospam,
            checksum: Self::checksum(&pk, &nospam),
        }
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

/** Should always work, provided that there are supplied at least
[`TOXIDBYTES`](./constant.TOXIDBYTES.html).

Note that `ToxId` might not have a valid [`NoSpam`](./struct.NoSpam.html) from
provided bytes.

E.g.

```
use self::tox::toxcore::binary_io::FromBytes;
use self::tox::toxcore::toxid::{ToxId, TOXIDBYTES};

let bytes = [0; TOXIDBYTES + 10];

assert_eq!(None, ToxId::from_bytes(&bytes[..TOXIDBYTES - 11]));
let _toxid = ToxId::from_bytes(&bytes).expect("Failed to get ToxId from bytes!");
```
*/
impl FromBytes for ToxId {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        debug!(target: "ToxId", "Creating ToxId from bytes.");
        trace!(target: "ToxId", "Bytes: {:?}", bytes);

        fn parse_checksum(bytes: &[u8]) -> ParseResult<[u8; 2]> {
            if bytes.len() < 2 {
                return parse_error!("Not enough bytes for ToxId checksum.")
            }

            Ok(Parsed([bytes[0], bytes[1]], &bytes[2..]))
        }

        let Parsed(pk, bytes) = try!(PublicKey::parse_bytes(bytes));
        let Parsed(nospam, bytes) = try!(NoSpam::parse_bytes(bytes));
        let Parsed(checksum, bytes) = try!(parse_checksum(bytes));

        Ok(Parsed(ToxId {
            pk: pk,
            nospam: nospam,
            checksum: checksum,
        }, bytes))
    }
}

/** E.g.

```
use self::tox::toxcore::binary_io::ToBytes;
use self::tox::toxcore::crypto_core::{gen_keypair, PublicKey, PUBLICKEYBYTES};
use self::tox::toxcore::toxid::{NoSpam, NOSPAMBYTES, ToxId, TOXIDBYTES};

// create a `0` Tox ID
let mut toxid = ToxId::new(PublicKey([0; PUBLICKEYBYTES]));
toxid.new_nospam(Some(NoSpam([0; NOSPAMBYTES])));
let toxid_bytes = toxid.to_bytes();
assert_eq!([0; TOXIDBYTES].to_vec(), toxid_bytes);


// and a random one
let (pk, _) = gen_keypair();
let PublicKey(ref pk_bytes) = pk;
let toxid_bytes = ToxId::new(pk).to_bytes();
assert_eq!(pk_bytes, &toxid_bytes[..PUBLICKEYBYTES]);
```
*/
impl ToBytes for ToxId {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(TOXIDBYTES);
        let PublicKey(pk) = self.pk;
        result.extend_from_slice(&pk);
        result.extend_from_slice(&self.nospam.0);
        result.extend_from_slice(&self.checksum);
        result
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
