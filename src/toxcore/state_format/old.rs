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

//! Old state format. *__Will be deprecated__ when something better will become
//! available.*

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::dht::*;
use toxcore::toxid::{NoSpam, NOSPAMBYTES};

// TODO: improve docs

/** Sections of the old state format.

https://zetok.github.io/tox-spec/#sections

## Serialization into bytes

```
use self::tox::toxcore::state_format::old::SectionKind;

assert_eq!(1u8, SectionKind::NospamKeys as u8);
assert_eq!(2u8, SectionKind::DHT as u8);
assert_eq!(3u8, SectionKind::Friends as u8);
assert_eq!(4u8, SectionKind::Name as u8);
assert_eq!(5u8, SectionKind::StatusMsg as u8);
assert_eq!(6u8, SectionKind::Status as u8);
assert_eq!(10u8, SectionKind::TcpRelays as u8);
assert_eq!(11u8, SectionKind::PathNodes as u8);
assert_eq!(255u8, SectionKind::EOF as u8);
```
*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SectionKind {
    /// Section for [`NoSpam`](../../toxid/struct.NoSpam.html), public and
    /// secret keys.
    ///
    /// https://zetok.github.io/tox-spec/#nospam-and-keys-0x01
    NospamKeys = 0x01,
    /// Section for DHT-related data.
    ///
    /// https://zetok.github.io/tox-spec/#dht-0x02
    DHT =        0x02,
    /// Section for friends data.
    ///
    /// https://zetok.github.io/tox-spec/#friends-0x03
    Friends =    0x03,
    /// Section for own name.
    ///
    /// https://zetok.github.io/tox-spec/#name-0x04
    Name =       0x04,
    /// Section for own status message.
    ///
    /// https://zetok.github.io/tox-spec/#status-message-0x05
    StatusMsg =  0x05,
    /// Section for own status.
    ///
    /// https://zetok.github.io/tox-spec/#status-0x06
    Status =     0x06,
    /// Section for a list of TCP relays.
    ///
    /// https://zetok.github.io/tox-spec/#tcp-relays-0x0a
    TcpRelays =  0x0a,
    /// Section for a list of path nodes for onion routing.
    ///
    /// https://zetok.github.io/tox-spec/#path-nodes-0x0b
    PathNodes =  0x0b,
    /// End of file.
    ///
    /// https://zetok.github.io/tox-spec/#eof-0xff
    EOF =        0xff,
}

/** E.g.

```
use self::tox::toxcore::binary_io::FromBytes;
use self::tox::toxcore::state_format::old::SectionKind;

assert_eq!(SectionKind::NospamKeys,
        SectionKind::from_bytes(&[1]).expect("Failed to unwrap NospamKeys!"));
assert_eq!(SectionKind::DHT,
        SectionKind::from_bytes(&[2]).expect("Failed to unwrap DHT!"));
assert_eq!(SectionKind::Friends,
        SectionKind::from_bytes(&[3]).expect("Failed to unwrap Friends!"));
assert_eq!(SectionKind::Name,
        SectionKind::from_bytes(&[4]).expect("Failed to unwrap Name!"));
assert_eq!(SectionKind::StatusMsg,
        SectionKind::from_bytes(&[5]).expect("Failed to unwrap StatusMsg!"));
assert_eq!(SectionKind::Status,
        SectionKind::from_bytes(&[6]).expect("Failed to unwrap Status!"));
assert_eq!(SectionKind::TcpRelays,
        SectionKind::from_bytes(&[10]).expect("Failed to unwrap TcpRelays!"));
assert_eq!(SectionKind::PathNodes,
        SectionKind::from_bytes(&[11]).expect("Failed to unwrap PathNodes!"));
assert_eq!(SectionKind::EOF,
        SectionKind::from_bytes(&[255]).expect("Failed to unwrap EOF!"));
```
*/
impl FromBytes<SectionKind> for SectionKind {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes[0] {
            0x01 => Some(SectionKind::NospamKeys),
            0x02 => Some(SectionKind::DHT),
            0x03 => Some(SectionKind::Friends),
            0x04 => Some(SectionKind::Name),
            0x05 => Some(SectionKind::StatusMsg),
            0x06 => Some(SectionKind::Status),
            0x0a => Some(SectionKind::TcpRelays),
            0x0b => Some(SectionKind::PathNodes),
            0xff => Some(SectionKind::EOF),
            _ => None,
        }
    }
}


/** NoSpam and Keys section of the old state format.

https://zetok.github.io/tox-spec/#nospam-and-keys-0x01
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NospamKeys {
    /// Own `NoSpam`.
    pub nospam: NoSpam,
    /// Own `PublicKey`.
    pub pk: PublicKey,
    /// Own `SecretKey`.
    pub sk: SecretKey,
}

/// Number of bytes of serialized [`NospamKeys`](./struct.NospamKeys.html).
pub const NOSPAMKEYSBYTES: usize = NOSPAMBYTES + PUBLICKEYBYTES + SECRETKEYBYTES;

/** Provided that there's at least [`NOSPAMKEYSBYTES`]
(./constant.NOSPAMKEYSBYTES.html) de-serializing will not fail.

E.g.

```
use self::tox::toxcore::binary_io::FromBytes;
use self::tox::toxcore::crypto_core::{
        PublicKey,
        PUBLICKEYBYTES,
        SecretKey,
        SECRETKEYBYTES,
};
use self::tox::toxcore::state_format::old::{NospamKeys, NOSPAMKEYSBYTES};
use self::tox::toxcore::toxid::{NoSpam, NOSPAMBYTES};

let bytes = [0; NOSPAMKEYSBYTES];

let result = NospamKeys {
    nospam: NoSpam([0; NOSPAMBYTES]),
    pk: PublicKey([0; PUBLICKEYBYTES]),
    sk: SecretKey([0; SECRETKEYBYTES]),
};

assert_eq!(None, NospamKeys::from_bytes(&bytes[..NOSPAMKEYSBYTES - 1]));
assert_eq!(result, NospamKeys::from_bytes(&bytes)
                    .expect("Failed to parse NospamKeys!"));
```
*/
impl FromBytes<NospamKeys> for NospamKeys {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < NOSPAMKEYSBYTES { return None }

        let nospam = NoSpam([bytes[0], bytes[1], bytes[2], bytes[3]]);

        let pk = match PublicKey::from_slice(
                    &bytes[NOSPAMBYTES..PUBLICKEYBYTES + NOSPAMBYTES]) {

            Some(pk) => pk,
            None => return None,
        };

        let sk = match SecretKey::from_slice(
                    &bytes[NOSPAMBYTES + PUBLICKEYBYTES..NOSPAMKEYSBYTES]) {

            Some(sk) => sk,
            None => return None,
        };

        Some(NospamKeys { nospam: nospam, pk: pk, sk: sk })
    }
}

/** E.g.

```
use self::tox::toxcore::binary_io::{FromBytes, ToBytes};
use self::tox::toxcore::crypto_core::*;
use self::tox::toxcore::state_format::old::{NospamKeys, NOSPAMKEYSBYTES};
use self::tox::toxcore::toxid::{NoSpam, NOSPAMBYTES};

{ // with `0` keys
    let nk = NospamKeys {
        nospam: NoSpam([0; NOSPAMBYTES]),
        pk: PublicKey([0; PUBLICKEYBYTES]),
        sk: SecretKey([0; SECRETKEYBYTES]),
    };
    assert_eq!(nk.to_bytes(), [0; NOSPAMKEYSBYTES].to_vec());
}

{ // with random
    let mut to_compare = Vec::with_capacity(NOSPAMKEYSBYTES);

    let mut nospam_bytes = [0; NOSPAMBYTES];
    randombytes_into(&mut nospam_bytes);
    to_compare.extend_from_slice(&nospam_bytes);

    let mut pk_bytes = [0; PUBLICKEYBYTES];
    randombytes_into(&mut pk_bytes);
    to_compare.extend_from_slice(&pk_bytes);

    let mut sk_bytes = [0; SECRETKEYBYTES];
    randombytes_into(&mut sk_bytes);
    to_compare.extend_from_slice(&sk_bytes);

    let nk = NospamKeys {
        nospam: NoSpam(nospam_bytes),
        pk: PublicKey(pk_bytes),
        sk: SecretKey(sk_bytes),
    };

    assert_eq!(to_compare, nk.to_bytes());
}

{ // with de-serialized
    let (pk, sk) = gen_keypair();
    let nk = NospamKeys {
        nospam: NoSpam::new(),
        pk: pk,
        sk: sk,
    };

    assert_eq!(nk, NospamKeys::from_bytes(&nk.to_bytes()).unwrap());
}
```
*/
impl ToBytes for NospamKeys {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(NOSPAMKEYSBYTES);
        result.extend_from_slice(&*self.nospam);
        let PublicKey(ref pk) = self.pk;
        result.extend_from_slice(pk);
        let SecretKey(ref sk) = self.sk;
        result.extend_from_slice(sk);
        result
    }
}


/** DHT section of the old state format.

https://zetok.github.io/tox-spec/#dht-0x02

Serialized format
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtState(pub Vec<PackedNode>);

/// Minimal number of bytes [`DhtState`](./struct.DhtState.html) has.
///
/// Assumes that at least all the magic numbers are present.
pub const DHT_STATE_MIN_SIZE: usize = 12;

/// Special, magical beginning of DHT section in LE.
const DHT_MAGICAL: u32 = 0x159000d;

/** Special DHT section type encoded in LE.

    https://zetok.github.io/tox-spec/#dht-sections
*/
const DHT_SECTION_TYPE: u16 = 0x04;

/** Yet another magical number in DHT section that needs a check.

https://zetok.github.io/tox-spec/#dht-sections
*/
const DHT_2ND_MAGICAL: u16 = 0x11ce;

/** An alias for de-serialization result of [`DhtState`]
    (./struct.DhtState.html).

### De-serialization docs:

If successful, returns `DhtState` and length of the section in bytes.

**Note that an empty list of nodes can be returned!**

If de-serialization failed, returns `None`.

Fails when:

* number of bytes is less than [`DHT_STATE_MIN_SIZE`]
  (./constant.DHT_STATE_MIN_SIZE.html)
* one of 3 magic numbers doesn't match
* encoded length of section + `DHT_STATE_MIN_SIZE` is bigger than all
  suppplied bytes

E.g. de-serialization with an empty list:

```
use self::tox::toxcore::binary_io::*;
use self::tox::toxcore::dht::*;
use self::tox::toxcore::state_format::old::*;

let serialized = vec![
        0x0d, 0x00, 0x59, 0x01,  // the first magic number
        0, 0, 0, 0,   // length of `PackedNode`s bytes
        0x04, 0,  // section magic number
        0xce, 0x11,  // another magic number
        // here would go `PackedNode`s, but since their length is `0`..
];

let result = (DhtState(vec![]), DHT_STATE_MIN_SIZE);

assert_eq!(result, ToDhtState::from_bytes(&serialized).unwrap());
```
*/

// TODO: ↓ rename
pub type ToDhtState = (DhtState, usize);

/** If successful, returns `DhtState` and length of the section in bytes.

**Note that an empty list of nodes can be returned!**

If de-serialization failed, returns `None`.

Fails when:

* number of bytes is less than [`DHT_STATE_MIN_SIZE`]
  (./constant.DHT_STATE_MIN_SIZE.html)
* one of 3 magic numbers doesn't match
* encoded length of section + `DHT_STATE_MIN_SIZE` is bigger than all
  suppplied bytes

E.g. de-serialization with an empty list:

```
use self::tox::toxcore::binary_io::*;
use self::tox::toxcore::dht::*;
use self::tox::toxcore::state_format::old::*;

let serialized = vec![
        0x0d, 0x00, 0x59, 0x01,  // the first magic number
        0, 0, 0, 0,   // length of `PackedNode`s bytes
        0x04, 0,  // section magic number
        0xce, 0x11,  // another magic number
        // here would go `PackedNode`s, but since their length is `0`..
];

let result = (DhtState(vec![]), DHT_STATE_MIN_SIZE);

assert_eq!(result, ToDhtState::from_bytes(&serialized).unwrap());
```
*/
impl FromBytes<ToDhtState> for ToDhtState {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if
            bytes.len() < DHT_STATE_MIN_SIZE ||
            // check whether beginning of the section matches DHT magic bytes
            &u32_to_array(DHT_MAGICAL.to_le()) != &bytes[..4] ||
            // check DHT section type
            &u16_to_array(DHT_SECTION_TYPE.to_le()) != &bytes[8..10] ||
            // check whether yet another magic number matches ;f
            &u16_to_array(DHT_2ND_MAGICAL.to_le()) != &bytes[10..12]
        { return None } // can I haz yet another magical number?

        // length of the whole section
        let section_len = {
            let nodes = array_to_u32(&[bytes[4], bytes[5], bytes[6], bytes[7]]);
            let whole_len = u32::from_le(nodes) as usize + DHT_STATE_MIN_SIZE;
            // check if it's bigger, since that would be the only thing that
            // could cause panic
            if whole_len > bytes.len() { return None }
            whole_len
        };

        PackedNode::from_bytes_multiple(&bytes[DHT_STATE_MIN_SIZE..section_len])
            .map_or(Some((DhtState(vec![]), DHT_STATE_MIN_SIZE)),
                    |pns| Some((DhtState(pns), section_len)))
    }
}
// TODO: test ↑
