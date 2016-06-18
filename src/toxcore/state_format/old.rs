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
impl FromBytes for SectionKind {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        if bytes.is_empty() {
            return parse_error!("Not enough bytes for SectionKind.")
        }

        let result = match bytes[0] {
            0x01 => SectionKind::NospamKeys,
            0x02 => SectionKind::DHT,
            0x03 => SectionKind::Friends,
            0x04 => SectionKind::Name,
            0x05 => SectionKind::StatusMsg,
            0x06 => SectionKind::Status,
            0x0a => SectionKind::TcpRelays,
            0x0b => SectionKind::PathNodes,
            0xff => SectionKind::EOF,
            _ => return parse_error!("Incorrect SectionKind: {:x}.", bytes[0]),
        };

        Ok(Parsed(result, &bytes[1..]))
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
impl FromBytes for NospamKeys {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        debug!(target: "NospamKeys", "Creating NospamKeys from bytes.");
        trace!(target: "NospamKeys", "Bytes: {:?}", bytes);

        let Parsed(nospam, bytes) = try!(NoSpam::parse_bytes(bytes));
        let Parsed(pk, bytes) = try!(PublicKey::parse_bytes(bytes));
        let Parsed(sk, bytes) = try!(SecretKey::parse_bytes(bytes));

        Ok(Parsed(NospamKeys { nospam: nospam, pk: pk, sk: sk }, bytes))
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
        result.extend_from_slice(&self.pk.0);
        result.extend_from_slice(&self.sk.0);
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

assert_eq!(DhtState(vec![]), DhtState::from_bytes(&serialized).unwrap());
```
*/
impl FromBytes for DhtState {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        if bytes.len() < DHT_STATE_MIN_SIZE ||
           // check whether beginning of the section matches DHT magic bytes
           &u32_to_array(DHT_MAGICAL.to_le()) != &bytes[..4] ||
           // check DHT section type
           &u16_to_array(DHT_SECTION_TYPE.to_le()) != &bytes[8..10] ||
           // check whether yet another magic number matches ;f
           &u16_to_array(DHT_2ND_MAGICAL.to_le()) != &bytes[10..12] {
            return parse_error!("Incorect DhtState.")
        } // can I haz yet another magical number?

        // length of the whole section
        let section_len = {
            let nodes = array_to_u32(&[bytes[4], bytes[5], bytes[6], bytes[7]]);
            let whole_len = u32::from_le(nodes) as usize + DHT_STATE_MIN_SIZE;
            // check if it's bigger, since that would be the only thing that
            // could cause panic
            if whole_len > bytes.len() {
                return parse_error!("Not enough bytes for DhtState.")
            }
            whole_len
        };

        let nodes_bytes = &bytes[DHT_STATE_MIN_SIZE..section_len];
        let Parsed(pns, _) = try!(PackedNode::parse_bytes_multiple(nodes_bytes));
        Ok(Parsed(DhtState(pns), &bytes[section_len..]))
    }
}

/** E.g. serialization of an empty list:

```
use self::tox::toxcore::binary_io::*;
use self::tox::toxcore::dht::*;
use self::tox::toxcore::state_format::old::*;

let result = vec![
        0x0d, 0x00, 0x59, 0x01,  // the first magic number
        0, 0, 0, 0,   // length of `PackedNode`s bytes
        0x04, 0,  // section magic number
        0xce, 0x11,  // another magic number
        // here would go `PackedNode`s, but since their length is `0`..
];

assert_eq!(result, DhtState(vec![]).to_bytes());
```
*/
impl ToBytes for DhtState {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(DHT_STATE_MIN_SIZE);
        result.extend_from_slice(&u32_to_array(DHT_MAGICAL.to_le()));

        let pn_bytes = {
            let mut bytes = Vec::with_capacity(
                                    PACKED_NODE_IPV6_SIZE * self.0.len());
            for pn in &self.0 {
                bytes.extend_from_slice(&pn.to_bytes());
            }
            bytes
        };

        // add length of serialized `PackedNode`s
        result.extend_from_slice(&u32_to_array((pn_bytes.len() as u32).to_le()));

        // section magic number
        result.extend_from_slice(&u16_to_array(DHT_SECTION_TYPE.to_le()));

        // 2nd magic number
        result.extend_from_slice(&u16_to_array(DHT_2ND_MAGICAL.to_le()));

        // and `PackedNode`s
        result.extend_from_slice(&pn_bytes);
        result
    }
}


/** Friend state status. Used by [`FriendState`](./struct.FriendState.html).

https://zetok.github.io/tox-spec/#friends-0x03

```
use self::tox::toxcore::state_format::old::FriendStatus;

assert_eq!(0u8, FriendStatus::NotFriend as u8);
assert_eq!(1u8, FriendStatus::Added     as u8);
assert_eq!(2u8, FriendStatus::FrSent    as u8);
assert_eq!(3u8, FriendStatus::Confirmed as u8);
assert_eq!(4u8, FriendStatus::Online    as u8);
```
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FriendStatus {
    /// Not a friend. (When this can happen and what does it entail?)
    NotFriend   = 0,
    /// Friend was added.
    Added       = 1,
    /// Friend request was sent to the friend.
    FrSent      = 2,
    /// Friend confirmed.
    /// (Something like toxcore knowing that friend accepted FR?)
    Confirmed   = 3,
    /// Friend has come online.
    Online      = 4,
}

/** E.g.

```
use self::tox::toxcore::binary_io::*;
use self::tox::toxcore::state_format::old::*;

{ // ::NotFriend
    let bytes = [FriendStatus::NotFriend as u8];
    assert_eq!(FriendStatus::NotFriend,
        FriendStatus::from_bytes(&bytes)
            .expect("Failed to de-serialize FriendStatus::NotFriend!"));
}

{ // ::Added
    let bytes = [FriendStatus::Added as u8];
    assert_eq!(FriendStatus::Added,
        FriendStatus::from_bytes(&bytes)
            .expect("Failed to de-serialize FriendStatus::Added!"));
}

{ // ::FrSent
    let bytes = [FriendStatus::FrSent as u8];
    assert_eq!(FriendStatus::FrSent,
        FriendStatus::from_bytes(&bytes)
            .expect("Failed to de-serialize FriendStatus::FrSent!"));
}

{ // ::Confirmed
    let bytes = [FriendStatus::Confirmed as u8];
    assert_eq!(FriendStatus::Confirmed,
        FriendStatus::from_bytes(&bytes)
            .expect("Failed to de-serialize FriendStatus::Confirmed!"));
}

{ // ::Online
    let bytes = [FriendStatus::Online as u8];
    assert_eq!(FriendStatus::Online,
        FriendStatus::from_bytes(&bytes)
            .expect("Failed to de-serialize FriendStatus::Online!"));
}

// empty
assert_eq!(None, FriendStatus::from_bytes(&[]));

// wrong
for i in 5..256 {
    let bytes = [i as u8];
    assert_eq!(None, FriendStatus::from_bytes(&bytes));
}
```
*/
impl FromBytes for FriendStatus {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        if bytes.is_empty() {
            return parse_error!("Not enough bytes for FriendStatus.")
        }

        let result = match bytes[0] {
            0 => FriendStatus::NotFriend,
            1 => FriendStatus::Added,
            2 => FriendStatus::FrSent,
            3 => FriendStatus::Confirmed,
            4 => FriendStatus::Online,
            _ => return parse_error!("Unknown FriendStatus: {}.", bytes[0]),
        };

        Ok(Parsed(result, &bytes[1..]))
    }
}


/** User status. Used for both own & friend statuses.

https://zetok.github.io/tox-spec/#userstatus

*/
// FIXME: *move somewhere else* (messenger?)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserStatus {
    /// User is `Online`.
    Online = 0,
    /// User is `Away`.
    Away   = 1,
    /// User is `Busy`.
    Busy   = 2,
}

/** E.g.

```
use self::tox::toxcore::binary_io::*;
use self::tox::toxcore::state_format::old::UserStatus;

{ // ::Online
    let bytes = [UserStatus::Online as u8];
    assert_eq!(UserStatus::Online, UserStatus::from_bytes(&bytes)
                .expect("Failed to de-serialize UserStatus::Online!"));
}

{ // ::Away
    let bytes = [UserStatus::Away as u8];
    assert_eq!(UserStatus::Away, UserStatus::from_bytes(&bytes)
                .expect("Failed to de-serialize UserStatus::Away!"));
}

{ // ::Busy
    let bytes = [UserStatus::Busy as u8];
    assert_eq!(UserStatus::Busy, UserStatus::from_bytes(&bytes)
                .expect("Failed to de-serialize UserStatus::Busy!"));
}

// empty
assert_eq!(None, UserStatus::from_bytes(&[]));

// invalid
for i in 3..256 {
    let bytes = [i as u8];
    assert_eq!(None, UserStatus::from_bytes(&bytes));
}
```
*/
impl FromBytes for UserStatus {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        if bytes.is_empty() {
            return parse_error!("Not enough bytes for UserStatus.")
        }

        let result = match bytes[0] {
            0 => UserStatus::Online,
            1 => UserStatus::Away,
            2 => UserStatus::Busy,
            _ => return parse_error!("Unknown UserStatus: {}.", bytes[0])
        };

        Ok(Parsed(result, &bytes[1..]))
    }
}

/** Friend state format for a single friend, compatible with what C toxcore
does with on `GCC x86{,_x64}` platform.

*feel free to add compatibility to what broken C toxcore does on other
platforms*

https://zetok.github.io/tox-spec/#friends-0x03
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriendState {
    status: FriendStatus,
    pk: PublicKey,
    /// Friend request message that is being sent to friend.
    fr_msg: String,
    /// Friend's name.
    name: String,
    status_msg: String,
    user_status: UserStatus,
    nospam: NoSpam,
    /// Time when friend was last seen.
    last_seen: u64,
}

/// Number of bytes of serialized [`FriendState`](./struct.FriendState.html).
pub const FRIENDSTATEBYTES: usize = 1      // "Status"
                                  + PUBLICKEYBYTES
                                  + 1024   // FR message; TODO: change to const
                                  + 2      // actual size of FR message
                                  + 128    // Name; TODO: change to const
                                  + 2      // actual size of Name
                                  + 1007   // Status msg; TODO: change to const
                                  + 2      // actual size of status message
                                  + 1      // user status
                                  + 3      // padding
                                  + NOSPAMBYTES      // only used for sending FR
                                  + 8;     // last time seen

impl FromBytes for FriendState {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        if bytes.len() < FRIENDSTATEBYTES {
            return parse_error!("Not enough bytes for FriendState.")
        }

        let Parsed(status, bytes) = try!(FriendStatus::parse_bytes(bytes));

        let Parsed(pk, bytes) = try!(PublicKey::parse_bytes(bytes));

        // parse string out of bytes
        // supply length
        fn parse_string(bytes: &[u8], len: usize) -> ParseResult<String> {
            let str_len = u16::from_be(array_to_u16(
                        &[bytes[len], bytes[len+1]])) as usize;
            match String::from_utf8(bytes[..str_len].to_vec()) {
                Ok(str) => Ok(Parsed(str, &bytes[len+2..])),
                Err(err) => parse_error!("Can't parse string from bytes: '{:?}'. \
                                         Original error: {:?}.",
                                         &bytes[..len+2], err)
            }
        };

        const FR_MSG_LEN: usize = 1024;
        let Parsed(fr_msg, bytes) = try!(parse_string(bytes, FR_MSG_LEN));

        const NAME_LEN: usize = 128;
        let Parsed(name, bytes) = try!(parse_string(bytes, NAME_LEN));

        const STATUS_MSG_LEN: usize = 1007;
        let Parsed(status_msg, bytes) = try!(parse_string(bytes, STATUS_MSG_LEN));

        let Parsed(user_status, bytes) = try!(UserStatus::parse_bytes(bytes));

        let bytes = &bytes[3..]; // padding
        let Parsed(nospam, bytes) = try!(NoSpam::parse_bytes(&bytes));

        let seen = u64::from_le(array_to_u64(&[
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7]]));

        let bytes = &bytes[8..];

        Ok(Parsed(FriendState {
            status: status,
            pk: pk,
            fr_msg: fr_msg,
            name: name,
            status_msg: status_msg,
            user_status: user_status,
            nospam: nospam,
            last_seen: seen,
        }, bytes))
    }
}
// TODO: write tests ↑
