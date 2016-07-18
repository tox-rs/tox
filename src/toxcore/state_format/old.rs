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


#[cfg(test)]
use ::toxcore_tests::quickcheck::{Arbitrary, Gen, quickcheck};



/// Length in bytes of request message.
// FIXME: move somewhere else
// TODO: rename
const REQUEST_MSG_LEN: usize = 1024;

/// Length in bytes of name. Will be moved elsewhere.
// FIXME: move somewhere else
pub const NAME_LEN: usize = 128;

/// Length in bytes of friend's status message.
// FIXME: move somewhere else
const STATUS_MSG_LEN: usize = 1007;



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

{ // empty
    assert_eq!(None, FriendStatus::from_bytes(&[]));
    let debug = format!("{:?}", FriendStatus::parse_bytes(&[]).unwrap_err());
    let err_msg = "Not enough bytes for FriendStatus.";
    assert!(debug.contains(err_msg));
}

// wrong
for i in 5..256 {
    let bytes = [i as u8];
    assert_eq!(None, FriendStatus::from_bytes(&bytes));
    let debug = format!("{:?}", FriendStatus::parse_bytes(&bytes).unwrap_err());
    let err_msg = format!("Unknown FriendStatus: {}", i);
    assert!(debug.contains(&err_msg));
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

{ // empty
    assert_eq!(None, UserStatus::from_bytes(&[]));
    let debug = format!("{:?}", UserStatus::parse_bytes(&[]).unwrap_err());
    let err_msg = "Not enough bytes for UserStatus.";
    assert!(debug.contains(err_msg));
}

// invalid
for i in 3..256 {
    let bytes = [i as u8];
    assert_eq!(None, UserStatus::from_bytes(&bytes));
    let debug = format!("{:?}", UserStatus::parse_bytes(&bytes).unwrap_err());
    let err_msg = format!("Unknown UserStatus: {}.", i);
    assert!(debug.contains(&err_msg));
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

Data that is supposed to be strings (friend request message, friend name,
friend status message) might, or might not even be a valid UTF-8. **Anything
using that data should validate whether it's actually correct UTF-8!**

*feel free to add compatibility to what broken C toxcore does on other
platforms*

https://zetok.github.io/tox-spec/#friends-0x03
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriendState {
    status: FriendStatus,
    pk: PublicKey,
    /// Friend request message that is being sent to friend.
    fr_msg: Vec<u8>,
    /// Friend's name.
    name: Name,
    status_msg: Vec<u8>,
    user_status: UserStatus,
    nospam: NoSpam,
    /// Time when friend was last seen.
    last_seen: u64,
}

/// Number of bytes of serialized [`FriendState`](./struct.FriendState.html).
pub const FRIENDSTATEBYTES: usize = 1      // "Status"
                                  + PUBLICKEYBYTES
/* Friend request message      */ + REQUEST_MSG_LEN
/* actual size of FR message   */ + 2
/* Name;                       */ + NAME_LEN
/* actual size of Name         */ + 2
/* Status msg;                 */ + STATUS_MSG_LEN
/* actual size of status msg   */ + 2
/* UserStatus                  */ + 1
/* padding                     */ + 3
/* only used for sending FR    */ + NOSPAMBYTES
/* last time seen              */ + 8;

impl FromBytes for FriendState {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        if bytes.len() < FRIENDSTATEBYTES {
            return parse_error!("Not enough bytes for FriendState.")
        }

        let Parsed(status, bytes) = try!(FriendStatus::parse_bytes(bytes));

        let Parsed(pk, bytes) = try!(PublicKey::parse_bytes(bytes));

        // supply length
        fn get_bytes(bytes: &[u8], len: usize) -> ParseResult<Vec<u8>> {
            let str_len = u16::from_be(array_to_u16(
                        &[bytes[len], bytes[len+1]])) as usize;
            if str_len > len {
                return parse_error!("Value demands {} bytes when it is \
                    supposed to take {}!", str_len, len)
            }

            Ok(Parsed(bytes[..str_len].to_vec(), &bytes[len+2..]))
        };

        let Parsed(fr_msg, bytes) = try!(get_bytes(bytes, REQUEST_MSG_LEN));

        let Parsed(name_bytes, bytes) = try!(get_bytes(bytes, NAME_LEN));
        let name = Name(name_bytes);

        let Parsed(status_msg, bytes) = try!(get_bytes(bytes, STATUS_MSG_LEN));

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


impl ToBytes for FriendState {
    fn to_bytes(&self) -> Vec<u8> {
        // extend vec with all contents of slice and padd with `0`s up to `len`
        // assume that Vec isn't too big for fr_msg
        fn ext_vec(vec: &mut Vec<u8>, slice: &[u8], len: usize) {
            vec.extend_from_slice(slice);
            for _ in 0..(len - slice.len()) {
                vec.push(0);
            }
        }

        let len_to_u16be = |len| u16_to_array((len as u16).to_be());

        let mut result = Vec::with_capacity(FRIENDSTATEBYTES);

        // friend status
        result.push(self.status as u8);

        // pk
        result.extend_from_slice(&self.pk.0);

        // friend request msg and its length
        ext_vec(&mut result, &self.fr_msg, REQUEST_MSG_LEN);
        result.extend_from_slice(&len_to_u16be(self.fr_msg.len()));

        // name and its length
        ext_vec(&mut result, &self.name.0, NAME_LEN);
        result.extend_from_slice(&len_to_u16be(self.name.0.len()));

        // status msg and its length
        ext_vec(&mut result, &self.status_msg, STATUS_MSG_LEN);
        result.extend_from_slice(&len_to_u16be(self.status_msg.len()));

        // UserStatus
        result.push(self.user_status as u8);

        // padding
        for _ in 0..3 {
            result.push(0);
        }

        // NoSpam
        result.extend_from_slice(&self.nospam.0);

        // last seen
        result.extend_from_slice(&u64_to_array(self.last_seen.to_le()));

        result
    }
}

#[cfg(test)]
impl Arbitrary for FriendState {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        // friend's PublicKey
        let mut pk_bytes = [0; PUBLICKEYBYTES];
        g.fill_bytes(&mut pk_bytes);
        let pk = PublicKey(pk_bytes);

        // friend message and its length
        let mut fr_msg = [0; REQUEST_MSG_LEN];
        let fr_msg_len = g.gen_range(0, REQUEST_MSG_LEN);
        g.fill_bytes(&mut fr_msg[..fr_msg_len]);
        let fr_msg = fr_msg[..fr_msg_len].to_vec();

        // friend name and its length
        let mut fname = [0; NAME_LEN];
        let fname_len = g.gen_range(0, NAME_LEN);
        g.fill_bytes(&mut fname[..fname_len]);
        let fname = Name(fname[..fname_len].to_vec());

        // status message and its length
        let mut status_msg = [0; STATUS_MSG_LEN];
        let status_msg_len = g.gen_range(0, STATUS_MSG_LEN);
        g.fill_bytes(&mut status_msg[..status_msg_len]);
        let status_msg = status_msg[..status_msg_len].to_vec();

        let mut ns_bytes = [0; NOSPAMBYTES];
        g.fill_bytes(&mut ns_bytes);
        let nospam = NoSpam(ns_bytes);

        FriendState {
            status: Arbitrary::arbitrary(g),
            pk: pk,
            fr_msg: fr_msg,
            name: fname,
            status_msg: status_msg,
            user_status: Arbitrary::arbitrary(g),
            nospam: nospam,
            last_seen: Arbitrary::arbitrary(g),
        }
    }
}

/** Own name, up to [`NAME_LEN`](./constant.NAME_LEN.html) bytes long.
*/
// TODO: move elsewhere from this module
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Name(pub Vec<u8>);

/** Produces up to [`NAME_LEN`](./constant.NAME_LEN.html) bytes long `Name`.
    Can't fail.
*/
impl FromBytes for Name {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        if bytes.len() < NAME_LEN {
            Ok(Parsed(Name(bytes.to_vec()), &bytes[bytes.len()..]))
        } else {
            Ok(Parsed(Name(bytes[..NAME_LEN].to_vec()), &bytes[..NAME_LEN]))
        }
    }
}



// FriendState::parse_bytes()

#[test]
// TODO: deduplicate the code
fn friend_state_parse_bytes_test() {
    // TODO: see if it won't be better off as a generic function, macro, or
    //       something, used by more tests
    fn assert_error(bytes: &[u8], error: &str) {
        let e = format!("{:?}", FriendState::parse_bytes(bytes).unwrap_err());
        assert!(e.contains(error));
    }

    // serialized and deserialized remain the same
    fn assert_success(bytes: &[u8], friend_state: &FriendState) {
        let Parsed(ref p, _) = FriendState::parse_bytes(bytes)
            .expect("Failed to unwrap FriendState!");
        assert_eq!(friend_state, p);
    }

    // actually don't allow, just supress useless warnings
    #[allow(overflowing_literals)]
    fn with_fs(fs: FriendState) {
        let fs_bytes = fs.to_bytes();
        assert_success(&fs_bytes, &fs);

        for b in 0..(FRIENDSTATEBYTES - 1) {
            assert_error(&fs_bytes[..b], "Not enough bytes for FriendState.");
        }

        { // FriendStatus
            let mut bytes = fs_bytes.clone();
            for b in 5..256 {
                bytes[0] = b as u8;
                assert_error(&bytes, &format!("Unknown FriendStatus: {}", b));
            }
        }

        const FR_MSG_LEN_POS: usize = 1 + PUBLICKEYBYTES + REQUEST_MSG_LEN;
        { // friend request message lenght check
            let mut bytes = fs_bytes.clone();
            for i in (REQUEST_MSG_LEN+1)..2500 { // too slow with bigger ranges
                let invalid = u16_to_array((i as u16).to_be());
                for pos in 0..2 {
                    bytes[FR_MSG_LEN_POS+pos] = invalid[pos];
                }
                assert_error(&bytes, &format!("Value demands {} bytes \
                    when it is supposed to take {}!", i, REQUEST_MSG_LEN));
            }
        }

        const NAME_LEN_POS: usize = FR_MSG_LEN_POS + NAME_LEN + 2;
        { // friend name lenght check
            let mut bytes = fs_bytes.clone();
            for i in (NAME_LEN+1)..2500 { // too slow with bigger ranges
                let invalid = u16_to_array((i as u16).to_be());
                for pos in 0..2 {
                    bytes[NAME_LEN_POS+pos] = invalid[pos];
                }
                assert_error(&bytes, &format!("Value demands {} bytes \
                    when it is supposed to take {}!", i, NAME_LEN));
            }
        }

        const STATUS_MSG_LEN_POS: usize = NAME_LEN_POS + STATUS_MSG_LEN + 2;
        { // friend name lenght check
            let mut bytes = fs_bytes.clone();
            for i in (STATUS_MSG_LEN+1)..2500 { // too slow with bigger ranges
                let invalid = u16_to_array((i as u16).to_be());
                for pos in 0..2 {
                    bytes[STATUS_MSG_LEN_POS+pos] = invalid[pos];
                }
                assert_error(&bytes, &format!("Value demands {} bytes \
                    when it is supposed to take {}!", i, STATUS_MSG_LEN));
            }
        }


        const USTATUS_POS: usize = STATUS_MSG_LEN_POS + 2;
        { // user status
            fn has_status(bytes: &[u8], status: UserStatus) {
                let Parsed(fs, _) = FriendState::parse_bytes(bytes).unwrap();
                assert_eq!(fs.user_status, status);
            }

            let mut bytes = fs_bytes.clone();

            for i in 0..256 {
                bytes[USTATUS_POS] = i;

                match i {
                    0 => has_status(&bytes, UserStatus::Online),
                    1 => has_status(&bytes, UserStatus::Away),
                    2 => has_status(&bytes, UserStatus::Busy),
                    n => assert_error(&bytes,
                            &format!("Unknown UserStatus: {}.", n)),
                }
            }
        }

        const PADDING_POS: usize = USTATUS_POS + 1;
        { // padding; should be always ignored when parsing
            let mut bytes = fs_bytes.clone();
            for n in 0..256 {
                for i in 0..256 {
                    for h in 0..256 {
                        bytes[PADDING_POS]   = n;
                        bytes[PADDING_POS+1] = i;
                        bytes[PADDING_POS+2] = h;
                        assert_success(&bytes, &fs);
                    }
                }
            }
        }

        // TODO: test for:
        //
        // nospam
        //
        // last time seen
    }
    quickcheck(with_fs as fn(FriendState));
}
