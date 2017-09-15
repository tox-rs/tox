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

//! Old **Tox State Format (TSF)**. *__Will be deprecated__ when something
//! better will become available.*

use std::default::Default;
use byteorder::{ByteOrder, BigEndian, LittleEndian, WriteBytesExt};

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::dht::*;
use toxcore::toxid::{NoSpam, NOSPAMBYTES};


#[cfg(test)]
use quickcheck::*;

// TODO: add logging where it's missing

/// Length in bytes of request message.
// FIXME: move somewhere else
// TODO: rename
const REQUEST_MSG_LEN: usize = 1024;


// TODO: improve docs

/** Sections of the old state format.

https://zetok.github.io/tox-spec/#sections
*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SectionKind {
    /** Section for [`NoSpam`](../../toxid/struct.NoSpam.html), public and
    secret keys.

    https://zetok.github.io/tox-spec/#nospam-and-keys-0x01
    */
    NospamKeys = 0x01,
    /** Section for DHT-related data – [`DhtState`](./struct.DhtState.html).

    https://zetok.github.io/tox-spec/#dht-0x02
    */
    // TODO: rename to DhtState
    DHT =        0x02,
    /** Section for friends data. Contains list of [`Friends`]
    (./struct.Friends.html).

    https://zetok.github.io/tox-spec/#friends-0x03
    */
    Friends =    0x03,
    /** Section for own [`Name`](./struct.Name.html).

    https://zetok.github.io/tox-spec/#name-0x04
    */
    Name =       0x04,
    /** Section for own [`StatusMsg`](./struct.StatusMsg.html).

    https://zetok.github.io/tox-spec/#status-message-0x05
    */
    StatusMsg =  0x05,
    /** Section for own [`UserStatus`](./enum.UserStatus.html).

    https://zetok.github.io/tox-spec/#status-0x06
    */
    // TODO: rename to UserStatus
    Status =     0x06,
    /** Section for a list of [`TcpRelays`](./struct.TcpRelays.html).

    https://zetok.github.io/tox-spec/#tcp-relays-0x0a
    */
    TcpRelays =  0x0a,
    /** Section for a list of [`PathNodes`](./struct.PathNodes.html) for onion
    routing.

    https://zetok.github.io/tox-spec/#path-nodes-0x0b
    */
    PathNodes =  0x0b,
    /// End of file. https://zetok.github.io/tox-spec/#eof-0xff
    EOF =        0xff,
}

impl FromBytes for SectionKind {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        if bytes.len() < 2 {
            return parse_error!("Not enough bytes for SectionKind.")
        }

        let num = LittleEndian::read_u16(bytes);
        let result = match num {
            0x01 => SectionKind::NospamKeys,
            0x02 => SectionKind::DHT,
            0x03 => SectionKind::Friends,
            0x04 => SectionKind::Name,
            0x05 => SectionKind::StatusMsg,
            0x06 => SectionKind::Status,
            0x0a => SectionKind::TcpRelays,
            0x0b => SectionKind::PathNodes,
            0xff => SectionKind::EOF,
            _ => return parse_error!("Incorrect SectionKind: {:x}.", num),
        };

        Ok(Parsed(result, &bytes[2..]))
    }
}

/** Serialization into bytes

```
use self::tox::toxcore::binary_io::ToBytes;
use self::tox::toxcore::state_format::old::SectionKind;

assert_eq!(vec![1u8, 0],   SectionKind::NospamKeys .to_bytes());
assert_eq!(vec![2u8, 0],   SectionKind::DHT        .to_bytes());
assert_eq!(vec![3u8, 0],   SectionKind::Friends    .to_bytes());
assert_eq!(vec![4u8, 0],   SectionKind::Name       .to_bytes());
assert_eq!(vec![5u8, 0],   SectionKind::StatusMsg  .to_bytes());
assert_eq!(vec![6u8, 0],   SectionKind::Status     .to_bytes());
assert_eq!(vec![10u8, 0],  SectionKind::TcpRelays  .to_bytes());
assert_eq!(vec![11u8, 0],  SectionKind::PathNodes  .to_bytes());
assert_eq!(vec![255u8, 0], SectionKind::EOF        .to_bytes());
```
*/
impl ToBytes for SectionKind {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(2);
        result.write_u16::<LittleEndian>(*self as u16)
            .expect("Failed to write SectionKind!");
        result
    }
}


/// Implement returning matching SectionKind for sections.
trait SectionKindMatch {
    /// Returns matching `SectionKind`.
    fn kind() -> SectionKind;
}

macro_rules! section_kind_for_section {
    ($($skind:ident, $sect:ident, $tname:ident),+) => ($(
        impl SectionKindMatch for $sect {
            fn kind() -> SectionKind { SectionKind::$skind }
        }

        #[test]
        fn $tname() {
            assert_eq!(SectionKind::$skind, $sect::kind());
        }
    )+)
}
section_kind_for_section!(
    NospamKeys, NospamKeys, nospam_keys_kind_test,
    DHT, DhtState, dht_state_kind_test,
    Friends, Friends, friends_kind_test,
    Name, Name, name_kind_test,
    StatusMsg, StatusMsg, status_msg_kind_test,
    Status, UserStatus, user_status_kind_test,
    TcpRelays, TcpRelays, tcp_relays_kind_test,
    PathNodes, PathNodes, path_nodes_kind_test,
    EOF, Eof, eof_kind_test
);


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


/// The `Default` implementation generates random `NospamKeys`.
impl Default for NospamKeys {
    fn default() -> Self {
        let nospam = NoSpam::default();
        let (pk, sk) = gen_keypair();
        NospamKeys {
            nospam: nospam,
            pk: pk,
            sk: sk
        }
    }
}

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
        result.extend_from_slice(&self.nospam.0);
        result.extend_from_slice(&self.pk.0);
        result.extend_from_slice(&self.sk.0);
        result
    }
}


/** DHT section of the old state format.

https://zetok.github.io/tox-spec/#dht-0x02

Default is empty, no Nodes.

```
# use std::default::Default;
# use tox::toxcore::state_format::old::DhtState;
# use tox::toxcore::dht::PackedNode;
assert_eq!(&[] as &[PackedNode], DhtState::default().0.as_slice());
```
*/
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DhtState(pub Vec<PackedNode>);

/// Minimal number of bytes [`DhtState`](./struct.DhtState.html) has.
///
/// Assumes that at least all the magic numbers are present.
pub const DHT_STATE_MIN_SIZE: usize = 12;

/// Special, magical beginning of DHT section in LE.
// TODO: change to &'static [u8]
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

> **Note:** An empty list of nodes can be returned!

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
           LittleEndian::read_u32(bytes) != DHT_MAGICAL ||
           // check DHT section type
           LittleEndian::read_u16(&bytes[8..10]) != DHT_SECTION_TYPE ||
           // check whether yet another magic number matches
           LittleEndian::read_u16(&bytes[10..12]) != DHT_2ND_MAGICAL {
            return parse_error!("Incorect DhtState.")
        } // can I haz yet another magical number?

        // length of the whole section
        let section_len = {
            let nodes = LittleEndian::read_u32(&bytes[4..]);
            let whole_len = nodes as usize + DHT_STATE_MIN_SIZE;
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
        result.write_u32::<LittleEndian>(DHT_MAGICAL)
            .expect("Failed to write DhtState DHT_MAGICAL!");;

        let pn_bytes = {
            let mut bytes = Vec::with_capacity(
                                    PACKED_NODE_IPV6_SIZE * self.0.len());
            for pn in &self.0 {
                bytes.extend_from_slice(&pn.to_bytes());
            }
            bytes
        };

        // add length of serialized `PackedNode`s
        result.write_u32::<LittleEndian>(pn_bytes.len() as u32)
            .expect("Failed to write DhtState PackedNode length!");

        // section magic number
        result.write_u16::<LittleEndian>(DHT_SECTION_TYPE)
            .expect("Failed to write DhtState DHT_SECTION_TYPE!");

        // 2nd magic number
        result.write_u16::<LittleEndian>(DHT_2ND_MAGICAL)
            .expect("Failed to write DhtState DHT_2ND_MAGICAL!");

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

```
# use self::tox::toxcore::state_format::old::UserStatus;
assert_eq!(UserStatus::Online, UserStatus::default());
```
*/
// FIXME: *move somewhere else* (messenger?)
// TODO: rename to `Status` ?
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserStatus {
    /// User is `Online`.
    Online = 0,
    /// User is `Away`.
    Away   = 1,
    /// User is `Busy`.
    Busy   = 2,
}

/// Returns `UserStatus::Online`.
impl Default for UserStatus {
    fn default() -> Self {
        UserStatus::Online
    }
}

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

impl ToBytes for UserStatus {
    fn to_bytes(&self) -> Vec<u8> {
        vec![*self as u8]
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
    status_msg: StatusMsg,
    user_status: UserStatus,
    nospam: NoSpam,
    /// Time when friend was last seen online.
    last_seen: u64,
}

impl FriendState {
    /** Add a new friend via `PublicKey`.

    State assumes that friend request was sent and accepted.
    */
    pub fn new_from_pk(pk: &PublicKey) -> Self {
        FriendState {
            status: FriendStatus::Added,
            pk: *pk,
            fr_msg: Vec::new(),
            name: Name::default(),
            status_msg: StatusMsg::default(),
            user_status: UserStatus::default(),
            nospam: NoSpam([0; NOSPAMBYTES]),
            last_seen: 0,
        }
    }
}


/// Number of bytes of serialized [`FriendState`](./struct.FriendState.html).
pub const FRIENDSTATEBYTES: usize = 1      // "Status"
                                  + PUBLICKEYBYTES
/* Friend request message      */ + REQUEST_MSG_LEN
/* padding1                    */ + 1
/* actual size of FR message   */ + 2
/* Name;                       */ + NAME_LEN
/* actual size of Name         */ + 2
/* Status msg;                 */ + STATUS_MSG_LEN
/* padding2                    */ + 1
/* actual size of status msg   */ + 2
/* UserStatus                  */ + 1
/* padding3                    */ + 3
/* only used for sending FR    */ + NOSPAMBYTES
/* last time seen              */ + 8;

impl FromBytes for FriendState {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        if bytes.len() < FRIENDSTATEBYTES {
            return parse_error!("Not enough bytes for FriendState.")
        }

        let Parsed(status, bytes) = try!(FriendStatus::parse_bytes(bytes));

        let Parsed(pk, bytes) = try!(PublicKey::parse_bytes(bytes));

        // supply length and number of bytes that need to be padded
        // if no padding needed, supply `0`
        // TODO: refactor?
        fn get_bytes(bytes: &[u8], len: usize, pad: usize)
            -> ParseResult<Vec<u8>>
        {
            let str_len = BigEndian::read_u16(&bytes[len+pad..len+pad+2]) as usize;
            if str_len > len {
                return parse_error!("Value demands {} bytes when it is \
                    supposed to take {}!", str_len, len)
            }

            Ok(Parsed(bytes[..str_len].to_vec(), &bytes[len+pad+2..]))
        };

        let Parsed(fr_msg, bytes) = try!(get_bytes(bytes, REQUEST_MSG_LEN, 1));

        // TODO: refactor?
        let Parsed(name_bytes, bytes) = try!(get_bytes(bytes, NAME_LEN, 0));
        let name = Name(name_bytes);

        // TODO: refactor?
        let Parsed(status_msg_bytes, bytes) = try!(
            get_bytes(bytes, STATUS_MSG_LEN, 1)
        );
        let status_msg = StatusMsg(status_msg_bytes);

        let Parsed(user_status, bytes) = try!(UserStatus::parse_bytes(bytes));

        let bytes = &bytes[3..]; // padding
        let Parsed(nospam, bytes) = try!(NoSpam::parse_bytes(&bytes));

        let seen = LittleEndian::read_u64(bytes);

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
        // extend vec with all contents of slice and pad with `0`s up to `len`
        // assume that Vec isn't too big for fr_msg
        fn ext_vec(vec: &mut Vec<u8>, slice: &[u8], len: usize) {
            let mut to_add = slice.to_vec();
            append_zeros(&mut to_add, len);
            vec.append(&mut to_add);
        }

        let mut result = Vec::with_capacity(FRIENDSTATEBYTES);

        // friend status
        result.push(self.status as u8);

        // pk
        result.extend_from_slice(&self.pk.0);

        // friend request msg..
        ext_vec(&mut result, &self.fr_msg, REQUEST_MSG_LEN);
        // padding
        result.push(0);
        // .. and its length
        result.write_u16::<BigEndian>(self.fr_msg.len() as u16)
            .expect("Failed to write FriendState message length!");

        // name and its length
        ext_vec(&mut result, &self.name.0, NAME_LEN);
        result.write_u16::<BigEndian>(self.name.0.len() as u16)
            .expect("Failed to write FriendState name length!");

        // status msg ..
        ext_vec(&mut result, &self.status_msg.0, STATUS_MSG_LEN);
        // padding
        result.push(0);
        // .. and its length
        result.write_u16::<BigEndian>(self.status_msg.0.len() as u16)
            .expect("Failed to write FriendState padding length!");

        // UserStatus
        result.push(self.user_status as u8);

        // padding
        append_zeros(&mut result, FRIENDSTATEBYTES - 12);

        // NoSpam
        result.extend_from_slice(&self.nospam.0);

        // last seen
        result.write_u64::<LittleEndian>(self.last_seen)
            .expect("Failed to write FriendState last seen!");

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
        let status_msg = StatusMsg(status_msg[..status_msg_len].to_vec());

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


// TODO: replace every `Vec<FriendState>` with `Friends`
/** Wrapper struct for `Vec<FriendState>` to ease working with friend lists.
*/
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Friends(pub Vec<FriendState>);

impl Friends {

    /// `true` if there is a friend with given `PublicKey`, `false` otherwise.
    pub fn is_friend(&self, pk: &PublicKey) -> bool {
        self.0.iter().any(|fs| fs.pk == *pk)
    }

    /** Add [`FriendState`](./struct.FriendState.html) to the list of friends.

    If the friend was already in `Friends`, `false` is returned, `true`
    otherwise.
    */
    pub fn add_friend(&mut self, fs: FriendState) -> bool {
        if self.is_friend(&fs.pk) {
            return false
        }

        self.0.push(fs);
        true
    }
}

impl FromBytes for Friends {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        FriendState::parse_bytes_multiple(bytes)
            .map(|Parsed(fs, b)| Parsed(Friends(fs), b))
    }
}

impl ToBytes for Friends {
    fn to_bytes(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(FRIENDSTATEBYTES * self.0.len());
        for f in &self.0 {
            res.extend_from_slice(&f.to_bytes());
        }
        res
    }
}

#[cfg(test)]
impl Arbitrary for Friends {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        Friends(Arbitrary::arbitrary(g))
    }
}


macro_rules! impl_to_bytes_for_bytes_struct {
    ($name:ty, $tname:ident) => (
        impl ToBytes for $name {
            fn to_bytes(&self) -> Vec<u8> {
                self.0.clone()
            }
        }

        #[test]
        fn $tname() {
            fn test_fn(s: $name) {
                assert_eq!(s.0, s.to_bytes());
            }
            quickcheck(test_fn as fn($name));
        }
    )
}

// TODO: refactor `Name` and `StatusMsg` to implementation via via macro,
//       in a similar way to how sodiumoxide does implementation via macros

/** Own name, up to [`NAME_LEN`](./constant.NAME_LEN.html) bytes long.
*/
// TODO: move elsewhere from this module
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Name(pub Vec<u8>);

/// Length in bytes of name. ***Will be moved elsewhere.***
// FIXME: move somewhere else
pub const NAME_LEN: usize = 128;

impl Name {
    /** Create new `Name` from bytes in a slice. If there are more bytes than
    [`NAME_LEN`](./constant.NAME_LEN.html), use only `NAME_LEN` bytes.

    E.g.:

    ```
    use self::tox::toxcore::state_format::old::*;

    for n in 0..(NAME_LEN + 1) {
        let bytes = vec![0; n];
        assert_eq!(bytes, Name::new(&bytes).0);
    }

    for n in (NAME_LEN + 1)..(NAME_LEN + 20) {
        let bytes = vec![0; n];
        assert_eq!(&bytes[..NAME_LEN], Name::new(&bytes).0.as_slice());
    }
    ```
    */
    pub fn new(bytes: &[u8]) -> Self {
        if bytes.len() < NAME_LEN {
            Name(bytes.to_vec())
        } else {
            Name(bytes[..NAME_LEN].to_vec())
        }
    }
}

/** Produces up to [`NAME_LEN`](./constant.NAME_LEN.html) bytes long `Name`.
    Can't fail.
*/
impl FromBytes for Name {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        if bytes.len() < NAME_LEN {
            Ok(Parsed(Name::new(bytes), &bytes[bytes.len()..]))
        } else {
            Ok(Parsed(Name::new(bytes), &bytes[NAME_LEN..]))
        }
    }
}

impl_to_bytes_for_bytes_struct!(Name, name_to_bytes_test);


/** Status message, up to [`STATUS_MSG_LEN`](./constant.STATUS_MSG_LEN.html)
bytes.

> ***Note: will be moved (and renamed?)***.
*/
// TODO: rename(?) & move from this module
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StatusMsg(pub Vec<u8>);

/// Length in bytes of friend's status message.
// FIXME: move somewhere else
pub const STATUS_MSG_LEN: usize = 1007;

impl StatusMsg {
    /** Create new `StatusMsg` from bytes in a slice. If there are more bytes
    than [`STATUS_MSG_LEN`](./constant.STATUS_MSG_LEN.html), use only
    `STATUS_MSG_LEN` bytes.

    E.g.:

    ```
    use self::tox::toxcore::state_format::old::*;

    for n in 0..(STATUS_MSG_LEN + 1) {
        let bytes = vec![0; n];
        assert_eq!(bytes, StatusMsg::new(&bytes).0);
    }

    for n in (STATUS_MSG_LEN + 1)..(STATUS_MSG_LEN + 20) {
        let bytes = vec![0; n];
        assert_eq!(&bytes[..STATUS_MSG_LEN],
                StatusMsg::new(&bytes).0.as_slice());
    }
    ```
    */
    pub fn new(bytes: &[u8]) -> Self {
        if bytes.len() < STATUS_MSG_LEN {
            StatusMsg(bytes.to_vec())
        } else {
            StatusMsg(bytes[..STATUS_MSG_LEN].to_vec())
        }
    }
}

/** Produces up to [`STATUS_MSG_LEN`](./constant.STATUS_MSG_LEN.html) bytes
long `StatusMsg`. Can't fail.
*/
impl FromBytes for StatusMsg {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        if bytes.len() < STATUS_MSG_LEN {
            Ok(Parsed(StatusMsg::new(bytes), &bytes[bytes.len()..]))
        } else {
            Ok(Parsed(StatusMsg::new(bytes), &bytes[STATUS_MSG_LEN..]))
        }
    }
}

impl_to_bytes_for_bytes_struct!(StatusMsg, status_msg_to_bytes_test);

macro_rules! nodes_list {
    ($($name:ident, $tname:ident),+) => ($(
        /// Contains list in `PackedNode` format.
        #[derive(Clone, Debug, Default, Eq, PartialEq)]
        pub struct $name(pub Vec<PackedNode>);

        impl FromBytes for $name {
            fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
                let Parsed(value, rest) =
                    try!(PackedNode::parse_bytes_multiple(&bytes));
                Ok(Parsed($name(value), rest))
            }
        }

        impl ToBytes for $name {
            fn to_bytes(&self) -> Vec<u8> {
                let mut result = Vec::with_capacity(
                            PACKED_NODE_IPV6_SIZE * self.0.len());
                for node in &self.0 {
                    result.append(&mut node.to_bytes());
                }
                result
            }
        }

        #[cfg(test)]
        impl_arb_for_pn!($name);

        #[cfg(test)]
        #[test]
        // TODO: test also for failures? should be covered by other test, but..
        fn $tname() {
            fn with_pns(pns: Vec<PackedNode>) {
                let mut bytes = Vec::new();
                for pn in &pns {
                    bytes.append(&mut pn.to_bytes());
                }
                {
                    let Parsed(p, r_bytes) = $name::parse_bytes(&bytes)
                        .expect("Parsing can't fail.");

                    assert_eq!(p.0, pns);
                    assert_eq!(&[] as &[u8], r_bytes);
                }

                assert_eq!($name(pns).to_bytes(), bytes);
            }
            quickcheck(with_pns as fn(Vec<PackedNode>));

            // Default impl test
            assert_eq!(&[] as &[PackedNode], $name::default().0.as_slice());
        }
    )+)
}

nodes_list!(TcpRelays, tcp_relays_test,
            PathNodes, path_nodes_test);


/// End of the state format data.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Eof;

impl ToBytes for Eof {
    fn to_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}

#[cfg(test)]
impl Arbitrary for Eof {
    fn arbitrary<G: Gen>(_g: &mut G) -> Self { Eof }
}

/// Data for `Section`. Might, or might not contain valid data.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SectionData {
    kind: SectionKind,
    data: Vec<u8>,
}

/// Minimal length in bytes of an empty section. Any section that is not empty
/// should be bigger.
const SECTION_MIN_LEN: usize = 8;

/// According to https://zetok.github.io/tox-spec/#sections
const SECTION_MAGIC: &'static [u8; 2] = &[206, 1];

impl SectionData {

    /** Try to parse `SectionData`'s bytes into [`Section`]
    (./enum.Section.html).

    Fails if `SectionData` doesn't contain valid data.
    */
    // TODO: test failures?
    fn as_section(&self) -> Option<Section> {
        match self.kind {
            SectionKind::NospamKeys => NospamKeys::from_bytes(&self.data)
                .map(Section::NospamKeys),
            SectionKind::DHT => DhtState::from_bytes(&self.data)
                .map(Section::DHT),
            SectionKind::Friends => Friends::from_bytes(&self.data)
                .map(Section::Friends),
            SectionKind::Name => Name::from_bytes(&self.data)
                .map(Section::Name),
            SectionKind::StatusMsg => StatusMsg::from_bytes(&self.data)
                .map(Section::StatusMsg),
            SectionKind::Status => UserStatus::from_bytes(&self.data)
                .map(Section::Status),
            SectionKind::TcpRelays => TcpRelays::from_bytes(&self.data)
                .map(Section::TcpRelays),
            SectionKind::PathNodes => PathNodes::from_bytes(&self.data)
                .map(Section::PathNodes),
            SectionKind::EOF => Some(Section::EOF),
        }
    }

    /** Try to parse `SectionData`'s bytes into multiple [`Section`s]
    (./enum.Section.html).

    Fails if `SectionData` doesn't contain valid data.

    Can return empty `Vec<_>`.
    */
    // TODO: move under `Section` ?
    fn into_sect_mult(s: &[SectionData]) -> Vec<Section> {
        // TODO: don't return an empty Vec ?
        s.iter()
            .map(|sd| sd.as_section())
            .filter(|s| s.is_some())
            .map(|s| s.expect("IS Some(_)"))
            .collect()
    }
}


impl FromBytes for SectionData {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        if bytes.len() < SECTION_MIN_LEN {
            return parse_error!("Parsing failed: Not enough bytes for \
            SectionData!")
        }

        let data_len = {
            let num = LittleEndian::read_u32(bytes) as usize;
            if num > (bytes.len() - SECTION_MIN_LEN) {
                return parse_error!("Parsing failed: there are not enough \
                bytes in section to parse!")
            }
            num
        };
        let left = &bytes[4..SECTION_MIN_LEN+data_len];

        let Parsed(kind, left) = try!(SectionKind::parse_bytes(left));

        if SECTION_MAGIC != &left[..2] {
            return parse_error!("Parsing failed: SECTION_MAGIC doesn't match!")
        }
        let left = &left[2..];

        Ok(Parsed(
            SectionData {
                kind: kind,
                data: left.to_vec()
            },
            &bytes[SECTION_MIN_LEN + left.len()..]
        ))
    }
}


#[cfg(test)]
impl Arbitrary for SectionData {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let kind: SectionKind = Arbitrary::arbitrary(g);
        let data = match kind {
            SectionKind::NospamKeys => NospamKeys::arbitrary(g).to_bytes(),
            SectionKind::DHT => DhtState::arbitrary(g).to_bytes(),
            SectionKind::Friends => Friends::arbitrary(g).to_bytes(),
            SectionKind::Name => Name::arbitrary(g).0,
            SectionKind::StatusMsg => StatusMsg::arbitrary(g).0,
            SectionKind::Status => vec![UserStatus::arbitrary(g) as u8],
            SectionKind::TcpRelays => TcpRelays::arbitrary(g).to_bytes(),
            SectionKind::PathNodes => PathNodes::arbitrary(g).to_bytes(),
            SectionKind::EOF => vec![],
        };
        SectionData { kind: kind, data: data }
    }
}


/** Sections of state format.

https://zetok.github.io/tox-spec/#sections
*/
#[derive(Clone, Debug, Eq, PartialEq)]
// TODO: deduplicate with `SectionKind` ?
pub enum Section {
    /** Section for [`NoSpam`](../../toxid/struct.NoSpam.html), public and
    secret keys.

    https://zetok.github.io/tox-spec/#nospam-and-keys-0x01
    */
    NospamKeys(NospamKeys),
    /** Section for DHT-related data – [`DhtState`](./struct.DhtState.html).

    https://zetok.github.io/tox-spec/#dht-0x02
    */
    DHT(DhtState),
    /** Section for friends data. Contains list of [`Friends`]
    (./struct.Friends.html).

    https://zetok.github.io/tox-spec/#friends-0x03
    */
    Friends(Friends),
    /** Section for own [`StatusMsg`](./struct.StatusMsg.html).

    https://zetok.github.io/tox-spec/#status-message-0x05
    */
    Name(Name),
    /** Section for own [`StatusMsg`](./struct.StatusMsg.html).

    https://zetok.github.io/tox-spec/#status-message-0x05
    */
    StatusMsg(StatusMsg),
    /** Section for own [`UserStatus`](./enum.UserStatus.html).

    https://zetok.github.io/tox-spec/#status-0x06
    */
    Status(UserStatus),
    /** Section for a list of [`TcpRelays`](./struct.TcpRelays.html).

    https://zetok.github.io/tox-spec/#tcp-relays-0x0a
    */
    TcpRelays(TcpRelays),
    /** Section for a list of [`PathNodes`](./struct.PathNodes.html) for onion
    routing.

    https://zetok.github.io/tox-spec/#path-nodes-0x0b
    */
    PathNodes(PathNodes),
    /// End of file. https://zetok.github.io/tox-spec/#eof-0xff
    EOF,
}


/** Tox State sections. Use to manage `.tox` save files.

https://zetok.github.io/tox-spec/#state-format
*/
#[derive(Clone, Debug, Default, Eq, PartialEq)]
// TODO: change to use `Section`s
pub struct State {
    // Sections are listed in order from the spec.
    nospamkeys: NospamKeys,
    dhtstate: DhtState,
    friends: Friends,
    name: Name,
    status_msg: StatusMsg,
    status: UserStatus,
    tcp_relays: TcpRelays,
    path_nodes: PathNodes,
    eof: Eof,
}

/// State Format magic bytes.
const STATE_MAGIC: &'static [u8; 4] = &[0x1f, 0x1b, 0xed, 0x15];

/// Length of `State` header.
const STATE_HEAD_LEN: usize = 8;

/// Minimal length of State Format.
const STATE_MIN_LEN: usize = STATE_HEAD_LEN + SECTION_MIN_LEN;


// TODO: refactor the whole thing
impl State {

    /** Add friend with `PublicKey` without sending a friend request.

    Returns `true` if friend was added, `false` otherwise.

    **Subject to change**.
    */
    // TODO: move elsewhere
    pub fn add_friend_norequest(&mut self, pk: &PublicKey) -> bool {
        self.friends.add_friend(FriendState::new_from_pk(pk))
    }

    /** Check if given `PublicKey` is an exact match to the `State` PK.

    When checking if given Tox ID is our own, check only PK part, as it is
    the only usable unchanging part.

    Returns `true` if there's an exact match, `false` otherwise.
    */
    pub fn is_own_pk(&self, pk: &PublicKey) -> bool {
        self.nospamkeys.pk == *pk
    }

    /** Checks if given bytes have `State` header, i.e. whether the first
    8 bytes match.

    > **Note:** Even if data has `State` header, it still can fail to
    >           de-serialize when even a part of the data is invalid.

    Returns `true` if there's matching header, `false` otherwise.
    */
    pub fn is_state(bytes: &[u8]) -> bool {
        if bytes.len() < STATE_MIN_LEN {
            return false
        }
        // should start with 4 `0` bytes
        if &bytes[..4] != &[0; 4] {
            return false
        }
        let bytes = &bytes[4..];

        // match magic bytes
        if &bytes[..4] != STATE_MAGIC {
            return false
        }
        true
    }

    /** Fails (returns `None`) only if there is no `NospamKeys` in supplied
    sections. If some other section than `NospamKeys` has invalid data,
    `Default` value is used.
    */
    // TODO: test
    fn from_sects(sects: &[Section]) -> Option<Self> {
        // if no section matches `NospamKeys` return early
        if !sects.iter()
            .any(|s| match *s { Section::NospamKeys(_) => true, _ => false })
        {
            return None
        }

        // TODO: ↓ refactor once Eof gets implemented

        // get the section, or `Default` if section doesn't exist
        macro_rules! state_section {
            ($pname: path) => (
                sects.iter()
                    .filter_map(|s| match *s {
                        $pname(ref s) => Some(s.clone()),
                        _ => None,
                    })
                    .next()
                    .unwrap_or_default()
            )
        }

        // return `Some(_)` only if there are valid `NospamKeys`
        sects.iter()
            .filter_map(|s| match *s {
                Section::NospamKeys(ref nspks) => Some(nspks.clone()),
                _ => None,
            })
            .next()
            .map(|nspks|
                State {
                    nospamkeys: nspks,
                    dhtstate: state_section!(Section::DHT),
                    friends: state_section!(Section::Friends),
                    name: state_section!(Section::Name),
                    status_msg: state_section!(Section::StatusMsg),
                    status: state_section!(Section::Status),
                    tcp_relays: state_section!(Section::TcpRelays),
                    path_nodes: state_section!(Section::PathNodes),
                    eof: Eof,
                }
            )
    }
}

impl FromBytes for State {
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self> {
        if !State::is_state(bytes) {
            return parse_error!("Not a State!")
        }
        let bytes = &bytes[STATE_HEAD_LEN..];

        let (sections, bytes) = try!(SectionData::parse_bytes_multiple(bytes)
            .map(|Parsed(ref sd, b)| (SectionData::into_sect_mult(sd), b)));

        match Self::from_sects(&sections) {
            Some(s) => Ok(Parsed(s, bytes)),
            None => parse_error!("Failed to parse data, no valid sections!"),
        }
    }
}

impl ToBytes for State {
    // unoptimized
    fn to_bytes(&self) -> Vec<u8> {
        // should be run for each State's section
        fn to_s_bytes<S: ToBytes + SectionKindMatch>(sect: &S) -> Vec<u8> {
            let bytes = sect.to_bytes();
            let mut res = Vec::with_capacity(SECTION_MIN_LEN + bytes.len());
            // length of the section goes first
            res.write_u32::<LittleEndian>(bytes.len() as u32)
                .expect("Failed to write State length!");
            // knowing what's the section is useful
            res.extend_from_slice(&S::kind().to_bytes());
            // lets make it *magical*
            res.extend_from_slice(SECTION_MAGIC);
            res.extend_from_slice(&bytes);
            res
        }

        let mut res = Vec::new();
        // state header
        res.extend_from_slice(&[0; 4]);
        res.extend_from_slice(STATE_MAGIC);

        macro_rules! append_to_res {
            ($($sect:ident),+) => ($(
                res.extend_from_slice(&to_s_bytes(&self.$sect));
            )+)
        }
        // Right STR8 C Order:
        // 1. NospamKeys
        // 2. Friends
        // 3. Name
        // 4. StatusMsg
        // 5. Status
        // 6. DhtState ← /obviously/ 2nd section kind fits here
        // 7. TcpRelays
        // 8. PathNodes
        // 9. EOF
        append_to_res!(nospamkeys, friends, name, status_msg, status,
                       dhtstate, tcp_relays, path_nodes, eof);
        res
    }
}


#[cfg(test)]
impl Arbitrary for State {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        macro_rules! arb_state_section {
            ($($section:ident),+) => (
                State {
                    $($section: Arbitrary::arbitrary(g),)+
                }
            )
        }
        arb_state_section!(nospamkeys, friends, name, status_msg, status,
                           dhtstate, tcp_relays, path_nodes, eof)
    }
}



// FriendState::

// FriendState::new_from_pk()

#[test]
fn friend_state_new_from_pk_test() {
    fn with_pkbytes(bytes: Vec<u8>) -> TestResult {
        if bytes.len() < PUBLICKEYBYTES {
            return TestResult::discard()
        }

        let pk = PublicKey::from_slice(&bytes[..PUBLICKEYBYTES])
            .expect("PK failed");

        let fs = FriendState::new_from_pk(&pk);

        assert_eq!(FriendStatus::Added, fs.status);
        assert_eq!(pk, fs.pk);
        assert!(fs.fr_msg.is_empty());
        assert!(fs.name.0.is_empty());
        assert!(fs.status_msg.0.is_empty());
        assert_eq!(UserStatus::Online, fs.user_status);
        assert_eq!(NoSpam([0; NOSPAMBYTES]), fs.nospam);
        assert_eq!(0, fs.last_seen);

        TestResult::passed()
    }
    quickcheck(with_pkbytes as fn(Vec<u8>) -> TestResult);
}

// FriendState::parse_bytes()

#[test]
#[cfg(test)] // ← https://github.com/rust-lang/rust/issues/16688
fn friend_state_parse_bytes_test() {
    fn assert_error(bytes: &[u8], error: &str) {
        contains_err!(FriendState::parse_bytes, bytes, error);
    }

    // serialized and deserialized remain the same
    fn assert_success(bytes: &[u8], friend_state: &FriendState) {
        let Parsed(ref p, _) = FriendState::parse_bytes(bytes)
            .expect("Failed to unwrap FriendState!");
        assert_eq!(friend_state, p);
    }

    fn with_fs(fs: FriendState) {
        let fs_bytes = fs.to_bytes();
        assert_success(&fs_bytes, &fs);

        for b in 0..(FRIENDSTATEBYTES - 1) {
            assert_error(&fs_bytes[..b], "Not enough bytes for FriendState.");
        }

        { // FriendStatus
            let mut bytes = fs_bytes.clone();
            // TODO: change to inclusive range (`...`) once gets stabilised
            //       rust #28237
            for b in 5..u8::max_value() {
                bytes[0] = b;
                assert_error(&bytes, &format!("Unknown FriendStatus: {}", b));
            }
        }

        const FR_MSG_LEN_POS: usize = 1 + PUBLICKEYBYTES + REQUEST_MSG_LEN + 1;
        { // friend request message lenght check
            let mut bytes = fs_bytes.clone();
            for i in (REQUEST_MSG_LEN+1)..2500 { // too slow with bigger ranges
                BigEndian::write_u16(&mut bytes[FR_MSG_LEN_POS..], i as u16);
                assert_error(&bytes, &format!("Value demands {} bytes \
                    when it is supposed to take {}!", i, REQUEST_MSG_LEN));
            }
        }

        const NAME_LEN_POS: usize = FR_MSG_LEN_POS + NAME_LEN + 2;
        { // friend name lenght check
            let mut bytes = fs_bytes.clone();
            for i in (NAME_LEN+1)..2500 { // too slow with bigger ranges
                BigEndian::write_u16(&mut bytes[NAME_LEN_POS..], i as u16);
                assert_error(&bytes, &format!("Value demands {} bytes \
                    when it is supposed to take {}!", i, NAME_LEN));
            }
        }

        // padding + bytes containing length
        const STATUS_MSG_LEN_POS: usize = NAME_LEN_POS + STATUS_MSG_LEN + 3;
        { // friend name lenght check
            let mut bytes = fs_bytes.clone();
            for i in (STATUS_MSG_LEN+1)..2500 { // too slow with bigger ranges
                BigEndian::write_u16(&mut bytes[STATUS_MSG_LEN_POS..], i as u16);
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

            // TODO: change to inclusive range (`...`) once gets stabilised
            //       rust #28237
            for i in 0..u8::max_value() {
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
            // TODO: change to inclusive range (`...`) once gets stabilised
            //       rust #28237
            for i in 0..u8::max_value() {
                bytes[PADDING_POS]   = i;
                bytes[PADDING_POS+1] = i;
                bytes[PADDING_POS+2] = i;
                assert_success(&bytes, &fs);
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


// Friends::

// Friends::is_friend()

#[test]
fn friends_is_friend_test() {
    fn with_friends(friends: Friends, fstate: FriendState) -> TestResult {
        // can fail if quickcheck produces `Friends` that includes generated
        // friend
        assert_eq!(false, friends.is_friend(&fstate.pk));

        let mut friends = friends.clone();
        let pk = fstate.pk;
        friends.0.push(fstate);
        assert_eq!(true, friends.is_friend(&pk));
        TestResult::passed()
    }
    quickcheck(with_friends as fn(Friends, FriendState) -> TestResult);

    // empty
    let pk = PublicKey([0; PUBLICKEYBYTES]);
    assert_eq!(false, Friends(Vec::new()).is_friend(&pk));
}


// SectionData::

// SectionData::into_section()

// check for each type
macro_rules! section_data_with_kind_into {
    ($($kind:ident, $tname:ident),+) => ($(
        #[test]
        fn $tname() {
            fn tf(sd: SectionData) -> TestResult {
                if sd.kind != SectionKind::$kind {
                    return TestResult::discard()
                }
                assert!(sd.as_section().is_some());
                TestResult::passed()
            }
            quickcheck(tf as fn(SectionData) -> TestResult);
        }
    )+)
}
section_data_with_kind_into!(
    NospamKeys, section_data_into_sect_test_nospamkeys,
    DHT,        section_data_into_sect_test_dht,
    Friends,    section_data_into_sect_test_friends,
    Name,       section_data_into_sect_test_name,
    StatusMsg,  section_data_into_sect_test_status_msg,
    Status,     section_data_into_sect_test_status,
    TcpRelays,  section_data_into_sect_test_tcp_relays,
    PathNodes,  section_data_into_sect_test_path_nodes,
    EOF,        section_data_into_sect_test_eof
);

#[test]
fn section_data_into_section_test_random() {
    fn with_section(sd: SectionData) {
        assert!(sd.as_section().is_some());
    }
    quickcheck(with_section as fn(SectionData));
}

// SectionData::into_sect_mult()

macro_rules! section_data_into_sect_mult_into {
    ($($sect:ty, $kind:ident, $tname:ident),+) => ($(
        #[test]
        fn $tname() {
            fn with_sects(s: Vec<$sect>) {
                let sds: Vec<SectionData> = s.iter()
                    .map(|se| SectionData {
                        kind: SectionKind::$kind,
                        data: se.to_bytes()
                    })
                    .collect();
                let sections = SectionData::into_sect_mult(&sds);
                assert_eq!(s.len(), sections.len());
                if !s.is_empty() {
                    assert!(sections.iter().all(|se| match *se {
                        Section::$kind(_) => true,
                        _ => false,
                    }));
                }
            }
            QuickCheck::new().max_tests(20).quickcheck(with_sects as fn(Vec<$sect>));
        }
    )+)
}
// NOTE: ↓ this takes 5 min of CPU time on a 4GHz AMD Piledriver(!)
section_data_into_sect_mult_into!(
    NospamKeys, NospamKeys, section_data_into_sect_mult_test_nospamkeys,
    DhtState, DHT, section_data_into_sect_mult_test_dht,
    // ↓ takes longest, since it requires generating Vec<Friend> and then
    //   parsing that
    Friends, Friends, section_data_into_sect_mult_test_friends,
    Name, Name, section_data_into_sect_mult_test_name,
    StatusMsg, StatusMsg, section_data_into_sect_mult_test_status_msg,
    UserStatus, Status, section_data_into_sect_mult_test_status,
    TcpRelays, TcpRelays, section_data_into_sect_mult_test_path_nodes,
    TcpRelays, TcpRelays, section_data_into_sect_mult_test_tcp_relays
);

#[test]
fn section_data_into_sect_mult_test_random() {
    fn random_sds(sds: Vec<SectionData>) {
        assert_eq!(sds.len(), SectionData::into_sect_mult(&sds).len());
    }
    quickcheck(random_sds as fn(Vec<SectionData>));
}

// SectionData::parse_bytes()

#[test]
#[cfg(test)] // ← https://github.com/rust-lang/rust/issues/16688
fn section_data_parse_bytes_test() {
    fn rand_b_sect(kind: SectionKind, bytes: &[u8]) -> Vec<u8> {
        let mut b_sect = Vec::with_capacity(bytes.len() + SECTION_MIN_LEN);
        b_sect.write_u32::<LittleEndian>(bytes.len() as u32)
            .expect("Failed to write Section length!");
        b_sect.write_u16::<LittleEndian>(kind as u16)
            .expect("Failed to write Section kind!");
        b_sect.extend_from_slice(SECTION_MAGIC);
        b_sect.extend_from_slice(bytes);
        b_sect
    }

    fn with_bytes(bytes: Vec<u8>, kind: SectionKind) {
        let b_sect = rand_b_sect(kind, &bytes);

        { // working case
            let Parsed(section, left) = SectionData::parse_bytes(&b_sect)
                .expect("Failed to parse SectionData bytes!");

            assert_eq!(0, left.len());
            assert_eq!(section.kind, kind);
            assert_eq!(&section.data, &bytes);
        }

        { // wrong SectionKind
            fn wrong_skind(bytes: &[u8]) {
                contains_err!(SectionData::parse_bytes, bytes,
                              "Incorrect SectionKind: ");
            }

            let mut b_sect = b_sect.clone();
            for num in 7..10 {
                b_sect[4] = num;
                wrong_skind(&b_sect);
            }
            // TODO: change to inclusive range (`...`) once gets stabilised
            //       rust #28237
            for num in 12..u8::max_value() {
                b_sect[4] = num;
                wrong_skind(&b_sect);
            }

            b_sect[4] = 1; // right
            b_sect[5] = 1; // wrong
            wrong_skind(&b_sect);
        }

        // too short
        for l in 0..SECTION_MIN_LEN {
            contains_err!(SectionData::parse_bytes,
                          &b_sect[..l],
                          "Parsing failed: Not enough bytes for SectionData!");
        }

        // wrong len
        for l in SECTION_MIN_LEN..(b_sect.len() - 1) {
            contains_err!(SectionData::parse_bytes,
                          &b_sect[..l],
                          "Parsing failed: there are not enough bytes in \
                          section to parse!");
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>, SectionKind));

    fn with_magic(bytes: Vec<u8>, kind: SectionKind, magic: Vec<u8>)
        -> TestResult
    {
        if magic.len() < 2 || &[magic[0], magic[1]] == SECTION_MAGIC {
                return TestResult::discard()
        }

        let tmp_b_sect = rand_b_sect(kind, &bytes);
        let mut b_sect = Vec::with_capacity(tmp_b_sect.len());
        b_sect.extend_from_slice(&tmp_b_sect[..SECTION_MIN_LEN - 2]);
        b_sect.extend_from_slice(&magic[..2]);
        b_sect.extend_from_slice(&tmp_b_sect[SECTION_MIN_LEN..]);
        contains_err!(SectionData::parse_bytes,
                      &b_sect,
                      "Parsing failed: SECTION_MAGIC doesn\\'t match!");
        TestResult::passed()
    }
    quickcheck(with_magic as fn(Vec<u8>, SectionKind, Vec<u8>) -> TestResult);
}


// State::

// State::add_friend_norequest()

#[test]
#[cfg(test)] // ← https://github.com/rust-lang/rust/issues/16688
fn state_add_friend_norequest_test() {
    fn with_pk(state: State, pkbytes: Vec<u8>) -> TestResult {
        quick_pk_from_bytes!(pkbytes, pk);

        let mut new_state = state.clone();

        assert!(new_state.add_friend_norequest(&pk));
        assert_eq!(false, new_state.add_friend_norequest(&pk));
        assert!(state != new_state);
        assert_eq!(state.friends.0.len() + 1, new_state.friends.0.len());

        let popped = new_state.friends.0.pop().expect("Friend");
        assert_eq!(state, new_state);
        assert_eq!(popped, FriendState::new_from_pk(&pk));

        TestResult::passed()
    }
    quickcheck(with_pk as fn(State, Vec<u8>) -> TestResult);
}

// State::is_own_pk()

#[test]
#[cfg(test)] // ← https://github.com/rust-lang/rust/issues/16688
fn state_is_own_pk_test() {
    fn with_pk(state: State, bytes: Vec<u8>) -> TestResult {
        quick_pk_from_bytes!(bytes, rand_pk);

        assert!(state.is_own_pk(&state.nospamkeys.pk));
        assert_eq!(false, state.is_own_pk(&rand_pk));
        TestResult::passed()
    }
    quickcheck(with_pk as fn(State, Vec<u8>) -> TestResult);
}

// State::is_state()

#[test]
fn state_is_state_test() {
    // test parsing right and wrong bytes
    fn with_num(num: u8) -> TestResult {
        // right bytes
        let sf_bytes = vec![0, 0, 0, 0,
                            0x1f, 0x1b, 0xed, 0x15,
                            // ↑ section header
                            // ↓ this would be section data
                            0, 0, 0, 0,
                            0, 0 ,0 ,0];
        assert_eq!(true, State::is_state(&sf_bytes));

        // wrong, mismatching magic
        for pos in 4..8 {
            let mut bytes = sf_bytes.clone();
            match (pos, num) {
                (4, 0x1f) | (5, 0x1b) | (6, 0xed) | (7, 0x15) =>
                    return TestResult::discard(),
                _ => {},
            }

            bytes[pos] = num;
            assert_eq!(false, State::is_state(&bytes));
        }
        TestResult::passed()
    }
    quickcheck(with_num as fn(u8) -> TestResult);

    fn with_bytes(b: Vec<u8>) -> TestResult {
        if b.len() < STATE_MIN_LEN { return TestResult::discard() }
        for n in 0..(STATE_MIN_LEN - 1) {
            assert_eq!(false, State::is_state(&b[..n]));
        }
        assert_eq!(false, State::is_state(&b));
        TestResult::passed()
    }
    quickcheck(with_bytes as fn(Vec<u8>) -> TestResult);

    // empty bytes case
    assert_eq!(false, State::is_state(&[]));
}

// State::parse_bytes()

#[test]
fn state_parse_bytes_test_magic() {
    fn with_state(state: State, rand_bytes: Vec<u8>) -> TestResult {
        if rand_bytes.len() < STATE_HEAD_LEN {
            return TestResult::discard()
        }

        let state_bytes = state.to_bytes();
        assert!(State::is_state(&state_bytes));

        let mut invalid_bytes = Vec::with_capacity(state_bytes.len());
        invalid_bytes.extend_from_slice(&rand_bytes[..STATE_HEAD_LEN]);
        invalid_bytes.extend_from_slice(&state_bytes[STATE_HEAD_LEN..]);
        contains_err!(State::parse_bytes, &invalid_bytes, "Not a State!");
        TestResult::passed()
    }
    quickcheck(with_state as fn(State, Vec<u8>) -> TestResult);
}

#[test]
fn state_parse_bytes_test_section_detect() {
    fn with_state(state: State, rand_byte: u8) -> TestResult {
        if rand_byte == SECTION_MAGIC[0] {
            return TestResult::discard()
        }

        let bytes: Vec<u8> = state.to_bytes().iter_mut()
            .map(|b| { if *b == SECTION_MAGIC[0] { *b = rand_byte; } *b })
            .collect();

        contains_err!(State::parse_bytes, &bytes,
                      "Failed to parse data, no valid sections!");

        TestResult::passed()
    }
    quickcheck(with_state as fn(State, u8) -> TestResult);
}
