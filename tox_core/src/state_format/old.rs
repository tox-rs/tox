//! Old **Tox State Format (TSF)**. *__Will be deprecated__ when something
//! better will become available.*

use std::default::Default;
use nom::{
    number::complete::{le_u16, be_u16, le_u8, le_u32, le_u64},
    combinator::{rest, success, verify, map_parser, map},
    bytes::complete::{take, tag},
    multi::{many0, length_data},
    error::{ErrorKind, make_error},
    branch::alt,
};
use rand::{CryptoRng, Rng};

use tox_binary_io::*;
use tox_crypto::*;
use tox_packet::dht::packed_node::*;
use tox_packet::toxid::{NoSpam, NOSPAMBYTES};
use tox_packet::packed_node::*;

const REQUEST_MSG_LEN: usize = 1024;

/// According to https://zetok.github.io/tox-spec/#sections
const SECTION_MAGIC: &[u8; 2] = &[0xce, 0x01];

/** NoSpam and Keys section of the new state format.

https://zetok.github.io/tox-spec/#nospam-and-keys-0x01
*/
#[derive(Clone)]
pub struct NospamKeys {
    /// Own `NoSpam`.
    pub nospam: NoSpam,
    /// Own `PublicKey`.
    pub pk: PublicKey,
    /// Own `SecretKey`.
    pub sk: SecretKey,
}

/// Number of bytes of serialized [`NospamKeys`](./struct.NospamKeys.html).
pub const NOSPAMKEYSBYTES: usize = NOSPAMBYTES + crypto_box::KEY_SIZE + crypto_box::KEY_SIZE;

impl NospamKeys {
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let sk = SecretKey::generate(rng);
        let pk = sk.public_key();
        NospamKeys {
            nospam: rng.gen(),
            pk,
            sk
        }
    }
}

/** Provided that there's at least [`NOSPAMKEYSBYTES`]
(./constant.NOSPAMKEYSBYTES.html) de-serializing will not fail.
*/
// NoSpam is defined in toxid.rs
impl FromBytes for NospamKeys {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag([0x01,0x00])(input)?;
        let (input, _) = tag(SECTION_MAGIC)(input)?;
        let (input, nospam) = NoSpam::from_bytes(input)?;
        let (input, pk) = PublicKey::from_bytes(input)?;
        let (input, sk) = SecretKey::from_bytes(input)?;
        Ok((input, NospamKeys {
            nospam,
            pk,
            sk
        }))
    }
}

impl ToBytes for NospamKeys {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u16!(0x0001) >>
            gen_slice!(SECTION_MAGIC) >>
            gen_slice!(self.nospam.0) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.sk.as_bytes())
        )
    }
}

/** Own name, up to [`NAME_LEN`](./constant.NAME_LEN.html) bytes long.
*/
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Name(pub Vec<u8>);

/// Length in bytes of name. ***Will be moved elsewhere.***
pub const NAME_LEN: usize = 128;

/** Produces up to [`NAME_LEN`](./constant.NAME_LEN.html) bytes long `Name`.
    Can't fail.
*/
impl FromBytes for Name {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag([0x04,0x00])(input)?;
        let (input, _) = tag(SECTION_MAGIC)(input)?;
        let (input, name_bytes) = rest(input)?;
        Ok((input, Name(name_bytes.to_vec())))
    }
}

impl ToBytes for Name {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u16!(0x0004) >>
            gen_slice!(SECTION_MAGIC) >>
            gen_slice!(self.0.as_slice())
        )
    }
}

/** DHT section of the old state format.
https://zetok.github.io/tox-spec/#dht-0x02
Default is empty, no Nodes.
*/
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DhtState(pub Vec<PackedNode>);

/// Special, magical beginning of DHT section in LE.
const DHT_MAGICAL: u32 = 0x0159_000d;

/** Special DHT section type encoded in LE.

    https://zetok.github.io/tox-spec/#dht-sections
*/
const DHT_SECTION_TYPE: u16 = 0x0004;

/** Yet another magical number in DHT section that needs a check.

https://zetok.github.io/tox-spec/#dht-sections
*/
const DHT_2ND_MAGICAL: u16 = 0x11ce;

impl FromBytes for DhtState {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag([0x02,0x00])(input)?;
        let (input, _) = tag(SECTION_MAGIC)(input)?;
        let (input, _) = verify(le_u32, |value| *value == DHT_MAGICAL)(input)?; // check whether beginning of the section matches DHT magic bytes
        let (input, num_of_bytes) = le_u32(input)?;
        let (input, _) = verify(le_u16, |value| *value == DHT_SECTION_TYPE)(input)?; // check DHT section type
        let (input, _) = verify(le_u16, |value| *value == DHT_2ND_MAGICAL)(input)?; // check whether yet another magic number matches
        let (input, nodes) = map_parser(take(num_of_bytes), many0(PackedNode::from_bytes))(input)?;
        Ok((input, DhtState(nodes)))
    }
}

impl ToBytes for DhtState {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        let start_idx = buf.1;

        let (buf, idx) = do_gen!(buf,
            gen_le_u16!(0x0002) >>
            gen_slice!(SECTION_MAGIC) >>
            gen_le_u32!(DHT_MAGICAL as u32) >>
            gen_skip!(4) >>
            gen_le_u16!(DHT_SECTION_TYPE as u16) >>
            gen_le_u16!(DHT_2ND_MAGICAL as u16) >>
            gen_many_ref!(&self.0, |buf, node| PackedNode::to_bytes(node, buf))
        )?;

        let len = (idx - start_idx - 16) as u32;
        buf[start_idx + 8..start_idx + 12].copy_from_slice(&u32::to_le_bytes(len));
        Ok((buf, idx))
    }
}

/** Friend state status. Used by [`FriendState`](./struct.FriendState.html).

https://zetok.github.io/tox-spec/#friends-0x03

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

impl FromBytes for FriendStatus {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, b) = le_u8(input)?;
        match b {
            0 => Ok((input, FriendStatus::NotFriend)),
            1 => Ok((input, FriendStatus::Added)),
            2 => Ok((input, FriendStatus::FrSent)),
            3 => Ok((input, FriendStatus::Confirmed)),
            4 => Ok((input, FriendStatus::Online)),
            _ => Err(nom::Err::Error(make_error(input, ErrorKind::Switch))),
        }
    }
}

/** User status. Used for both own & friend statuses.

https://zetok.github.io/tox-spec/#userstatus

*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserWorkingStatus {
    /// User is `Online`.
    Online = 0,
    /// User is `Away`.
    Away   = 1,
    /// User is `Busy`.
    Busy   = 2,
}

/// Returns `UserWorkingStatus::Online`.
impl Default for UserWorkingStatus {
    fn default() -> Self {
        UserWorkingStatus::Online
    }
}

impl FromBytes for UserWorkingStatus {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, b) = le_u8(input)?;
        match b {
            0 => Ok((input, UserWorkingStatus::Online)),
            1 => Ok((input, UserWorkingStatus::Away)),
            2 => Ok((input, UserWorkingStatus::Busy)),
            _ => Err(nom::Err::Error(make_error(input, ErrorKind::Switch))),
        }
    }
}

/// Length in bytes of UserStatus
pub const USER_STATUS_LEN: usize = 1;

/// User status section
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UserStatus(UserWorkingStatus);

impl FromBytes for UserStatus {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag([0x06,0x00])(input)?;
        let (input, _) = tag(SECTION_MAGIC)(input)?;
        let (input, user_status) = UserWorkingStatus::from_bytes(input)?;
        Ok((input, UserStatus(user_status)))
    }
}

impl ToBytes for UserStatus {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u16!(0x0006) >>
            gen_slice!(SECTION_MAGIC) >>
            gen_le_u8!(self.0 as u8)
        )
    }
}

/** Status message, up to [`STATUS_MSG_LEN`](./constant.STATUS_MSG_LEN.html)
bytes.

*/
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StatusMsg(pub Vec<u8>);

/// Length in bytes of friend's status message.
// FIXME: move somewhere else
pub const STATUS_MSG_LEN: usize = 1007;

impl ToBytes for StatusMsg {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u16!(0x0005) >>
            gen_slice!(SECTION_MAGIC) >>
            gen_slice!(self.0.as_slice())
        )
    }
}

impl FromBytes for StatusMsg {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag([0x05,0x00])(input)?;
        let (input, _) = tag(SECTION_MAGIC)(input)?;
        let (input, status_msg_bytes) = rest(input)?;
        Ok((input, StatusMsg(status_msg_bytes.to_vec())))
    }
}

/// Contains list in `TcpUdpPackedNode` format.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TcpRelays(pub Vec<TcpUdpPackedNode>);

impl FromBytes for TcpRelays {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag([0x0a, 0x00])(input)?;
        let (input, _) = tag(SECTION_MAGIC)(input)?;
        let (input, nodes) = many0(TcpUdpPackedNode::from_bytes)(input)?;
        Ok((input, TcpRelays(nodes)))
    }
}

impl ToBytes for TcpRelays {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u16!(0x000a) >>
            gen_slice!(SECTION_MAGIC) >>
            gen_many_ref!(&self.0, |buf, node| TcpUdpPackedNode::to_bytes(node, buf))
        )
    }
}

/// Contains list in `PackedNode` format.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PathNodes(pub Vec<TcpUdpPackedNode>);

impl FromBytes for PathNodes {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag([0x0b, 0x00])(input)?;
        let (input, _) = tag(SECTION_MAGIC)(input)?;
        let (input, nodes) = many0(TcpUdpPackedNode::from_bytes)(input)?;
        Ok((input, PathNodes(nodes)))
    }
}

impl ToBytes for PathNodes {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u16!(0x000b) >>
            gen_slice!(SECTION_MAGIC) >>
            gen_many_ref!(&self.0, |buf, node| TcpUdpPackedNode::to_bytes(node, buf))
        )
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
    friend_status: FriendStatus,
    pk: PublicKey,
    /// Friend request message that is being sent to friend.
    fr_msg: Vec<u8>,
    /// Friend's name.
    name: Name,
    status_msg: StatusMsg,
    user_status: UserWorkingStatus,
    nospam: NoSpam,
    /// Time when friend was last seen online.
    last_seen: u64,
}

/// Number of bytes of serialized [`FriendState`](./struct.FriendState.html).
pub const FRIENDSTATEBYTES: usize = 1      // "Status"
    + crypto_box::KEY_SIZE
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
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, friend_status) = FriendStatus::from_bytes(input)?;
        let (input, pk) = PublicKey::from_bytes(input)?;
        let (input, fr_msg_bytes) = take(REQUEST_MSG_LEN)(input)?;
        let (input, _) = take(1usize)(input)?;
        let (input, fr_msg_len) = be_u16(input)?;
        let (input, _) = verify(success(fr_msg_len), |len| *len <= REQUEST_MSG_LEN as u16)(input)?;
        let fr_msg =fr_msg_bytes[..fr_msg_len as usize].to_vec();
        let (input, name_bytes) = take(NAME_LEN)(input)?;
        let (input, name_len) = be_u16(input)?;
        let (input, _) = verify(success(name_len), |len| *len <= NAME_LEN as u16)(input)?;
        let name = Name(name_bytes[..name_len as usize].to_vec());
        let (input, status_msg_bytes) = take(STATUS_MSG_LEN)(input)?;
        let (input, _) = take(1usize)(input)?;
        let (input, status_msg_len) = be_u16(input)?;
        let (input, _) = verify(success(status_msg_len), |len| *len <= STATUS_MSG_LEN as u16)(input)?;
        let status_msg = StatusMsg(status_msg_bytes[..status_msg_len as usize].to_vec());
        let (input, user_status) = UserWorkingStatus::from_bytes(input)?;
        let (input, _) = take(3usize)(input)?;
        let (input, nospam) = NoSpam::from_bytes(input)?;
        let (input, last_seen) = le_u64(input)?;
        Ok((input, FriendState {
            friend_status,
            pk,
            fr_msg,
            name,
            status_msg,
            user_status,
            nospam,
            last_seen,
        }))
    }
}

impl ToBytes for FriendState {
    #[allow(clippy::cognitive_complexity)]
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        let mut fr_msg_pad = self.fr_msg.clone();
        let mut name_pad = self.name.0.clone();
        let mut status_msg_pad = self.status_msg.0.clone();
        fr_msg_pad.resize(REQUEST_MSG_LEN, 0);
        name_pad.resize(NAME_LEN, 0);
        status_msg_pad.resize(STATUS_MSG_LEN, 0);

        do_gen!(buf,
            gen_le_u8!(self.friend_status as u8) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(fr_msg_pad.as_slice()) >>
            gen_le_u8!(0) >>
            gen_be_u16!(self.fr_msg.len() as u16) >>
            gen_slice!(name_pad.as_slice()) >>
            gen_be_u16!(self.name.0.len() as u16) >>
            gen_slice!(status_msg_pad.as_slice()) >>
            gen_le_u8!(0) >>
            gen_be_u16!(self.status_msg.0.len() as u16) >>
            gen_le_u8!(self.user_status as u8) >>
            gen_le_u8!(0) >>
            gen_le_u16!(0) >>
            gen_slice!(self.nospam.0) >>
            gen_le_u64!(self.last_seen)
        )
    }
}

/** Wrapper struct for `Vec<FriendState>` to ease working with friend lists.
*/
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Friends(pub Vec<FriendState>);

impl FromBytes for Friends {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag([0x03, 0x00])(input)?;
        let (input, _) = tag(SECTION_MAGIC)(input)?;
        let (input, friends) = many0(map_parser(take(FRIENDSTATEBYTES), FriendState::from_bytes))(input)?;
        Ok((input, Friends(friends)))
    }
}

impl ToBytes for Friends {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u16!(0x0003) >>
            gen_slice!(SECTION_MAGIC) >>
            gen_many_ref!(&self.0, |buf, friend| FriendState::to_bytes(friend, buf))
        )
    }
}

/// End of the state format data.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Eof;

impl FromBytes for Eof {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag([0xff, 0x00])(input)?;
        let (input, _) = tag(SECTION_MAGIC)(input)?;
        Ok((input, Eof))
    }
}

impl ToBytes for Eof {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u16!(0x00ff) >>
            gen_slice!(SECTION_MAGIC)
        )
    }
}

/** Sections of state format.

https://zetok.github.io/tox-spec/#sections
*/
#[derive(Clone)]
pub enum Section {
    /** Section for [`NoSpam`](../../toxid/struct.NoSpam.html), public and
    secret keys.

    https://zetok.github.io/tox-spec/#nospam-and-keys-0x01
    */
    NospamKeys(NospamKeys),
    /** Section for DHT-related data – [`DhtState`](./struct.DhtState.html).

    https://zetok.github.io/tox-spec/#dht-0x02
    */
    DhtState(DhtState),
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
    UserStatus(UserStatus),
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
    Eof(Eof),
}

impl FromBytes for Section {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        alt((
            map(NospamKeys::from_bytes, Section::NospamKeys),
            map(DhtState::from_bytes, Section::DhtState),
            map(Friends::from_bytes, Section::Friends),
            map(Name::from_bytes, Section::Name),
            map(StatusMsg::from_bytes, Section::StatusMsg),
            map(UserStatus::from_bytes, Section::UserStatus),
            map(TcpRelays::from_bytes, Section::TcpRelays),
            map(PathNodes::from_bytes, Section::PathNodes),
            map(Eof::from_bytes, Section::Eof),
        ))(input)
    }
}

impl ToBytes for Section {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        let (buf, start_idx) = buf;

        if buf.len() < start_idx + 4 {
            return Err(GenError::BufferTooSmall(start_idx + 4));
        }

        let buf = (buf, start_idx + 4);
        let (buf, idx) = match *self {
            Section::NospamKeys(ref p) => p.to_bytes(buf),
            Section::DhtState(ref p) => p.to_bytes(buf),
            Section::Friends(ref p) => p.to_bytes(buf),
            Section::Name(ref p) => p.to_bytes(buf),
            Section::StatusMsg(ref p) => p.to_bytes(buf),
            Section::UserStatus(ref p) => p.to_bytes(buf),
            Section::TcpRelays(ref p) => p.to_bytes(buf),
            Section::PathNodes(ref p) => p.to_bytes(buf),
            Section::Eof(ref p) => p.to_bytes(buf),
        }?;

        let len = (idx - start_idx - 8) as u32;
        buf[start_idx..start_idx + 4].copy_from_slice(&u32::to_le_bytes(len));
        Ok((buf, idx))
    }
}

/// State Format magic bytes.
const STATE_MAGIC: &[u8; 4] = &[0x1f, 0x1b, 0xed, 0x15];

/** Tox State sections. Use to manage `.tox` save files.

https://zetok.github.io/tox-spec/#state-format
*/
#[derive(Clone)]
pub struct State {
    sections: Vec<Section>,
}

impl FromBytes for State {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag(&[0; 4][..])(input)?;
        let (input, _) = tag(STATE_MAGIC)(input)?;
        let (input, sections) = many0(map_parser(length_data(map(le_u32, |len| len + 4)), Section::from_bytes))(input)?;
        Ok((input, State {
            sections: sections.to_vec(),
        }))
    }
}

impl ToBytes for State {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!([0; 4]) >>
            gen_slice!(STATE_MAGIC) >>
            gen_many_ref!(&self.sections, |buf, section| Section::to_bytes(section, buf))
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::thread_rng;
    use tox_packet::ip_port::*;

    encode_decode_test!(
        dht_state_encode_decode,
        DhtState(vec![
            PackedNode {
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
                saddr: "1.2.3.4:1234".parse().unwrap(),
            },
            PackedNode {
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
                saddr: "1.2.3.5:1235".parse().unwrap(),
            },
        ])
    );

    encode_decode_test!(
        friends_encode_decode,
        Friends(vec![
            FriendState {
                friend_status: FriendStatus::Added,
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
                fr_msg: b"test msg".to_vec(),
                name: Name(b"test name".to_vec()),
                status_msg: StatusMsg(b"test status msg".to_vec()),
                user_status: UserWorkingStatus::Online,
                nospam: NoSpam([7; NOSPAMBYTES]),
                last_seen: 1234,
            },
            FriendState {
                friend_status: FriendStatus::Added,
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
                fr_msg: b"test msg2".to_vec(),
                name: Name(b"test name2".to_vec()),
                status_msg: StatusMsg(b"test status msg2".to_vec()),
                user_status: UserWorkingStatus::Online,
                nospam: NoSpam([8; NOSPAMBYTES]),
                last_seen: 1235,
            },
        ])
    );

    encode_decode_test!(
        friend_state_encode_decode,
        FriendState {
            friend_status: FriendStatus::Added,
            pk: SecretKey::generate(&mut thread_rng()).public_key(),
            fr_msg: b"test msg".to_vec(),
            name: Name(b"test name".to_vec()),
            status_msg: StatusMsg(b"test status msg".to_vec()),
            user_status: UserWorkingStatus::Online,
            nospam: NoSpam([7; NOSPAMBYTES]),
            last_seen: 1234,
        }
    );

    encode_decode_test!(
        name_encode_decode,
        Name(vec![0,1,2,3,4])
    );

    encode_decode_test!(
        status_msg_encode_decode,
        StatusMsg(vec![0,1,2,3,4,5])
    );

    encode_decode_test!(
        eof_encode_decode,
        Eof
    );

    encode_decode_test!(
        user_status_encode_decode,
        UserStatus(UserWorkingStatus::Online)
    );

    encode_decode_test!(
        tcp_relays_encode_decode,
        TcpRelays(vec![
            TcpUdpPackedNode {
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
                ip_port: IpPort {
                    protocol: ProtocolType::Tcp,
                    ip_addr: "1.2.3.4".parse().unwrap(),
                    port: 1234,
                },
            },
            TcpUdpPackedNode {
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
                ip_port: IpPort {
                    protocol: ProtocolType::Udp,
                    ip_addr: "1.2.3.5".parse().unwrap(),
                    port: 12345,
                },
            },
        ])
    );

    encode_decode_test!(
        path_nodes_encode_decode,
        PathNodes(vec![
            TcpUdpPackedNode {
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
                ip_port: IpPort {
                    protocol: ProtocolType::Tcp,
                    ip_addr: "1.2.3.4".parse().unwrap(),
                    port: 1234,
                },
            },
            TcpUdpPackedNode {
                pk: SecretKey::generate(&mut thread_rng()).public_key(),
                ip_port: IpPort {
                    protocol: ProtocolType::Udp,
                    ip_addr: "1.2.3.5".parse().unwrap(),
                    port: 12345,
                },
            },
        ])
    );
}
