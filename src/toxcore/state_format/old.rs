//! Old **Tox State Format (TSF)**. *__Will be deprecated__ when something
//! better will become available.*

use std::default::Default;
use nom::{le_u16, le_u8, le_u32, le_u64};

#[cfg(test)]
use quickcheck::*;

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::dht::packed_node::*;
use toxcore::toxid::{NoSpam, NOSPAMBYTES};

const REQUEST_MSG_LEN: usize = 1024;

/// According to https://zetok.github.io/tox-spec/#sections
const SECTION_MAGIC: [u8; 2] = [206, 1];

/** NoSpam and Keys section of the new state format.

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
            nospam,
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
    named!(from_bytes<NospamKeys>, do_parse!(
        tag!([0x01,0x00]) >>
        tag!(SECTION_MAGIC) >>
        nospam: call!(NoSpam::from_bytes) >>
        pk: call!(PublicKey::from_bytes) >>
        sk: call!(SecretKey::from_bytes) >>
        (NospamKeys {
            nospam,
            pk,
            sk
        })
    ));
}

impl ToBytes for NospamKeys {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u16!(0x0001) >>
            gen_slice!(SECTION_MAGIC) >>
            gen_slice!(self.nospam.0) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.sk.0)
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
    named!(from_bytes<Name>, do_parse!(
        tag!([0x04,0x00]) >>
        tag!(SECTION_MAGIC) >>
        name_len: le_u16 >>
        verify!(value!(name_len), |len| len <= NAME_LEN as u16) >>
        name_bytes: take!(name_len) >>
        name: value!(name_bytes.to_vec()) >>
        (Name(name))
    ));
}

impl ToBytes for Name {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u16!(0x0004) >>
            gen_slice!(SECTION_MAGIC) >>
            gen_le_u16!(self.0.len()) >>
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
    named!(from_bytes<DhtState>, do_parse!(
        tag!([0x02,0x00]) >>
        tag!(SECTION_MAGIC) >>
        verify!(le_u32, |value| value == DHT_MAGICAL) >> // check whether beginning of the section matches DHT magic bytes
        num_of_nodes: le_u16 >>
        verify!(le_u16, |value| value == DHT_SECTION_TYPE) >> // check DHT section type
        verify!(le_u16, |value| value == DHT_2ND_MAGICAL) >> // check whether yet another magic number matches
        nodes: many_m_n!(num_of_nodes as usize, num_of_nodes as usize, PackedNode::from_bytes) >>
        (DhtState(nodes))
    ));
}

impl ToBytes for DhtState {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u16!(0x0002) >>
            gen_slice!(SECTION_MAGIC) >>
            gen_le_u32!(DHT_MAGICAL as u32) >>
            gen_le_u16!(self.0.len() as u16) >>
            gen_le_u16!(DHT_SECTION_TYPE as u16) >>
            gen_le_u16!(DHT_2ND_MAGICAL as u16) >>
            gen_many_ref!(&self.0, |buf, node| PackedNode::to_bytes(node, buf))
        )
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
    named!(from_bytes<FriendStatus>, switch!(le_u8,
        0 => value!(FriendStatus::NotFriend) |
        1 => value!(FriendStatus::Added) |
        2 => value!(FriendStatus::FrSent) |
        3 => value!(FriendStatus::Confirmed) |
        4 => value!(FriendStatus::Online)
    ));
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
    named!(from_bytes<UserWorkingStatus>,
        switch!(le_u8,
            0 => value!(UserWorkingStatus::Online) |
            1 => value!(UserWorkingStatus::Away) |
            2 => value!(UserWorkingStatus::Busy)
        )
    );
}

/// User status section
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UserStatus(UserWorkingStatus);

impl FromBytes for UserStatus {
    named!(from_bytes<UserStatus>, do_parse!(
        tag!([0x06,0x00]) >>
        tag!(SECTION_MAGIC) >>
        user_status : call!(UserWorkingStatus::from_bytes) >>
        (UserStatus(user_status))
    ));
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
            gen_le_u16!(self.0.len()) >>
            gen_slice!(self.0.as_slice())
        )
    }
}

impl FromBytes for StatusMsg {
    named!(from_bytes<StatusMsg>, do_parse!(
        tag!([0x05,0x00]) >>
        tag!(SECTION_MAGIC) >>
        status_msg_len: le_u16 >>
        verify!(value!(status_msg_len), |len| len <= STATUS_MSG_LEN as u16) >>
        status_msg_bytes: take!(status_msg_len) >>
        status_msg: value!(status_msg_bytes.to_vec()) >>
        (StatusMsg(status_msg))
    ));
}

macro_rules! impl_arb_for_pn {
    ($name:ident) => (
        #[cfg(test)]
        impl Arbitrary for $name {
            fn arbitrary<G: Gen>(g: &mut G) -> Self {
                let vec_len = g.gen_range(0, 16);
                let nodes = (0..vec_len).into_iter()
                    .map(|_| PackedNode::arbitrary(g))
                    .collect();

                $name(nodes)
            }
        }
    )
}

macro_rules! nodes_list {
    ($($name:ident, $tname:ident, $tag:expr),+) => ($(
        /// Contains list in `PackedNode` format.
        #[derive(Clone, Debug, Default, Eq, PartialEq)]
        pub struct $name(pub Vec<PackedNode>);

        impl FromBytes for $name {
            named!(from_bytes<$name>, do_parse!(
                tag!([0x00, $tag]) >>
                tag!(SECTION_MAGIC) >>
                num_of_nodes: le_u16 >>
                nodes: many_m_n!(num_of_nodes as usize, num_of_nodes as usize, PackedNode::from_bytes) >>
                ($name(nodes))
            ));
        }

        impl ToBytes for $name {
            fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
                do_gen!(buf,
                    gen_le_u8!(0) >>
                    gen_le_u8!($tag) >>
                    gen_slice!(SECTION_MAGIC) >>
                    gen_le_u16!(self.0.len()) >>
                    gen_many_ref!(&self.0, |buf, node| PackedNode::to_bytes(node, buf))
                )
            }
        }

        impl_arb_for_pn!($name);

        #[test]
        fn $tname() {
            fn with_pns(pns: $name) {
                let mut buf = [0u8; 1024 * 10];
                let (_, size) = pns.to_bytes((&mut buf, 0)).unwrap();
                let (r_bytes, p) = $name::from_bytes(&buf[..size]).unwrap();

                assert_eq!(p.0, pns.0);
                assert_eq!(&[] as &[u8], r_bytes);
            }
            quickcheck(with_pns as fn($name));

            // Default impl test
            assert_eq!(&[] as &[PackedNode], $name::default().0.as_slice());
        }
    )+)
}

nodes_list!(TcpRelays, tcp_relays_test, 0x0a,
                PathNodes, path_nodes_test, 0x0b);

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
/* friend status               1    */
/* PUBLICKEYBYTES              32   */
/* Friend request message      1024 */
/* padding1                    1    */
/* actual size of FR message   2    */
/* Name                        128  */
/* actual size of Name         2    */
/* Status msg                  1007 */
/* padding2                    1    */
/* actual size of status msg   2    */
/* UserStatus                  1    */
/* padding3                    3    */
/* no spam                     4    */
/* last time seen              8    */

impl FromBytes for FriendState {
    named!(from_bytes<FriendState>, do_parse!(
        friend_status: call!(FriendStatus::from_bytes) >>
        pk: call!(PublicKey::from_bytes) >>
        fr_msg_bytes: take!(REQUEST_MSG_LEN) >>
        padding1: take!(1) >>
        fr_msg_len: le_u16 >>
        verify!(value!(fr_msg_len), |len| len <= REQUEST_MSG_LEN as u16) >>
        fr_msg: value!(fr_msg_bytes[..fr_msg_len as usize].to_vec()) >>
        name_bytes: take!(NAME_LEN) >>
        name_len: le_u16 >>
        verify!(value!(name_len), |len| len <= NAME_LEN as u16) >>
        name: value!(Name(name_bytes[..name_len as usize].to_vec())) >>
        status_msg_bytes: take!(STATUS_MSG_LEN) >>
        padding2: take!(1) >>
        status_msg_len: le_u16 >>
        verify!(value!(status_msg_len), |len| len <= STATUS_MSG_LEN as u16) >>
        status_msg: value!(StatusMsg(status_msg_bytes[..status_msg_len as usize].to_vec())) >>
        user_status: call!(UserWorkingStatus::from_bytes) >>
        padding3: take!(3) >>
        nospam: call!(NoSpam::from_bytes) >>
        last_seen: le_u64 >>
        (FriendState {
            friend_status,
            pk,
            fr_msg,
            name,
            status_msg,
            user_status,
            nospam,
            last_seen,
        })
    ));
}

impl ToBytes for FriendState {
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
            gen_le_u16!(self.fr_msg.len()) >>
            gen_slice!(name_pad.as_slice()) >>
            gen_le_u16!(self.name.0.len()) >>
            gen_slice!(status_msg_pad.as_slice()) >>
            gen_le_u8!(0) >>
            gen_le_u16!(self.status_msg.0.len()) >>
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
    named!(from_bytes<Friends>, do_parse!(
        tag!([0x03, 0x00]) >>
        tag!(SECTION_MAGIC) >>
        num_of_friends: le_u16 >>
        friends: many_m_n!(num_of_friends as usize, num_of_friends as usize, FriendState::from_bytes) >>
        (Friends(friends))
    ));
}

impl ToBytes for Friends {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u16!(0x0003) >>
            gen_slice!(SECTION_MAGIC) >>
            gen_le_u16!(self.0.len()) >>
            gen_many_ref!(&self.0, |buf, friend| FriendState::to_bytes(friend, buf))
        )
    }
}

/// End of the state format data.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Eof;

impl FromBytes for Eof {
    named!(from_bytes<Eof>, do_parse!(
        tag!([0xff, 0x00]) >>
        tag!(SECTION_MAGIC) >>
        (Eof)
    ));
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
#[derive(Clone, Debug, Eq, PartialEq)]
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
}

impl FromBytes for Section {
    named!(from_bytes<Section>, alt!(
        map!(NospamKeys::from_bytes, Section::NospamKeys) |
        map!(DhtState::from_bytes, Section::DhtState) |
        map!(Friends::from_bytes, Section::Friends) |
        map!(Name::from_bytes, Section::Name) |
        map!(StatusMsg::from_bytes, Section::StatusMsg) |
        map!(UserStatus::from_bytes, Section::UserStatus) |
        map!(TcpRelays::from_bytes, Section::TcpRelays) |
        map!(PathNodes::from_bytes, Section::PathNodes)
    ));
}

impl ToBytes for Section {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            Section::NospamKeys(ref p) => p.to_bytes(buf),
            Section::DhtState(ref p) => p.to_bytes(buf),
            Section::Friends(ref p) => p.to_bytes(buf),
            Section::Name(ref p) => p.to_bytes(buf),
            Section::StatusMsg(ref p) => p.to_bytes(buf),
            Section::UserStatus(ref p) => p.to_bytes(buf),
            Section::TcpRelays(ref p) => p.to_bytes(buf),
            Section::PathNodes(ref p) => p.to_bytes(buf)
        }
    }
}

/** Tox State sections. Use to manage `.tox` save files.

https://zetok.github.io/tox-spec/#state-format
*/
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct State {
    sections: Vec<Section>,
    eof: Eof,
}

impl FromBytes for State {
    named!(from_bytes<State>, do_parse!(
        num_of_sections: le_u8 >>
        sections: many_m_n!(num_of_sections as usize, num_of_sections as usize, Section::from_bytes) >>
        eof: call!(Eof::from_bytes) >>
        (State {
            sections: sections.to_vec(),
            eof,
        })
    ));
}

impl ToBytes for State {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u8!(self.sections.len() as u8) >>
            gen_many_ref!(&self.sections, |buf, section| Section::to_bytes(section, buf)) >>
            gen_call!(|buf, eof| Eof::to_bytes(eof, buf), &self.eof)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        no_spam_keys_encode_decode,
        NospamKeys::default()
    );

    encode_decode_test!(
        dht_state_encode_decode,
        DhtState(vec![
            PackedNode {
                pk: gen_keypair().0,
                saddr: "1.2.3.4:1234".parse().unwrap(),
            },
            PackedNode {
                pk: gen_keypair().0,
                saddr: "1.2.3.5:1235".parse().unwrap(),
            },
        ])
    );

    encode_decode_test!(
        friends_encode_decode,
        Friends(vec![
            FriendState {
                friend_status: FriendStatus::Added,
                pk: gen_keypair().0,
                fr_msg: b"test msg".to_vec(),
                name: Name(b"test name".to_vec()),
                status_msg: StatusMsg(b"test status msg".to_vec()),
                user_status: UserWorkingStatus::Online,
                nospam: NoSpam([7; NOSPAMBYTES]),
                last_seen: 1234,
            },
            FriendState {
                friend_status: FriendStatus::Added,
                pk: gen_keypair().0,
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
        name_encode_decode,
        Name(vec![0,1,2,3,4])
    );

    encode_decode_test!(
        status_msg_encode_decode,
        StatusMsg(vec![0,1,2,3,4,5])
    );

    encode_decode_test!(
        user_status_encode_decode,
        UserStatus(UserWorkingStatus::Online)
    );

    encode_decode_test!(
        tcp_relays_encode_decode,
        TcpRelays(vec![
            PackedNode {
                pk: gen_keypair().0,
                saddr: "1.2.3.4:1234".parse().unwrap(),
            },
            PackedNode {
                pk: gen_keypair().0,
                saddr: "1.2.3.5:1235".parse().unwrap(),
            },
        ])
    );

    encode_decode_test!(
        path_nodes_encode_decode,
        PathNodes(vec![
            PackedNode {
                pk: gen_keypair().0,
                saddr: "1.2.3.4:1234".parse().unwrap(),
            },
            PackedNode {
                pk: gen_keypair().0,
                saddr: "1.2.3.5:1235".parse().unwrap(),
            },
        ])
    );

    encode_decode_test!(
        state_encode_decode,
        State {
            sections: vec![
                Section::NospamKeys(NospamKeys::default()),
                Section::DhtState(DhtState(vec![
                    PackedNode {
                        pk: gen_keypair().0,
                        saddr: "1.2.3.4:1234".parse().unwrap(),
                    },
                    PackedNode {
                        pk: gen_keypair().0,
                        saddr: "1.2.3.5:1235".parse().unwrap(),
                    },
                ])),
                Section::Friends(Friends(vec![
                    FriendState {
                        friend_status: FriendStatus::Added,
                        pk: gen_keypair().0,
                        fr_msg: b"test msg".to_vec(),
                        name: Name(b"test name".to_vec()),
                        status_msg: StatusMsg(b"test status msg".to_vec()),
                        user_status: UserWorkingStatus::Online,
                        nospam: NoSpam([7; NOSPAMBYTES]),
                        last_seen: 1234,
                    },
                    FriendState {
                        friend_status: FriendStatus::Added,
                        pk: gen_keypair().0,
                        fr_msg: b"test msg2".to_vec(),
                        name: Name(b"test name2".to_vec()),
                        status_msg: StatusMsg(b"test status msg2".to_vec()),
                        user_status: UserWorkingStatus::Online,
                        nospam: NoSpam([8; NOSPAMBYTES]),
                        last_seen: 1235,
                    },
                ])),
                Section::Name(Name(vec![0,1,2,3,4])),
                Section::StatusMsg(StatusMsg(vec![0,1,2,3,4,5])),
                Section::UserStatus(UserStatus(UserWorkingStatus::Online)),
                Section::TcpRelays(TcpRelays(vec![
                    PackedNode {
                        pk: gen_keypair().0,
                        saddr: "1.2.3.4:1234".parse().unwrap(),
                    },
                    PackedNode {
                        pk: gen_keypair().0,
                        saddr: "1.2.3.5:1235".parse().unwrap(),
                    },
                ])),
                Section::PathNodes(PathNodes(vec![
                    PackedNode {
                        pk: gen_keypair().0,
                        saddr: "1.2.3.4:1234".parse().unwrap(),
                    },
                    PackedNode {
                        pk: gen_keypair().0,
                        saddr: "1.2.3.5:1235".parse().unwrap(),
                    },
                ])),
            ],
            eof: Eof,
        }
    );
}
