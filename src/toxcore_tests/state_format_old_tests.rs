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

//! Tests for old state format module.

use super::quickcheck::{Arbitrary, Gen, TestResult, quickcheck};

use toxcore::binary_io::*;
use toxcore::dht::*;
use toxcore::crypto_core::*;
use toxcore::toxid::*;
use toxcore::state_format::old::*;

// SectionKind::

impl Arbitrary for SectionKind {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        *g.choose(&[SectionKind::NospamKeys,
                   SectionKind::DHT,
                   SectionKind::Friends,
                   SectionKind::Name,
                   SectionKind::StatusMsg,
                   SectionKind::Status,
                   SectionKind::TcpRelays,
                   SectionKind::PathNodes,
                   SectionKind::EOF])
            .unwrap()
    }
}

// SectionKind::parse_bytes()

#[test]
fn section_kind_parse_bytes_test() {
    // test only for failure, since success is tested in docs test
    fn with_bytes(bytes: Vec<u8>) -> TestResult {
        fn assert_kind(b: &[u8], k: SectionKind) {
            let Parsed(kind, _) = SectionKind::parse_bytes(&b)
                .expect(&format!("Failed to parse as {:?}!", k));
            assert_eq!(k, kind);
        }

        if bytes.len() < 2 {
            return TestResult::discard()
        }

        match (bytes[0], bytes[1]) {
            (1, 0) => assert_kind(&bytes, SectionKind::NospamKeys),
            (2, 0) => assert_kind(&bytes, SectionKind::DHT),
            (3, 0) => assert_kind(&bytes, SectionKind::Friends),
            (4, 0) => assert_kind(&bytes, SectionKind::Name),
            (5, 0) => assert_kind(&bytes, SectionKind::StatusMsg),
            (6, 0) => assert_kind(&bytes, SectionKind::Status),
            (10, 0) => assert_kind(&bytes, SectionKind::TcpRelays),
            (11, 0) => assert_kind(&bytes, SectionKind::PathNodes),
            (255, 0) => assert_kind(&bytes, SectionKind::EOF),
            (_, _) => assert_eq!(None, SectionKind::from_bytes(&bytes)),
        }
        TestResult::passed()
    }
    quickcheck(with_bytes as fn(Vec<u8>) -> TestResult);

    // correct
    with_bytes(vec![1, 0]);
    with_bytes(vec![2, 0]);
    with_bytes(vec![3, 0]);
    with_bytes(vec![4, 0]);
    with_bytes(vec![5, 0]);
    with_bytes(vec![6, 0]);
    with_bytes(vec![10, 0]);
    with_bytes(vec![11, 0]);
    with_bytes(vec![255, 0]);

}

#[test]
fn section_kind_parse_bytes_rest_test() {
    fn with_bytes(sk: SectionKind, r_rest: Vec<u8>) {
        let sk = u16_to_array((sk as u16).to_le());
        let mut bytes = Vec::with_capacity(r_rest.len() + 2);
        bytes.extend_from_slice(&sk);
        bytes.extend_from_slice(&r_rest);

        let Parsed(_, rest) = SectionKind::parse_bytes(&bytes)
            .expect("SectionKind parsing failure.");
        assert_eq!(&r_rest[..], rest);
    }
    quickcheck(with_bytes as fn(SectionKind, Vec<u8>));
}

// SectionKind::to_bytes()
#[test]
fn section_kind_to_bytes_test() {
    fn with_kind(sk: SectionKind) {
        assert_eq!(Some(sk), SectionKind::from_bytes(&sk.to_bytes()));
    }
    quickcheck(with_kind as fn(SectionKind));
}


// NospamKeys::

impl Arbitrary for NospamKeys {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let mut ns = [0; NOSPAMBYTES];
        let mut pk = [0; PUBLICKEYBYTES];
        let mut sk = [0; SECRETKEYBYTES];
        g.fill_bytes(&mut ns);
        g.fill_bytes(&mut pk);
        g.fill_bytes(&mut sk);
        NospamKeys {
            nospam: NoSpam(ns),
            pk: PublicKey(pk),
            sk: SecretKey(sk),
        }
    }
}

// NospamKeys::default()

#[test]
fn nospam_keys_default_test() {
    let nsk1 = NospamKeys::default();

    // is not filled with `0`s
    assert!(nsk1.nospam.0 != [0u8; NOSPAMBYTES]);
    assert!(nsk1.pk.0 != [0u8; PUBLICKEYBYTES]);
    assert!(nsk1.sk.0 != [0u8; SECRETKEYBYTES]);

    // different each time it's generated
    let nsk2 = NospamKeys::default();
    assert!(nsk1 != nsk2);
}

// NospamKeys::from_bytes()

#[test]
fn nospam_keys_from_bytes_test() {
    fn with_bytes(bytes: Vec<u8>) {
        if bytes.len() < NOSPAMKEYSBYTES {
            assert_eq!(None, NospamKeys::from_bytes(&bytes));
        } else {
            let nsk: NospamKeys = NospamKeys::from_bytes(&bytes)
                                .expect("Failed to unwrap NospamKeys!");

            assert_eq!(&bytes[..NOSPAMBYTES], &nsk.nospam.0);

            let PublicKey(ref pk) = nsk.pk;
            assert_eq!(&bytes[NOSPAMBYTES..NOSPAMBYTES + PUBLICKEYBYTES], pk);

            let SecretKey(ref sk) = nsk.sk;
            assert_eq!(&bytes[NOSPAMBYTES + PUBLICKEYBYTES..NOSPAMKEYSBYTES], sk);
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));
}

// NospamKeys::parse_bytes()

#[test]
fn nospam_keys_parse_bytes_rest_test() {
    // FIXME usee NospamKeys::to_bytes after implementation
    fn with_bytes(bytes: Vec<u8>) -> TestResult {
        if let Ok(Parsed(_, rest)) = NospamKeys::parse_bytes(&bytes) {
            assert_eq!(&bytes[NOSPAMKEYSBYTES..], rest);
            TestResult::passed()
        } else {
            TestResult::discard()
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>) -> TestResult);
}


// DhtState::

impl_arb_for_pn!(DhtState);

// DhtState::from_bytes()

#[test]
fn dht_state_from_bytes() {
    fn with_packed_nodes(pns: Vec<PackedNode>) {
        let pns_bytes: Vec<u8> = {
            let mut bytes = vec![];
            for pn in &pns {
                bytes.extend_from_slice(&pn.to_bytes());
            }
            bytes
        };
        // first magic number
        let mut serialized = vec![0x0d, 0x00, 0x59, 0x01];
        // length of `PackedNode`s that are serialized
        serialized.extend_from_slice(
                &u32_to_array((pns_bytes.len() as u32).to_le()));
        // other magic numbers
        serialized.extend_from_slice(&[0x04, 0, 0xce, 0x11]);
        serialized.extend_from_slice(&pns_bytes);

        { // check if de-serialized result is same as the input
            let DhtState(dpns) = DhtState::from_bytes(&serialized)
                    .expect("Failed to de-serialize DhtState!");

            assert_eq!(pns, dpns);
        }

        // check if fails to de-serialize with wrong magic number
        for pos in [0, 1, 2, 3, 8, 9, 10, 11].into_iter() {
            let mut s = serialized.clone();
            if *pos == 1 || *pos == 9 { s[*pos] = 0xff; } else { s[*pos] = 0; }
            assert_eq!(None, DhtState::from_bytes(&s));
        }
    }
    quickcheck(with_packed_nodes as fn(Vec<PackedNode>));
}

// DhtState::parse_bytes()

#[test]
fn dht_state_parse_bytes_rest_test() {
    fn with_packed_nodes(pns: Vec<PackedNode>, r_rest: Vec<u8>) {
        let pns_bytes: Vec<u8> = {
            let mut bytes = vec![];
            for pn in &pns {
                bytes.extend_from_slice(&pn.to_bytes());
            }
            bytes
        };
        // first magic number
        let mut serialized = vec![0x0d, 0x00, 0x59, 0x01];
        // length of `PackedNode`s that are serialized
        serialized.extend_from_slice(
                &u32_to_array((pns_bytes.len() as u32).to_le()));
        // other magic numbers
        serialized.extend_from_slice(&[0x04, 0, 0xce, 0x11]);
        serialized.extend_from_slice(&pns_bytes);
        serialized.extend_from_slice(&r_rest);

        let Parsed(_, rest) =
            DhtState::parse_bytes(&serialized)
                .expect("DhtState parsing failure.");

        assert_eq!(&r_rest[..], rest);
    }
    quickcheck(with_packed_nodes as fn(Vec<PackedNode>, Vec<u8>));
}

// DhtState::to_bytes()

#[test]
fn dht_state_to_bytes_test() {
    fn with_packed_nodes(pns: Vec<PackedNode>) {
        let dstate = DhtState::from_bytes(&DhtState(pns.clone())
                .to_bytes())
                .expect("Failed to de-serialize DhtState!");
        assert_eq!(dstate.0, pns);
    }
    quickcheck(with_packed_nodes as fn(Vec<PackedNode>));
}

// FriendStatus::

impl Arbitrary for FriendStatus {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        *g.choose(&[FriendStatus::NotFriend,
                   FriendStatus::Added,
                   FriendStatus::FrSent,
                   FriendStatus::Confirmed,
                   FriendStatus::Online])
            .unwrap()
    }
}

// FriendStatus::parse_bytes()

#[test]
fn friend_status_parse_bytes_rest_test() {
    fn with_bytes(sk: FriendStatus, r_rest: Vec<u8>) {
        let mut bytes = vec![sk as u8];
        bytes.extend_from_slice(&r_rest);

        let Parsed(_, rest) = FriendStatus::parse_bytes(&bytes)
            .expect("FriendStatus parsing failure.");
        assert_eq!(&r_rest[..], rest);
    }
    quickcheck(with_bytes as fn(FriendStatus, Vec<u8>));
}


// Friends::

// Friends::parse_bytes()
#[test]
fn friends_parse_bytes_test() {
    fn with_friend_state(fs: Vec<FriendState>, randb: Vec<u8>) {
        let mut bytes = Vec::new();
        for fr in &fs {
            bytes.append(&mut fr.to_bytes());
        }

        { // just the needed bytes, no more, no less
            let Parsed(friends, b) = Friends::parse_bytes(&bytes).expect("");
            assert_eq!(&fs, &friends.0);
            assert_eq!(&[] as &[u8], b); // empty
        }

        { // with random bytes appended
            let mut bytes = bytes.clone();
            bytes.extend_from_slice(&randb);
            let Parsed(friends, b) = Friends::parse_bytes(&bytes).expect("");
            assert_eq!(&fs, &friends.0);
            assert_eq!(randb.as_slice(), b);
        }
    }
    quickcheck(with_friend_state as fn(Vec<FriendState>, Vec<u8>));
}

// Friends::to_bytes()

#[test]
fn friends_to_bytes_test() {
    fn with_friends(fs: Vec<FriendState>) {
        let mut bytes = Vec::new();
        for f in &fs {
            bytes.append(&mut f.to_bytes());
        }
        assert_eq!(bytes, Friends(fs).to_bytes());
    }
    quickcheck(with_friends as fn(Vec<FriendState>));
}


// UserStatus::

impl Arbitrary for UserStatus {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        *g.choose(&[UserStatus::Online,
                   UserStatus::Away,
                   UserStatus::Busy])
            .unwrap()
    }
}

// UserStatus::parse_bytes()

#[test]
fn user_status_parse_bytes_test_rest() {
    fn with_bytes(sk: UserStatus, r_rest: Vec<u8>) {
        let mut bytes = vec![sk as u8];
        bytes.extend_from_slice(&r_rest);

        let Parsed(_, rest) = UserStatus::parse_bytes(&bytes)
            .expect("UserStatus parsing failure.");
        assert_eq!(&r_rest[..], rest);
    }
    quickcheck(with_bytes as fn(UserStatus, Vec<u8>));
}



// Name::

impl_arb_for_bytes!(Name, NAME_LEN);

// Name::parse_bytes()

#[test]
// TODO: make test more generic, so that both `Name` and `StatusMsg` could use
//       it
fn name_parse_bytes_test() {
    fn with_bytes(b: Vec<u8>) -> TestResult {
        // empty case is tested, and if quickcheck provides it test will break
        if b.is_empty() { return TestResult::discard() }

        let mut bytes = b.clone();
        if bytes.len() < NAME_LEN {
            // as many times as needed to be > NAME_LEN
            for _ in 0..((NAME_LEN/bytes.len())+1) {
                bytes.extend_from_slice(&b);
            }
        }

        for n in 0..bytes.len() {
            let bytes = &bytes[..n];
            let Parsed(name, remaining_bytes) = Name::parse_bytes(bytes)
                .expect("Name::parse_bytes can't fail!");

            if n <= NAME_LEN {
                assert_eq!(name.0.as_slice(), bytes);
                // TODO: remove `as &[u8]` when Rust RFC 803 gets fully
                //       implemented on ~stable - 1
                //       https://github.com/rust-lang/rust/issues/23416
                assert_eq!(&[] as &[u8], remaining_bytes); // empty
            } else if n > NAME_LEN {
                assert_eq!(name.0.as_slice(), &bytes[..NAME_LEN]);
                assert_eq!(&bytes[NAME_LEN..], remaining_bytes);
            }
        }
        TestResult::passed()
    }
    quickcheck(with_bytes as fn(Vec<u8>) -> TestResult);
}


// StatusMsg::

impl_arb_for_bytes!(StatusMsg, STATUS_MSG_LEN);

// StatusMsg::parse_bytes()

#[test]
// TODO: make test more generic, so that both `Name` and `StatusMsg` could use
//       it
fn status_message_parse_bytes_test() {
    fn with_bytes(b: Vec<u8>) -> TestResult {
        // empty case is tested, and if quickcheck provides it test will break
        if b.is_empty() { return TestResult::discard() }

        let mut bytes = b.clone();
        if bytes.len() < STATUS_MSG_LEN {
            // as many times as needed to be > STATUS_MSG_LEN
            for _ in 0..((STATUS_MSG_LEN/bytes.len())+1) {
                bytes.extend_from_slice(&b);
            }
        }

        for n in 0..bytes.len() {
            let bytes = &bytes[..n];
            let Parsed(name, remaining_bytes) = StatusMsg::parse_bytes(bytes)
                .expect("StatusMsg::parse_bytes can't fail!");

            if n <= STATUS_MSG_LEN {
                assert_eq!(name.0.as_slice(), bytes);
                // TODO: remove `as &[u8]` when Rust RFC 803 gets fully
                //       implemented on ~stable - 1
                //       https://github.com/rust-lang/rust/issues/23416
                assert_eq!(&[] as &[u8], remaining_bytes); // empty
            } else if n > STATUS_MSG_LEN {
                assert_eq!(name.0.as_slice(), &bytes[..STATUS_MSG_LEN]);
                assert_eq!(&bytes[STATUS_MSG_LEN..], remaining_bytes);
            }
        }
        TestResult::passed()
    }
    quickcheck(with_bytes as fn(Vec<u8>) -> TestResult);
}
