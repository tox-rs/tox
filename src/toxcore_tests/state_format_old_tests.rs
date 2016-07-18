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

// SectionKind::from_bytes()

#[test]
fn section_kind_from_bytes_test() {
    // test only for failure, since success is tested in docs test
    fn with_bytes(bytes: Vec<u8>) {
        if !bytes.is_empty() {
            if bytes[0] < 7 || bytes[0] == 10 ||
               bytes[0] == 11 || bytes[0] == 255 {
                return
            }
        }
        assert_eq!(None, SectionKind::from_bytes(&bytes));
    }
    quickcheck(with_bytes as fn(Vec<u8>));
}

// SectionKind::parse_bytes()

#[test]
fn section_kind_parse_bytes_rest_test() {
    fn with_bytes(sk: SectionKind, r_rest: Vec<u8>) {
        let mut bytes = vec![sk as u8];
        bytes.extend_from_slice(&r_rest);

        let Parsed(_, rest) = SectionKind::parse_bytes(&bytes)
            .expect("SectionKind parsing failure.");
        assert_eq!(&r_rest[..], rest);
    }
    quickcheck(with_bytes as fn(SectionKind, Vec<u8>));
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

            assert_eq!(&bytes[..NOSPAMBYTES], &*nsk.nospam);

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


// Name::parse_bytes()

#[test]
fn name_parse_bytes_test() {
    fn with_bytes(bytes: Vec<u8>) {
        let Parsed(name, remaining_bytes) = Name::parse_bytes(&bytes)
            .expect("Name::parse_bytes can't fail!");
        if bytes.len() > NAME_LEN {
            assert_eq!(name.0.as_slice(), &bytes[..NAME_LEN]);
            assert_eq!(&bytes[NAME_LEN..], remaining_bytes);
        } else {
            assert_eq!(&name.0, &bytes);
            assert_eq!(0, remaining_bytes.len());
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));
}
