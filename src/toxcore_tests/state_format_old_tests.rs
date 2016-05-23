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

use super::quickcheck::quickcheck;

use toxcore::binary_io::*;
use toxcore::dht::*;
use toxcore::crypto_core::*;
use toxcore::toxid::*;
use toxcore::state_format::old::*;

// SectionKind::from_bytes()

#[test]
fn section_kind_from_bytes_test() {
    // test only for failure, since success is tested in docs test
    fn with_bytes(bytes: Vec<u8>) {
        if bytes.is_empty() || bytes[0] < 7 || bytes[0] == 10 ||
           bytes[0] == 11 || bytes[0] == 255 {
            return
        }
        assert_eq!(None, SectionKind::from_bytes(&bytes));
    }
    quickcheck(with_bytes as fn(Vec<u8>));
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
            let (DhtState(dpns), num_bytes) = ToDhtState::from_bytes(&serialized)
                    .expect("Failed to de-serialize DhtState!");

            assert_eq!(num_bytes, serialized.len());
            assert_eq!(pns, dpns);
        }

        // check if fails to de-serialize with wrong magic number
        for pos in vec![0, 1, 2, 3, 8, 9, 10, 11] {
            let mut s = serialized.clone();
            if pos == 1 || pos == 9 { s[pos] = 0xff; } else { s[pos] = 0; }
            assert_eq!(None, ToDhtState::from_bytes(&s));
        }
    }
    quickcheck(with_packed_nodes as fn(Vec<PackedNode>));
}
