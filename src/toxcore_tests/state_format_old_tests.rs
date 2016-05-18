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
