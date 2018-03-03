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

//! Tests for `binary_io` module.

use byteorder::{NativeEndian, WriteBytesExt};
use nom::IResult;
use quickcheck::{quickcheck, TestResult};

use toxcore::binary_io::*;


// append_zeros()

macro_rules! test_append_zeros_for {
    ($($num:ty, $tname_f:ident, $tname_p:ident),+) => ($(
        #[test]
        #[should_panic]
        fn $tname_f() {
            fn with_bytes(bytes: Vec<$num>, len: usize) -> TestResult {
                if bytes.len() > len {
                    // this should nicely panic
                    append_zeros(&mut bytes.clone(), len);
                }
                TestResult::discard()
            }
            quickcheck(with_bytes as fn(Vec<$num>, usize) -> TestResult);
        }

        #[test]
        fn $tname_p() {
            fn with_bytes(bytes: Vec<$num>, len: usize) -> TestResult {
                if bytes.len() > len {
                    return TestResult::discard()
                }

                let mut bc = bytes.clone();
                append_zeros(&mut bc, len);
                assert_eq!(bytes[..], bc[..bytes.len()]);
                assert_eq!(&vec![0u8; len - bytes.len()] as &[$num],
                           &bc[bytes.len()..]);
                TestResult::passed()
            }
            quickcheck(with_bytes as fn(Vec<$num>, usize) -> TestResult);
        }
    )+)
}
test_append_zeros_for!(
    u8, append_zeros_test_u8_fail, append_zeros_test_u8_pass
);

// xor_checksum()

#[test]
fn xor_checksum_test() {
    assert_eq!([0; 2], xor_checksum(&[0; 2], &[0; 2]));
    assert_eq!([1; 2], xor_checksum(&[1; 2], &[0; 2]));
    assert_eq!([0; 2], xor_checksum(&[1; 2], &[1; 2]));
    assert_eq!([255; 2], xor_checksum(&[255; 2], &[0; 2]));
    assert_eq!([0; 2], xor_checksum(&[255; 2], &[255; 2]));

    fn with_numbers(a: u8, b: u8, c: u8, d: u8) {
        let checksum = xor_checksum(&[a, b], &[c, d]);
        assert_eq!(checksum[0], a ^ c);
        assert_eq!(checksum[1], b ^ d);
    }
    quickcheck(with_numbers as fn(u8, u8, u8, u8));
}

// ne_u64()

#[test]
fn ne_u64_test() {
    fn with_numbers(n: u64) {
        let mut v = Vec::new();
        v.write_u64::<NativeEndian>(n).unwrap();
        // TODO: remove `as &[u8]` when Rust RFC 803 gets fully
        //       implemented on ~stable - 1
        //       https://github.com/rust-lang/rust/issues/23416
        assert_eq!(ne_u64(&v), IResult::Done(&[] as &[u8], n));
    }
    quickcheck(with_numbers as fn(u64));
}
