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

use num_traits::identities::Zero;
use super::quickcheck::{quickcheck, TestResult};

use toxcore::binary_io::*;


fn u16_to_array_and_back(num: u16) {
    assert_eq!(num, array_to_u16(&u16_to_array(num)));
}

fn u32_to_array_and_back(num: u32) {
    assert_eq!(num, array_to_u32(&u32_to_array(num)));
}

fn u64_to_array_and_back(num: u64) {
    assert_eq!(num, array_to_u64(&u64_to_array(num)));
}


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
                assert_eq!(&vec![Zero::zero(); len - bytes.len()] as &[$num],
                           &bc[bytes.len()..]);
                TestResult::passed()
            }
            quickcheck(with_bytes as fn(Vec<$num>, usize) -> TestResult);
        }
    )+)
}
test_append_zeros_for!(
    u8, append_zeros_test_u8_fail, append_zeros_test_u8_pass,
    u16, append_zeros_test_u16_fail, append_zeros_test_u16_pass,
    u32, append_zeros_test_u32_fail, append_zeros_test_u32_pass,
    u64, append_zeros_test_u64_fail, append_zeros_test_u64_pass
);

#[test]
fn array_to_u16_test() {
    assert_eq!(array_to_u16(&[0, 0]), 0);
    assert_eq!(array_to_u16(&[1, 0]), 1);
    assert_eq!(array_to_u16(&[0, 1]), 256);
    assert_eq!(array_to_u16(&[1, 1]), 257);
    assert_eq!(array_to_u16(&[255, 255]), 65535);

    quickcheck(u16_to_array_and_back as fn(u16));
}

#[test]
fn u16_to_array_test() {
    assert_eq!([0, 0], u16_to_array(0));
    assert_eq!([1, 0], u16_to_array(1));
    assert_eq!([0, 1], u16_to_array(256));
    assert_eq!([255, 255], u16_to_array(65535));

    quickcheck(u16_to_array_and_back as fn(u16));
}

#[test]
fn array_to_u32_test() {
    assert_eq!(array_to_u32(&[0, 0, 0, 0]), 0);
    assert_eq!(array_to_u32(&[1, 0, 0, 0]), 1);
    assert_eq!(array_to_u32(&[0, 1, 0, 0]), 256);
    assert_eq!(array_to_u32(&[0, 0, 1, 0]), 65536);
    assert_eq!(array_to_u32(&[0, 0, 0, 1]), 16777216);
    assert_eq!(array_to_u32(&[0, 0, 0, 0xff]), 4278190080);
    assert_eq!(array_to_u32(&[0xff, 0xff, 0xff, 0xff]), u32::max_value());

    quickcheck(u32_to_array_and_back as fn(u32));
}

#[test]
fn u32_to_array_test() {
    assert_eq!([0, 0, 0, 0], u32_to_array(0));
    assert_eq!([1, 0, 0, 0], u32_to_array(1));
    assert_eq!([0, 1, 0, 0], u32_to_array(256));
    assert_eq!([0, 0, 1, 0], u32_to_array(65536));
    assert_eq!([0, 0, 0, 1], u32_to_array(16777216));
    assert_eq!([0, 0, 0, 0xff], u32_to_array(4278190080));
    assert_eq!([0xff, 0xff, 0xff, 0xff], u32_to_array(u32::max_value()));

    quickcheck(u32_to_array_and_back as fn(u32));
}

#[test]
fn array_to_u64_test() {
    assert_eq!(array_to_u64(&[0, 0, 0, 0, 0, 0, 0, 0]), 0);
    assert_eq!(array_to_u64(&[1, 0, 0, 0, 0, 0, 0, 0]), 1);
    assert_eq!(array_to_u64(&[0, 1, 0, 0, 0, 0, 0, 0]), 256);
    assert_eq!(array_to_u64(&[0, 0, 1, 0, 0, 0, 0, 0]), 65536);
    assert_eq!(array_to_u64(&[0, 0, 0, 1, 0, 0, 0, 0]), 16777216);
    assert_eq!(array_to_u64(&[0, 0, 0, 0, 1, 0, 0, 0]), 4294967296);
    assert_eq!(array_to_u64(&[0, 0, 0, 0, 0, 1, 0, 0]), 1099511627776);
    assert_eq!(array_to_u64(&[0, 0, 0, 0, 0, 0, 1, 0]), 281474976710656);
    assert_eq!(array_to_u64(&[0, 0, 0, 0, 0, 0, 0, 1]), 72057594037927936);
    assert_eq!(array_to_u64(&[0, 0, 0, 0, 0, 0, 0, 0xff]), 18374686479671623680);
    assert_eq!(array_to_u64(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), u64::max_value());

    quickcheck(u64_to_array_and_back as fn(u64));
}

#[test]
fn u64_to_array_test() {
    assert_eq!([0, 0, 0, 0, 0, 0, 0, 0], u64_to_array(0));
    assert_eq!([1, 0, 0, 0, 0, 0, 0, 0], u64_to_array(1));
    assert_eq!([0, 1, 0, 0, 0, 0, 0, 0], u64_to_array(256));
    assert_eq!([0, 0, 1, 0, 0, 0, 0, 0], u64_to_array(65536));
    assert_eq!([0, 0, 0, 1, 0, 0, 0, 0], u64_to_array(16777216));
    assert_eq!([0, 0, 0, 0, 1, 0, 0, 0], u64_to_array(4294967296));
    assert_eq!([0, 0, 0, 0, 0, 1, 0, 0], u64_to_array(1099511627776));
    assert_eq!([0, 0, 0, 0, 0, 0, 1, 0], u64_to_array(281474976710656));
    assert_eq!([0, 0, 0, 0, 0, 0, 0, 1], u64_to_array(72057594037927936));
    assert_eq!([0, 0, 0, 0, 0, 0, 0, 0xff], u64_to_array(18374686479671623680));
    assert_eq!([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], u64_to_array(u64::max_value()));

    quickcheck(u64_to_array_and_back as fn(u64));
}


// xor_checksum()

#[test]
fn xor_checksum_test() {
    assert_eq!([0; 2], xor_checksum(&[0; 2], &[0; 2]));
    assert_eq!([1; 2], xor_checksum(&[1; 2], &[0; 2]));
    assert_eq!([0; 2], xor_checksum(&[1; 2], &[1; 2]));
    assert_eq!([255; 2], xor_checksum(&[255; 2], &[0; 2]));
    assert_eq!([0; 2], xor_checksum(&[255; 2], &[255; 2]));

    fn with_numbers(a: u8, b: u8, c: u8, d: u8) {
        let x = xor_checksum(&[a, b], &[c, d]);
        assert_eq!(x[0], a ^ c);
        assert_eq!(x[1], b ^ d);
    }
    quickcheck(with_numbers as fn(u8, u8, u8, u8));
}
