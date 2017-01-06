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
