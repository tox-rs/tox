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

//! Functions for binary IO.

/// Convert `&[u8; 4]` to `u32`.
pub fn slice_to_u32(slice: &[u8; 4]) -> u32 {
    let mut result: u32 = 0;
    for byte in 0..slice.len() {
        result = result << 8;
        result = result | slice[byte] as u32;
    }
    result
}

#[test]
fn slice_to_u32_test() {
    assert_eq!(slice_to_u32(&[0, 0, 0, 0]), 0);
    assert_eq!(slice_to_u32(&[0, 0, 0, 1]), 1);
    assert_eq!(slice_to_u32(&[0, 0, 1, 0]), 256);
    assert_eq!(slice_to_u32(&[0, 1, 0, 0]), 65536);
    assert_eq!(slice_to_u32(&[1, 0, 0, 0]), 16777216);
    assert_eq!(slice_to_u32(&[0xff, 0, 0, 0]), 4278190080);
    assert_eq!(slice_to_u32(&[0xff, 0xff, 0xff, 0xff]), u32::max_value());
}


/// Convert `&[u8; 8]` to `u64`.
pub fn slice_to_u64(slice: &[u8; 8]) -> u64 {
    let mut result: u64 = 0;
    for byte in 0..slice.len() {
        result = result << 8;
        result = result | slice[byte] as u64;
    }
    result
}

#[test]
fn slice_to_u64_test() {
    assert_eq!(slice_to_u64(&[0, 0, 0, 0, 0, 0, 0, 0]), 0);
    assert_eq!(slice_to_u64(&[0, 0, 0, 0, 0, 0, 0, 1]), 1);
    assert_eq!(slice_to_u64(&[0, 0, 0, 0, 0, 0, 1, 0]), 256);
    assert_eq!(slice_to_u64(&[0, 0, 0, 0, 0, 1, 0, 0]), 65536);
    assert_eq!(slice_to_u64(&[0, 0, 0, 0, 1, 0, 0, 0]), 16777216);
    assert_eq!(slice_to_u64(&[0, 0, 0, 1, 0, 0, 0, 0]), 4294967296);
    assert_eq!(slice_to_u64(&[0, 0, 1, 0, 0, 0, 0, 0]), 1099511627776);
    assert_eq!(slice_to_u64(&[0, 1, 0, 0, 0, 0, 0, 0]), 281474976710656);
    assert_eq!(slice_to_u64(&[1, 0, 0, 0, 0, 0, 0, 0]), 72057594037927936);
    assert_eq!(slice_to_u64(&[0xff, 0, 0, 0, 0, 0, 0, 0]), 18374686479671623680);
    assert_eq!(slice_to_u64(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), u64::max_value());
}
