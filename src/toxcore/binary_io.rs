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

#[cfg(test)]
use quickcheck::quickcheck;


/// Safely cast `[u8; 2]` to `u16` using shift+or.
pub fn slice_to_u16(slice: &[u8; 2]) -> u16 {
    let mut result: u16 = 0;
    for byte in 0..slice.len() {
        result = result << 8;
        result = result | slice[1 - byte] as u16;
    }
    result
}

#[test]
fn slice_to_u16_test() {
    assert_eq!(slice_to_u16(&[0, 0]), 0);
    assert_eq!(slice_to_u16(&[1, 0]), 1);
    assert_eq!(slice_to_u16(&[0, 1]), 256);
    assert_eq!(slice_to_u16(&[1, 1]), 257);
    assert_eq!(slice_to_u16(&[255, 255]), 65535);

    fn to_slice_and_back(num: u16) {
        assert!(num == slice_to_u16(&u16_to_slice(num)));
    }
    quickcheck(to_slice_and_back as fn(u16));
}

/// Safely cast `u16` to `[u8; 2]`.
pub fn u16_to_slice(num: u16) -> [u8; 2] {
    let mut array: [u8; 2] = [0; 2];
    for n in 0..array.len() {
        array[n] = (num >> (8 * n)) as u8;
    }
    array
}

#[test]
fn u16_to_slice_test() {
    assert_eq!([0, 0], u16_to_slice(0));
    assert_eq!([1, 0], u16_to_slice(1));
    assert_eq!([0, 1], u16_to_slice(256));
    assert_eq!([255, 255], u16_to_slice(65535));

    fn to_slice_and_back(num: u16) {
        assert!(num == slice_to_u16(&u16_to_slice(num)));
    }
    quickcheck(to_slice_and_back as fn(u16));
}

/// Safely cast `&[u8; 4]` to `u32`.
pub fn slice_to_u32(slice: &[u8; 4]) -> u32 {
    let mut result: u32 = 0;
    for byte in 0..slice.len() {
        result = result << 8;
        result = result | slice[3 - byte] as u32;
    }
    result
}

#[test]
fn slice_to_u32_test() {
    assert_eq!(slice_to_u32(&[0, 0, 0, 0]), 0);
    assert_eq!(slice_to_u32(&[1, 0, 0, 0]), 1);
    assert_eq!(slice_to_u32(&[0, 1, 0, 0]), 256);
    assert_eq!(slice_to_u32(&[0, 0, 1, 0]), 65536);
    assert_eq!(slice_to_u32(&[0, 0, 0, 1]), 16777216);
    assert_eq!(slice_to_u32(&[0, 0, 0, 0xff]), 4278190080);
    assert_eq!(slice_to_u32(&[0xff, 0xff, 0xff, 0xff]), u32::max_value());

    fn u32_to_slice(num: u32) -> [u8; 4] {
        let mut array: [u8; 4] = [0; 4];
        for n in 0..array.len() {
            array[n] = (num >> (8 * n)) as u8;
        }
        array
    }

    fn to_slice_and_back(num: u32) {
        assert!(num == slice_to_u32(&u32_to_slice(num)));
    }
    quickcheck(to_slice_and_back as fn(u32));
}


/// Safely cast `&[u8; 8]` to `u64`.
pub fn slice_to_u64(slice: &[u8; 8]) -> u64 {
    let mut result: u64 = 0;
    for byte in 0..slice.len() {
        result = result << 8;
        result = result | slice[7 - byte] as u64;
    }
    result
}

#[test]
fn slice_to_u64_test() {
    assert_eq!(slice_to_u64(&[0, 0, 0, 0, 0, 0, 0, 0]), 0);
    assert_eq!(slice_to_u64(&[1, 0, 0, 0, 0, 0, 0, 0]), 1);
    assert_eq!(slice_to_u64(&[0, 1, 0, 0, 0, 0, 0, 0]), 256);
    assert_eq!(slice_to_u64(&[0, 0, 1, 0, 0, 0, 0, 0]), 65536);
    assert_eq!(slice_to_u64(&[0, 0, 0, 1, 0, 0, 0, 0]), 16777216);
    assert_eq!(slice_to_u64(&[0, 0, 0, 0, 1, 0, 0, 0]), 4294967296);
    assert_eq!(slice_to_u64(&[0, 0, 0, 0, 0, 1, 0, 0]), 1099511627776);
    assert_eq!(slice_to_u64(&[0, 0, 0, 0, 0, 0, 1, 0]), 281474976710656);
    assert_eq!(slice_to_u64(&[0, 0, 0, 0, 0, 0, 0, 1]), 72057594037927936);
    assert_eq!(slice_to_u64(&[0, 0, 0, 0, 0, 0, 0, 0xff]), 18374686479671623680);
    assert_eq!(slice_to_u64(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), u64::max_value());

    fn u64_to_slice(num: u64) -> [u8; 8] {
        let mut array: [u8; 8] = [0; 8];
        for n in 0..array.len() {
            array[n] = (num >> (8 * n)) as u8;
        }
        array
    }

    fn to_slice_and_back(num: u64) {
        assert!(num == slice_to_u64(&u64_to_slice(num)));
    }
    quickcheck(to_slice_and_back as fn(u64));
}
