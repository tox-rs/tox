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


/// Safely cast `[u8; 2]` to `u16` using shift+or.
pub fn slice_to_u16(slice: &[u8; 2]) -> u16 {
    let mut result: u16 = 0;
    for byte in 0..slice.len() {
        result = result << 8;
        result = result | slice[1 - byte] as u16;
    }
    result
}

/// Safely cast `u16` to `[u8; 2]`.
pub fn u16_to_slice(num: u16) -> [u8; 2] {
    let mut array: [u8; 2] = [0; 2];
    for n in 0..array.len() {
        array[n] = (num >> (8 * n)) as u8;
    }
    array
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


/// Safely cast `&[u8; 8]` to `u64`.
pub fn slice_to_u64(slice: &[u8; 8]) -> u64 {
    let mut result: u64 = 0;
    for byte in 0..slice.len() {
        result = result << 8;
        result = result | slice[7 - byte] as u64;
    }
    result
}
