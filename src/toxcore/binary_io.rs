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


/// Serialization into bytes.
pub trait ToBytes {
    /// Serialize into bytes.
    fn to_bytes(&self) -> Vec<u8>;
}

/// Parsing result. Provides result and remaining input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Parsed<'a, Output>(
    /// Result.
    pub Output,
    /// Remaining input.
    pub &'a [u8]
);

/// Parsing error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseError{
    target: &'static str,
    message: String,
    file: &'static str,
    line: u32
}

impl ParseError {
    /// Create new ParseError
    pub fn new(target: &'static str, message: String,
           file: &'static str, line: u32) -> ParseError {
        ParseError{
            target: target,
            message: message,
            file: file,
            line: line
        }
    }
}

macro_rules! parse_error {
    (target: $target:expr, $($arg:tt)*) => (
        Err(ParseError::new(
                $target,
                format!($($arg)*),
                file!(),
                line!()))
    );
    ($($arg:tt)*) => (parse_error!(target: module_path!(), $($arg)*))
}

/// Result type for parsing methods
pub type ParseResult<'a, Output> = Result<Parsed<'a, Output>, ParseError>;

/// Methods for de-serialization from bytes
// TODO: remove Option<T> types in favour of reworking `ParseResult` into a
//       real™ `Result` that could be just `ok()`d
pub trait FromBytes: Sized {

    /// De-serialize from bytes.
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self>;

    /** De-serialize exact `times` entities from bytes.

    Note that even if `Vec<_>` is returned, it still can be empty.
    */
    fn parse_bytes_multiple_n(times: usize, bytes: &[u8]) -> ParseResult<Vec<Self>> {
        debug!("De-serializing multiple ({}) outputs.", times);
        trace!("With bytes: {:?}", bytes);

        let mut bytes = bytes;
        let mut result = Vec::with_capacity(times);

        for _ in 0..times {
            let Parsed(value, rest) = try!(Self::parse_bytes(bytes));
            bytes = rest;
            result.push(value);
        }

        Ok(Parsed(result, bytes))
    }

    /** De-serialize as many entities from bytes as posible.

    Note that even if `Vec<_>` is returned, it still can be empty.
    */
    fn parse_bytes_multiple(bytes: &[u8]) -> ParseResult<Vec<Self>> {
        debug!("De-serializing multiple outputs.");
        trace!("With bytes: {:?}", bytes);

        let mut bytes = bytes;
        let mut result = Vec::new();

        while let Ok(Parsed(value, rest)) = Self::parse_bytes(bytes) {
            bytes = rest;
            result.push(value);
        }

        Ok(Parsed(result, bytes))
    }
    /// De-serialize from bytes, or return `None` if de-serialization failed.
    /// Note: `Some` is returned even if there are remaining bytes left.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match Self::parse_bytes(bytes) {
            Ok(Parsed(value, _)) => Some(value),
            Err(err) => {
                debug!("Can't parse bytes. Error: {:?}", err);
                None
            }
        }
    }
}


// TODO: refactor ↓ using macros?

/// Safely cast `[u8; 2]` to `u16` using shift+or.
pub fn array_to_u16(array: &[u8; 2]) -> u16 {
    trace!("Casting array to u16 from array: {:?}", array);
    let mut result: u16 = 0;
    for pos in 0..array.len() {
        result <<= 8;
        result |= array[1 - pos] as u16;
    }
    result
}

/// Safely cast `u16` to `[u8; 2]`.
pub fn u16_to_array(num: u16) -> [u8; 2] {
    trace!("Casting u16 to array from u16: {}", num);
    let mut array: [u8; 2] = [0; 2];
    for (pos, item) in array.iter_mut().enumerate() {
        *item = (num >> (8 * pos)) as u8;
    }
    array
}


/// Safely cast `&[u8; 4]` to `u32`.
pub fn array_to_u32(array: &[u8; 4]) -> u32 {
    trace!("Casting array to u32 from array: {:?}", array);
    let mut result: u32 = 0;
    for pos in 0..array.len() {
        result <<= 8;
        result |= array[3 - pos] as u32;
    }
    result
}

/// Safely cast `u32` to `[u8; 4]`.
pub fn u32_to_array(num: u32) -> [u8; 4] {
    let mut array: [u8; 4] = [0; 4];
    for (pos, item) in array.iter_mut().enumerate() {
        *item = (num >> (8 * pos)) as u8;
    }
    array
}

/// Safely cast `&[u8; 8]` to `u64`.
pub fn array_to_u64(array: &[u8; 8]) -> u64 {
    trace!("Casting array to u64 from array: {:?}", array);
    let mut result: u64 = 0;
    for pos in 0..array.len() {
        result <<= 8;
        result |= array[7 - pos] as u64;
    }
    result
}

/// Safely cast `u64` to `[u8; 8]`
pub fn u64_to_array(num: u64) -> [u8; 8] {
    trace!("Casting u64 to array from u64: {}", num);
    let mut array: [u8; 8] = [0; 8];
    for (pos, item) in array.iter_mut().enumerate() {
        *item = (num >> (8 * pos)) as u8;
    }
    array
}


/** Calculate XOR checksum for 2 [u8; 2].

    Used for calculating checksum of ToxId.

    https://zetok.github.io/tox-spec/#messenger , 7th paragraph.
*/
pub fn xor_checksum(lhs: &[u8; 2], rhs: &[u8; 2]) -> [u8; 2] {
    [lhs[0] ^ rhs[0], lhs[1] ^ rhs[1]]
}
