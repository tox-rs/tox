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

use num_traits::identities::Zero;

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


/// Append `0`s to given bytes up to `len`. Panics if `len` is smaller than
/// padded `Vec`.
pub fn append_zeros<T: Clone + Zero>(v: &mut Vec<T>, len: usize) {
    let l = v.len();
    v.append(&mut vec![T::zero(); len - l]);
}


/** Calculate XOR checksum for 2 [u8; 2].

    Used for calculating checksum of ToxId.

    https://zetok.github.io/tox-spec/#tox-id , 4th paragraph.
*/
pub fn xor_checksum(lhs: &[u8; 2], rhs: &[u8; 2]) -> [u8; 2] {
    [lhs[0] ^ rhs[0], lhs[1] ^ rhs[1]]
}
