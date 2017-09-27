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

use byteorder::{ByteOrder, NativeEndian};
use nom::{IResult, Needed};
use num_traits::identities::Zero;

/// Serialization into bytes.
pub trait ToBytes {
    /// Serialize into bytes.
    fn to_bytes(&self) -> Vec<u8>;
}

/// Result type for parsing methods
pub type ParseResult<'a, Output> = IResult<&'a [u8], Output>;

/// De-serialization from bytes.
pub trait FromBytes: Sized {
    /// De-serialize from bytes.
    fn parse_bytes(bytes: &[u8]) -> ParseResult<Self>;

    /// De-serialize as many entities from bytes as posible.
    /// Note that even if `Vec<_>` is returned, it still can be empty.
    fn parse_bytes_multiple<'a>(bytes: &'a [u8]) -> ParseResult<Vec<Self>> {
        closure!(&'a [u8], many0!(Self::parse_bytes))(bytes)
    }

    /// De-serialize exact `times` entities from bytes.
    /// Note that even if `Vec<_>` is returned, it still can be empty.
    fn parse_bytes_multiple_n<'a>(bytes: &'a [u8], times: usize) -> ParseResult<Vec<Self>> {
        closure!(&'a [u8], many_m_n!(times, times, Self::parse_bytes))(bytes)
    }

    /// De-serialize from bytes, or return `None` if de-serialization failed.
    /// Note: `Some` is returned even if there are remaining bytes left.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match Self::parse_bytes(bytes) {
            IResult::Done(_, value) => Some(value),
            IResult::Error(err) => {
                debug!("Can't parse bytes. Error: {:?}", err);
                None
            },
            IResult::Incomplete(_) => None
        }
    }
}

macro_rules! from_bytes (
    ($name:ident, $submac:ident!( $($args:tt)* )) => (
        impl FromBytes for $name {
            named!(parse_bytes<&[u8], Self>, $submac!($($args)*));
        }
    );
);


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

/// Recognizes native endian unsigned 8 bytes integer
#[inline]
pub fn ne_u64(i: &[u8]) -> IResult<&[u8], u64> {
    if i.len() < 8 {
        IResult::Incomplete(Needed::Size(8))
    } else {
        let res = NativeEndian::read_u64(i);
        IResult::Done(&i[8..], res)
    }
}

/// Adds an expect method.
pub trait Expect<T> {
    /// Unwraps a result, yielding the content.
    ///
    /// # Panics
    ///
    /// Panics if the value is an error, with a passed panic message.
    fn expect(self, &str) -> T;
}

impl<I, O> Expect<(I, O)> for IResult<I, O> {
    fn expect(self, err: &str) -> (I, O) {
        match self {
            IResult::Done(i, o) => (i, o),
            IResult::Incomplete(_) => panic!("Incomplete: {}", err),
            IResult::Error(e) => panic!("{}: {}", e.description(), err)
        }
    }
}
