//! Connection ID definition.

use std::num::NonZeroU8;

use crate::toxcore::binary_io::*;
use crate::toxcore::tcp::links::MAX_LINKS_N;

use nom::number::streaming::be_u8;

/// Connection ID is either a number between [16, 255] or 0. Zero can be
/// included in a response and means that the previous request was invalid.
/// If a connection id is a number between [16, 255] it can be uniquely mapped
/// to a connection index between [0, 239].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ConnectionId(Option<NonZeroU8>);

impl ConnectionId {
    /// Zero connection id meaning invalid request.
    pub fn zero() -> Self {
        ConnectionId(None)
    }

    /// Get connection id corresponding to the index.
    pub fn from_index(index: u8) -> Self {
        assert!(index < MAX_LINKS_N, "The index {} must be lower than {}", index, MAX_LINKS_N);
        ConnectionId(Some(NonZeroU8::new(index + 16).unwrap()))
    }

    /// Get index corresponding to the connection id. None if the connection id
    /// is zero.
    pub fn index(self) -> Option<u8> {
        self.0.map(|connection_id| connection_id.get() - 16)
    }
}

impl FromBytes for ConnectionId {
    named!(from_bytes<ConnectionId>, map!(verify!(be_u8, |id| *id == 0 || *id >= 0x10), |id| ConnectionId(NonZeroU8::new(id))));
}

impl ToBytes for ConnectionId {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        gen_be_u8!(buf, self.0.map_or(0, |connection_id| connection_id.get()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        connection_id_encode_decode,
        ConnectionId::from_index(42)
    );

    encode_decode_test!(
        connection_id_0_encode_decode,
        ConnectionId::zero()
    );

    #[test]
    fn zero() {
        let connection_id = ConnectionId::zero();
        assert_eq!(connection_id.0, None);
    }

    #[test]
    fn from_index() {
        let connection_id = ConnectionId::from_index(0);
        assert_eq!(connection_id.0.unwrap().get(), 16);
    }

    #[test]
    #[should_panic]
    fn from_index_invalid() {
        let _connection_id = ConnectionId::from_index(255);
    }

    #[test]
    fn index() {
        let index = 42;
        let connection_id = ConnectionId::from_index(index);
        assert_eq!(connection_id.index().unwrap(), index);
    }

    #[test]
    fn index_zero() {
        let connection_id = ConnectionId::zero();
        assert!(connection_id.index().is_none());
    }
}
