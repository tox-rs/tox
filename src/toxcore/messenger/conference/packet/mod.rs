/*! The implementation of conference packets.
*/

mod invite;

pub use self::invite::*;

use nom::be_u8;
use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/// Length of conference unique bytes
pub const CONFERENCE_UID_BYTES: usize = 32;

/// Unique id used in conference
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConferenceUID([u8; CONFERENCE_UID_BYTES]);

impl ConferenceUID {
    /// Create new object
    pub fn random() -> ConferenceUID {
        let mut array = [0; CONFERENCE_UID_BYTES];
        randombytes_into(&mut array);
        ConferenceUID(array)
    }

    /// Custom from_slice function of ConferenceUID
    pub fn from_slice(bs: &[u8]) -> Option<ConferenceUID> {
        if bs.len() != CONFERENCE_UID_BYTES {
            return None
        }
        let mut n = ConferenceUID([0; CONFERENCE_UID_BYTES]);
        for (ni, &bsi) in n.0.iter_mut().zip(bs.iter()) {
            *ni = bsi
        }
        Some(n)
    }
}

impl FromBytes for ConferenceUID {
    named!(from_bytes<ConferenceUID>, map_opt!(take!(CONFERENCE_UID_BYTES), ConferenceUID::from_slice));
}

impl ToBytes for ConferenceUID {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.0)
        )
    }
}

/// Type of conference
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConferenceType {
    /// Text conference.
    Text = 0x00,
    /// Audio conference.
    Audio,
}

impl FromBytes for ConferenceType {
    named!(from_bytes<ConferenceType>,
        switch!(be_u8,
            0 => value!(ConferenceType::Text) |
            1 => value!(ConferenceType::Audio)
        )
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        conference_uid_encode_decode,
        ConferenceUID::random()
    );

    #[test]
    fn conference_type_from_bytes() {
        let raw = [0];
        let (_, conference_type) = ConferenceType::from_bytes(&raw).unwrap();
        assert_eq!(ConferenceType::Text, conference_type);
    }
}
