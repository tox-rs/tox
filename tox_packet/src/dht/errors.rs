/*! Errors enum for DHT packets.
*/

use thiserror::Error;
use nom::{error::Error as NomError, Err};

use std::convert::From;
use std::io::Error as IoError;
use std::io::ErrorKind as IoErrorKind;

/// Error that can happen when calling `get_payload` of packet.
#[derive(Debug, PartialEq, Error)]
pub enum GetPayloadError {
    /// Error indicates that received payload of encrypted packet can't be decrypted
    #[error("Decrypt payload error")]
    Decrypt,
    /// Error indicates that decrypted payload of packet can't be parsed
    #[error("Deserialize payload error: {:?}, data: {:?}", error, payload)]
    Deserialize {
        /// Parsing error
        error: Err<NomError<Vec<u8>>>,
        /// Received payload of packet
        payload: Vec<u8>,
    }
}

impl GetPayloadError {
    pub(crate) fn decrypt() -> GetPayloadError {
        GetPayloadError::Decrypt
    }

    pub(crate) fn deserialize(e: Err<NomError<&[u8]>>, payload: Vec<u8>) -> GetPayloadError {
        GetPayloadError::Deserialize { error: e.to_owned(), payload }
    }
}

/// From trait for temporary use during transition from io:Error to custom enum error of failure crate
impl From<GetPayloadError> for IoError {
    fn from(item: GetPayloadError) -> Self {
        IoError::new(IoErrorKind::Other, format!("GetPayloadError occured. error: {:?}", item))
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::*;
    use nom::{Needed, error::{Error, ErrorKind}};

    #[test]
    fn get_payload_error_kind() {
        let decrypt = GetPayloadError::Decrypt;
        assert_eq!(format!("{}", decrypt), "Decrypt payload error".to_owned());

        let incomplete = GetPayloadError::Deserialize { error: Err::Incomplete(Needed::Size(NonZeroUsize::new(5).unwrap())), payload: vec![1, 2, 3, 4] };
        assert_eq!(format!("{}", incomplete), "Deserialize payload error: Incomplete(Size(5)), data: [1, 2, 3, 4]".to_owned());

        let deserialize = GetPayloadError::Deserialize { error: Err::Error(Error::new(vec![], ErrorKind::Eof)), payload: vec![1, 2, 3, 4] };
        assert_eq!(format!("{}", deserialize), "Deserialize payload error: Error(Error { input: [], code: Eof }), data: [1, 2, 3, 4]".to_owned());
    }
}
