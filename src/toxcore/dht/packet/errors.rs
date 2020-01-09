/*! Errors enum for DHT packets.
*/

use std::{str, fmt};

use failure::{Backtrace, Context, Fail};
use nom::{error::ErrorKind, Err};

use std::convert::From;
use std::io::Error as IoError;
use std::io::ErrorKind as IoErrorKind;

/// Error that can happen when calling `get_payload` of packet.
#[derive(Debug)]
pub struct GetPayloadError {
    ctx: Context<GetPayloadErrorKind>,
}

impl GetPayloadError {
    /// Return the kind of this error.
    pub fn kind(&self) -> &GetPayloadErrorKind {
        self.ctx.get_context()
    }

    pub(crate) fn decrypt() -> GetPayloadError {
        GetPayloadError::from(GetPayloadErrorKind::Decrypt)
    }

    pub(crate) fn deserialize(e: Err<(&[u8], ErrorKind)>, payload: Vec<u8>) -> GetPayloadError {
        GetPayloadError::from(GetPayloadErrorKind::Deserialize { error: e.to_owned(), payload })
    }
}

impl Fail for GetPayloadError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for GetPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Clone, Debug, Eq, PartialEq, Fail)]
pub enum GetPayloadErrorKind {
    /// Error indicates that received payload of encrypted packet can't be decrypted
    #[fail(display = "Decrypt payload error")]
    Decrypt,
    /// Error indicates that decrypted payload of packet can't be parsed
    #[fail(display = "Deserialize payload error: {:?}, data: {:?}", error, payload)]
    Deserialize {
        /// Parsing error
        error: nom::Err<(Vec<u8>, ErrorKind)>,
        /// Received payload of packet
        payload: Vec<u8>,
    }
}

impl From<GetPayloadErrorKind> for GetPayloadError {
    fn from(kind: GetPayloadErrorKind) -> GetPayloadError {
        GetPayloadError::from(Context::new(kind))
    }
}

impl From<Context<GetPayloadErrorKind>> for GetPayloadError {
    fn from(ctx: Context<GetPayloadErrorKind>) -> GetPayloadError {
        GetPayloadError { ctx }
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
    use super::*;
    use nom::Needed;

    #[test]
    fn get_payload_error() {
        let error = GetPayloadError::deserialize(Err::Error((&[], ErrorKind::Eof)), vec![1, 2, 3, 4]);
        assert!(error.cause().is_none());
        assert!(error.backtrace().is_some());
        assert_eq!(format!("{}", error), "Deserialize payload error: Error(([], Eof)), data: [1, 2, 3, 4]".to_owned());
    }

    #[test]
    fn get_payload_error_kind() {
        let decrypt = GetPayloadErrorKind::Decrypt;
        assert_eq!(format!("{}", decrypt), "Decrypt payload error".to_owned());

        let incomplete = GetPayloadErrorKind::Deserialize { error: Err::Incomplete(Needed::Size(5)), payload: vec![1, 2, 3, 4] };
        assert_eq!(format!("{}", incomplete), "Deserialize payload error: Incomplete(Size(5)), data: [1, 2, 3, 4]".to_owned());

        let deserialize = GetPayloadErrorKind::Deserialize { error: Err::Error((vec![], ErrorKind::Eof)), payload: vec![1, 2, 3, 4] };
        assert_eq!(format!("{}", deserialize), "Deserialize payload error: Error(([], Eof)), data: [1, 2, 3, 4]".to_owned());
    }
}
