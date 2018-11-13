/*! Error enums for DHT.
*/

use nom::{ErrorKind, Needed};

use std::convert::From;
use std::io::Error as IoError;
use std::io::ErrorKind as IoErrorKind;

/// Error that can happen when calling `get_payload` of packet.
#[derive(Debug, Fail)]
pub enum GetPayloadError {
    /// Error indicates that received payload of encrypted packet can't be decrypted
    #[fail(display = "Decrypt encrypted payload of {:?} packet error.", packet)]
    DecryptError {
        /// Packet type
        packet: String
    },
    /// Error indicates that more data is needed to parse decrypted payload of packet
    #[fail(display = "Payload of {:?} packet should not be incomplete: {:?}, payload: {:?}", packet, needed, payload)]
    IncompletePayload {
        /// Packet type
        packet: String,
        /// Required data size to be parsed
        needed: Needed,
        /// Received payload of packet
        payload: Vec<u8>,
    },
    /// Error indicates that decrypted payload of packet can't be parsed
    #[fail(display = "Deserialize payload of {:?} packet. error: {:?}, payload: {:?}", packet, error, payload)]
    DeserializeError {
        /// Packet type
        packet: String,
        /// Parsing error
        error: ErrorKind,
        /// Received payload of packet
        payload: Vec<u8>,
    }
}

/// From trait for temporary use during transition from io:Error to custom enum error of failure crate
impl From<GetPayloadError> for IoError {
    fn from(_item: GetPayloadError) -> Self {
        IoError::new(IoErrorKind::Other, "GetPayloadError occured.")
    }
}
