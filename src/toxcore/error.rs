/*! Error definitions
*/

use std::fmt;

use failure::{Backtrace, Context, Fail};
use nom::{Needed, ErrorKind as nomErrorKind};

/// An error that can occur while running tox-rs/tox.
#[derive(Debug)]
pub struct Error {
    ctx: Context<ErrorKind>,
}

impl Error {
    /// Return the kind of this error.
    pub fn kind(&self) -> &ErrorKind {
        self.ctx.get_context()
    }

    pub(crate) fn incomplete(needed: Needed, data: Vec<u8>) -> Error {
        Error::from(ErrorKind::IncompleteData { needed, data })
    }

    pub(crate) fn deserialize(error: nomErrorKind, data: Vec<u8>) -> Error {
        Error::from(ErrorKind::Deserialize { error, data })
    }
}

impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// Error indicates that object can't be parsed.
    Deserialize {
        /// Parsing error
        error: nomErrorKind,
        /// object serialized data
        data: Vec<u8>,
    },
    /// Error indicates that more data is needed to parse serialized object.
    IncompleteData {
        /// Required data size to be parsed
        needed: Needed,
        /// object serialized data
        data: Vec<u8>,
    },
    /// This enum may grow additional variants, so this makes sure clients
    /// don't count on exhaustive matching. (Otherwise, adding a new variant
    /// could break existing code.)
    #[doc(hidden)]
    __Nonexhaustive,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ErrorKind::Deserialize { ref error, ref data } => {
                write!(f, "Deserialize object error: {:?}, data: {:?}", error, data)
            },
            ErrorKind::IncompleteData { ref needed, ref data } => {
                write!(f, "Bytes of object should not be incomplete: {:?}, data: {:?}", needed, data)
            },
            ErrorKind::__Nonexhaustive => panic!("invalid error"),
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error::from(Context::new(kind))
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(ctx: Context<ErrorKind>) -> Error {
        Error { ctx }
    }
}
