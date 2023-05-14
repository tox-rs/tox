/*! File transfer packets
*/

use nom::branch::alt;
use nom::bytes::complete::take;
use nom::combinator::{map, map_opt};
use nom::error::{make_error, ErrorKind};
use nom::number::complete::{be_u32, be_u64, le_u8};
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};

use tox_binary_io::*;

mod file_control;
mod file_data;
mod file_send_request;

pub use self::file_control::*;
pub use self::file_data::*;
pub use self::file_send_request::*;

use cookie_factory::{do_gen, gen_be_u32, gen_be_u64, gen_be_u8, gen_call, gen_cond, gen_slice};

/// Maximum size in bytes of chunk of file data
const MAX_FILE_DATA_SIZE: usize = 1371;

/// Whether I am a sender or receiver of file data packet
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferDirection {
    /// I am a sender
    Send = 0,
    /// I am a receiver
    Receive,
}

impl FromBytes for TransferDirection {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, b) = le_u8(input)?;
        match b {
            0 => Ok((input, TransferDirection::Send)),
            1 => Ok((input, TransferDirection::Receive)),
            _ => Err(nom::Err::Error(make_error(input, ErrorKind::Switch))),
        }
    }
}

/// Control types for transferring file data
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlType {
    /// Accept a request of transferring file from a peer
    Accept,
    /// Pause transferring
    Pause,
    /// Stop transferring and quit session
    Kill,
    /// Seek to position of file stream and holds seek parameter
    Seek(u64),
}

impl ToBytes for ControlType {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match self {
            ControlType::Accept => do_gen!(buf, gen_be_u8!(0x00)),
            ControlType::Pause => do_gen!(buf, gen_be_u8!(0x01)),
            ControlType::Kill => do_gen!(buf, gen_be_u8!(0x02)),
            ControlType::Seek(seek_param) => do_gen!(buf, gen_be_u8!(0x03) >> gen_be_u64!(*seek_param)),
        }
    }
}

impl FromBytes for ControlType {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, b) = le_u8(input)?;
        match b {
            0 => Ok((input, ControlType::Accept)),
            1 => Ok((input, ControlType::Pause)),
            2 => Ok((input, ControlType::Kill)),
            3 => map(be_u64, ControlType::Seek)(input),
            _ => Err(nom::Err::Error(make_error(input, ErrorKind::Switch))),
        }
    }
}

/// Type of file to transfer
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileType {
    /// Normal data file.
    Data = 0,
    /// Avatar image file.
    Avatar,
}

/// Maximum file name size in bytes
const MAX_FILESEND_FILENAME_LENGTH: usize = 255;

impl FromBytes for FileType {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, b) = be_u32(input)?;
        match b {
            0 => Ok((input, FileType::Data)),
            1 => Ok((input, FileType::Avatar)),
            _ => Err(nom::Err::Error(make_error(input, ErrorKind::Switch))),
        }
    }
}

const FILE_UID_BYTES: usize = 32;

/// A type for random 32 bytes which is used as file unique id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileUid([u8; FILE_UID_BYTES]);

impl Distribution<FileUid> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> FileUid {
        FileUid(rng.gen())
    }
}

impl FileUid {
    fn from_slice(bs: &[u8]) -> Option<FileUid> {
        if bs.len() != FILE_UID_BYTES {
            return None;
        }
        let mut n = [0; FILE_UID_BYTES];
        n.clone_from_slice(bs);

        Some(FileUid(n))
    }
}

impl FromBytes for FileUid {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        map_opt(take(FILE_UID_BYTES), FileUid::from_slice)(input)
    }
}

/** FileTransfer packet enum that encapsulates all types of FileTransfer packets.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    /// [`FileControl`](./struct.FileControl.html) structure.
    FileControl(FileControl),
    /// [`FileData`](./struct.FileData.html) structure.
    FileData(FileData),
    /// [`FileSendRequest`](./struct.FileSendRequest.html) structure.
    FileSendRequest(FileSendRequest),
}

impl ToBytes for Packet {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            Packet::FileControl(ref p) => p.to_bytes(buf),
            Packet::FileData(ref p) => p.to_bytes(buf),
            Packet::FileSendRequest(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for Packet {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        alt((
            map(FileControl::from_bytes, Packet::FileControl),
            map(FileData::from_bytes, Packet::FileData),
            map(FileSendRequest::from_bytes, Packet::FileSendRequest),
        ))(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        packet_file_control_encode_decode,
        Packet::FileControl(FileControl::new(TransferDirection::Send, 1, ControlType::Seek(100)))
    );

    encode_decode_test!(
        packet_file_data_encode_decode,
        Packet::FileData(FileData::new(1, vec![1, 2, 3, 4]))
    );

    encode_decode_test!(
        packet_file_send_request_encode_decode,
        Packet::FileSendRequest(FileSendRequest::new(
            1,
            FileType::Avatar,
            4,
            FileUid([42; FILE_UID_BYTES]),
            "data".to_string()
        ))
    );
}
