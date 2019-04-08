/*! FileSendRequest struct.
It is used to start transferring file to a friend.
*/

use nom::{rest, le_u8, be_u32, be_u64};

use std::str;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

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
    named!(from_bytes<FileType>,
        switch!(be_u32,
            0 => value!(FileType::Data) |
            1 => value!(FileType::Avatar)
        )
    );
}

const FILE_UID_BYTES: usize = 32;

/// A type for random 32 bytes which is used as file unique id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileUID([u8; FILE_UID_BYTES]);

impl FileUID {
    /// Create new object
    pub fn new() -> FileUID {
        let mut array = [0; FILE_UID_BYTES];
        randombytes_into(&mut array);
        FileUID(array)
    }

    fn from_slice(bs: &[u8]) -> Option<FileUID> {
        if bs.len() != FILE_UID_BYTES {
            return None
        }
        let mut n = FileUID([0; FILE_UID_BYTES]);
        for (ni, &bsi) in n.0.iter_mut().zip(bs.iter()) {
            *ni = bsi
        }
        Some(n)
    }
}

impl FromBytes for FileUID {
    named!(from_bytes<FileUID>, map_opt!(take!(FILE_UID_BYTES), FileUID::from_slice));
}

/** FileSendRequest is a struct that holds info to start transferring file to a friend.

This packet is used to start transferring sender's file to a friend.
`file_type` and `file_size` are sent in big endian format.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x50`
`1`       | `file_id`
`4`       | `file_type`(0 = normal file, 1 = avatar file)
`8`       | `file_size`
`32`      | `file_unique_id`(a random bytes)
`0..255`  | file name as a UTF-8 C string

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileSendRequest {
    file_id: u8,
    file_type: FileType,
    file_size: u64,
    file_unique_id: FileUID,
    file_name: String,
}

impl FromBytes for FileSendRequest {
    named!(from_bytes<FileSendRequest>, do_parse!(
        tag!("\x50") >>
        file_id: le_u8 >>
        file_type: call!(FileType::from_bytes) >>
        file_size: be_u64 >>
        file_unique_id: call!(FileUID::from_bytes) >>
        file_name: map_res!(verify!(rest, |file_name: &[u8]| file_name.len() <= MAX_FILESEND_FILENAME_LENGTH),
            str::from_utf8) >>
        (FileSendRequest {
            file_id,
            file_type,
            file_size,
            file_unique_id,
            file_name: file_name.to_string(),
        })
    ));
}

impl ToBytes for FileSendRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x50) >>
            gen_be_u8!(self.file_id) >>
            gen_be_u32!(self.file_type as u32) >>
            gen_be_u64!(self.file_size) >>
            gen_slice!(self.file_unique_id.0) >>
            gen_cond!(self.file_name.len() > MAX_FILESEND_FILENAME_LENGTH, |buf| gen_error(buf, 0)) >>
            gen_slice!(self.file_name.as_bytes())
    )}
}

impl FileSendRequest {
    /// Create new FileControl object.
    pub fn new(file_id: u8, file_type: FileType, file_size: u64, file_unique_id: FileUID, file_name: String) -> Self {
        FileSendRequest {
            file_id,
            file_type,
            file_size,
            file_unique_id,
            file_name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        file_send_request_encode_decode,
        FileSendRequest::new(1, FileType::Data, 4, FileUID::new(), "data".to_string())
    );

    // Test for encoding error of from_bytes.
    #[test]
    fn file_send_request_from_bytes_encoding_error() {
        let mut packet = vec![0x50, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];
        packet.extend_from_slice(&FileUID::new().0);
        let err_string = vec![0, 159, 146, 150]; // not UTF8 bytes.
        packet.extend_from_slice(&err_string);
        assert!(FileSendRequest::from_bytes(&packet).is_err());
    }

    // Test for overflow of from_bytes.
    #[test]
    fn file_send_request_from_bytes_overflow() {
        let mut packet = vec![0x50, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];
        packet.extend_from_slice(&FileUID::new().0);
        let large_string = vec![32; MAX_FILESEND_FILENAME_LENGTH + 1];
        packet.extend_from_slice(&large_string);
        assert!(FileSendRequest::from_bytes(&packet).is_err());
    }

    // Test for overflow of to_bytes.
    #[test]
    fn file_send_request_to_bytes_overflow() {
        let large_string = String::from_utf8(vec![32u8; MAX_FILESEND_FILENAME_LENGTH + 1]).unwrap();
        let large_msg = FileSendRequest::new(1,FileType::Data,0xff00, FileUID::new(), large_string);
        let mut buf = [0; MAX_FILESEND_FILENAME_LENGTH + 1 + 4 + 8 + FILE_UID_BYTES]; // provide needed space for serialize.
        assert!(large_msg.to_bytes((&mut buf, 0)).is_err());
    }
}
