/*! The implementation of file transfer packets.
*/

use crate::toxcore::binary_io::*;

mod file_control;
mod file_data;
mod file_send_request;

pub use self::file_control::*;
pub use self::file_data::*;
pub use self::file_send_request::*;

/** File transfer packet enum that encapsulates all types of file transfer packets.
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
    named!(from_bytes<Packet>, alt!(
        map!(FileControl::from_bytes, Packet::FileControl) |
        map!(FileData::from_bytes, Packet::FileData) |
        map!(FileSendRequest::from_bytes, Packet::FileSendRequest)
    ));
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
        Packet::FileData(FileData::new(1, vec![1,2,3,4]))
    );

    encode_decode_test!(
        packet_file_send_request_encode_decode,
        Packet::FileSendRequest(FileSendRequest::new(1, FileType::Avatar, 4, FileUID::new(), "data".to_string()))
    );
}
