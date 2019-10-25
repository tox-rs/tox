/*! FileData struct.
It is used to transfer chunk of file data to a friend.
*/

use nom::{
    AsBytes,
    number::complete::le_u8,
    combinator::{rest, rest_len},
};

use super::*;

/** FileData is a struct that holds chunk of data of a file to transfer to a friend.

This packet is used to transfer sender's data file to a friend.
It holds `file_id` which is one byte long, means that a tox client can send maximum 256 files concurrently.
And it means that two friends can send 512 files to each other concurrently.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x52`
`1`       | `file_id`
`0..1371` | file data piece

*/

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileData {
    file_id: u8,
    data: Vec<u8>,
}

impl FromBytes for FileData {
    named!(from_bytes<FileData>, do_parse!(
        tag!("\x52") >>
        file_id: le_u8 >>
        verify!(rest_len, |len| *len <= MAX_FILE_DATA_SIZE) >>
        data : rest >>
        (FileData { file_id, data: data.to_vec() })
    ));
}

impl ToBytes for FileData {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x52) >>
            gen_be_u8!(self.file_id) >>
            gen_cond!(self.data.len() > MAX_FILE_DATA_SIZE, |buf| gen_error(buf, 0)) >>
            gen_slice!(self.data.as_bytes())
        )
    }
}

impl FileData {
    /// Create new FileData object.
    pub fn new(file_id: u8, data: Vec<u8>) -> Self {
        FileData { file_id, data }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        file_data_encode_decode,
        FileData::new(1, vec![1,2,3,4])
    );

    #[test]
    fn file_data_from_bytes_too_long() {
        let mut data = vec![0x52, 1];
        let long_data = [47; MAX_FILE_DATA_SIZE + 1];
        data.extend_from_slice(&long_data);
        assert!(FileData::from_bytes(&data).is_err());
    }
}
