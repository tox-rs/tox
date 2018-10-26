/*! Data packet
*/

use toxcore::binary_io::*;

use nom::{be_u8, rest};

/** Sent by client to server.
The client sends data with `connection_id` and the server
relays it to the given connection

Serialized form:

Length   | Content
-------- | ------
`1`      | connection_id [ `0x10` .. `0xFF` ]
variable | Data

*/
#[derive(Debug, PartialEq, Clone)]
pub struct Data {
    /// The id of the connection of the client
    pub connection_id: u8,
    /// Data packet
    pub data: Vec<u8>
}

impl FromBytes for Data {
    named!(from_bytes<Data>, do_parse!(
        connection_id: verify!(be_u8, |id| id >= 0x10) >>
        data: rest >>
        (Data { connection_id, data: data.to_vec() })
    ));
}

impl ToBytes for Data {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(self.connection_id) >>
            gen_slice!(self.data)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        data_encode_decode,
        Data {
            connection_id: 17,
            data: vec![42; 123]
        }
    );
}
