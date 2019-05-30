/*! Data packet
*/

use crate::toxcore::binary_io::*;
use crate::toxcore::dht::packet::{CookieRequest, CookieResponse, CryptoHandshake, CryptoData};
use crate::toxcore::tcp::connection_id::ConnectionId;

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
    pub connection_id: ConnectionId,
    /// Data payload
    pub data: DataPayload,
}

impl FromBytes for Data {
    named!(from_bytes<Data>, do_parse!(
        connection_id: call!(ConnectionId::from_bytes) >>
        data: call!(DataPayload::from_bytes) >>
        (Data { connection_id, data })
    ));
}

impl ToBytes for Data {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_call!(|buf, connection_id| ConnectionId::to_bytes(connection_id, buf), &self.connection_id) >>
            gen_call!(|buf, packet| DataPayload::to_bytes(packet, buf), &self.data)
        )
    }
}

/// Data payload enum.
#[derive(Debug, PartialEq, Clone)]
pub enum DataPayload {
    /// [`CookieRequest`](../../dht/packet/struct.CookieRequest.html) structure.
    CookieRequest(CookieRequest),
    /// [`CookieResponse`](../../dht/packet/struct.CookieResponse.html) structure.
    CookieResponse(CookieResponse),
    /// [`CryptoHandshake`](../../dht/packet/struct.CryptoHandshake.html) structure.
    CryptoHandshake(CryptoHandshake),
    /// [`CryptoData`](../../dht/packet/struct.CryptoData.html) structure.
    CryptoData(CryptoData),
}

impl ToBytes for DataPayload {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            DataPayload::CookieRequest(ref p) => p.to_bytes(buf),
            DataPayload::CookieResponse(ref p) => p.to_bytes(buf),
            DataPayload::CryptoHandshake(ref p) => p.to_bytes(buf),
            DataPayload::CryptoData(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for DataPayload {
    named!(from_bytes<DataPayload>, alt!(
        map!(CookieRequest::from_bytes, DataPayload::CookieRequest) |
        map!(CookieResponse::from_bytes, DataPayload::CookieResponse) |
        map!(CryptoHandshake::from_bytes, DataPayload::CryptoHandshake) |
        map!(CryptoData::from_bytes, DataPayload::CryptoData)
    ));
}

#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        data_encode_decode,
        Data {
            connection_id: ConnectionId::from_index(1),
            data: DataPayload::CryptoData(CryptoData {
                nonce_last_bytes: 42,
                payload: vec![42; 123],
            }),
        }
    );
}
