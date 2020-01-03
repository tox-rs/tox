/*! Top-level TCP Packets according
    to [Tox spec](https://zetok.github.io/tox-spec/#encrypted-payload-types)
*/

mod route_request;
mod route_response;
mod connect_notification;
mod disconnect_notification;
mod ping_request;
mod pong_response;
mod oob_send;
mod oob_receive;
mod onion_request;
mod onion_response;
mod data;

pub use self::route_request::RouteRequest;
pub use self::route_response::RouteResponse;
pub use self::connect_notification::ConnectNotification;
pub use self::disconnect_notification::DisconnectNotification;
pub use self::ping_request::PingRequest;
pub use self::pong_response::PongResponse;
pub use self::oob_send::OobSend;
pub use self::oob_receive::OobReceive;
pub use self::onion_request::OnionRequest;
pub use self::onion_response::OnionResponse;
pub use self::data::{Data, DataPayload};

use crate::toxcore::binary_io::*;

use nom::number::streaming::be_u16;

/** Top-level TCP packet.

    According to [Tox spec](https://zetok.github.io/tox-spec/#encrypted-payload-types)
*/
#[derive(Debug, PartialEq, Clone)]
pub enum Packet {
    /// [`RouteRequest`](./struct.RouteRequest.html) structure.
    RouteRequest(RouteRequest),
    /// [`RouteResponse`](./struct.RouteResponse.html) structure.
    RouteResponse(RouteResponse),
    /// [`ConnectNotification`](./struct.ConnectNotification.html) structure.
    ConnectNotification(ConnectNotification),
    /// [`DisconnectNotification`](./struct.DisconnectNotification.html) structure.
    DisconnectNotification(DisconnectNotification),
    /// [`PingRequest`](./struct.PingRequest.html) structure.
    PingRequest(PingRequest),
    /// [`PongResponse`](./struct.PongResponse.html) structure.
    PongResponse(PongResponse),
    /// [`OobSend`](./struct.OobSend.html) structure.
    OobSend(OobSend),
    /// [`OobReceive`](./struct.OobReceive.html) structure.
    OobReceive(OobReceive),
    /// [`OnionRequest`](./struct.OnionRequest.html) structure.
    OnionRequest(OnionRequest),
    /// [`OnionResponse`](./struct.OnionResponse.html) structure.
    OnionResponse(OnionResponse),
    /// [`Data`](./struct.Data.html) structure.
    Data(Data)
}

/// A serialized Packet should be not longer than 2032 bytes
pub const MAX_TCP_PACKET_SIZE: usize = 2032;

impl FromBytes for Packet {
    named!(from_bytes<Packet>, alt!(
        map!(RouteRequest::from_bytes, Packet::RouteRequest) |
        map!(RouteResponse::from_bytes, Packet::RouteResponse) |
        map!(ConnectNotification::from_bytes, Packet::ConnectNotification) |
        map!(DisconnectNotification::from_bytes, Packet::DisconnectNotification) |
        map!(PingRequest::from_bytes, Packet::PingRequest) |
        map!(PongResponse::from_bytes, Packet::PongResponse) |
        map!(OobSend::from_bytes, Packet::OobSend) |
        map!(OobReceive::from_bytes, Packet::OobReceive) |
        map!(OnionRequest::from_bytes, Packet::OnionRequest) |
        map!(OnionResponse::from_bytes, Packet::OnionResponse) |
        map!(Data::from_bytes, Packet::Data)
    ));
}

impl ToBytes for Packet {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            Packet::RouteRequest(ref p) => p.to_bytes(buf),
            Packet::RouteResponse(ref p) => p.to_bytes(buf),
            Packet::ConnectNotification(ref p) => p.to_bytes(buf),
            Packet::DisconnectNotification(ref p) => p.to_bytes(buf),
            Packet::PingRequest(ref p) => p.to_bytes(buf),
            Packet::PongResponse(ref p) => p.to_bytes(buf),
            Packet::OobSend(ref p) => p.to_bytes(buf),
            Packet::OobReceive(ref p) => p.to_bytes(buf),
            Packet::OnionRequest(ref p) => p.to_bytes(buf),
            Packet::OnionResponse(ref p) => p.to_bytes(buf),
            Packet::Data(ref p) => p.to_bytes(buf),
        }
    }
}

/** Packets are encrypted and sent in this form.

Serialized form:

Length     | Content
---------- | ------
`2`        | Length of encrypted payload in BigEndian
variable   | Encrypted payload (max 2048)

*/
#[derive(Debug, PartialEq, Clone)]
pub struct EncryptedPacket {
    /// Encrypted payload
    pub payload: Vec<u8>
}

/// A serialized EncryptedPacket should be not longer than 2050 bytes
pub const MAX_TCP_ENC_PACKET_SIZE: usize = 2050;

/// A serialized EncryptedPacket payload should be not longer than 2048 bytes
pub const MAX_TCP_ENC_PACKET_PAYLOAD_SIZE: usize = 2048;

impl FromBytes for EncryptedPacket {
    named!(from_bytes<EncryptedPacket>, do_parse!(
        length: be_u16 >>
        verify!(value!(length), |len| *len > 0 && *len as usize <= MAX_TCP_ENC_PACKET_PAYLOAD_SIZE) >>
        payload: take!(length) >>
        (EncryptedPacket { payload: payload.to_vec() })
    ));
}

impl ToBytes for EncryptedPacket {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_cond!(self.payload.len() > MAX_TCP_ENC_PACKET_PAYLOAD_SIZE, |buf| gen_error(buf, 0)) >>
            gen_be_u16!(self.payload.len() as u16) >>
            gen_slice!(self.payload.as_slice())
        )
    }
}


#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        encrypted_packet_encode_decode,
        EncryptedPacket {
            payload: vec![42; 123]
        }
    );
}
