/*! Msi struct. Used by tox-av
*/

use nom::{
    Err, error::ErrorKind,
    number::complete::le_u8,
    combinator::rest_len
};
use bitflags::*;

use crate::toxcore::binary_io::*;

/// Maximum size in bytes of msi message packet
const MAX_MSI_PAYLOAD_SIZE: usize = 256;

bitflags! {
    /// Capabilities kind of msi packet. Used by bitwise OR.
    pub struct CapabilitiesKind: u8 {
        /// Send audio
        const SEND_AUDIO = 4;
        /// Send video
        const SEND_VIDEO = 8;
        /// Receive audio
        const RECEIVE_AUDIO = 16;
        /// Receive video
        const RECEIVE_VIDEO = 32;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Capabilities(CapabilitiesKind);

/// Errors of msi session
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MsiErrorKind {
    /// Error of none
    MsiNone = 0,
    /// Error of invalid message
    InvalidMessage,
    /// Error of invalid parameter
    InvalidParam,
    /// Error of invalid state
    InvalidState,
    /// Error of stray message
    StrayMessage,
    /// Error of system
    System,
    /// Error of handle
    Handle,
    /// Error of undisclosed
    Undisclosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MsiError(MsiErrorKind);

/// Kind of msi request
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestKind {
    /// Msi request of init
    Init = 1,
    /// Msi request of push
    Push,
    /// Msi request of pop
    Pop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Request(RequestKind);

impl FromBytes for Request {
    named!(from_bytes<Request>, do_parse!(
        tag!("\x01\x01") >>
        value: call!(RequestKind::from_bytes) >>
        (Request(value))
    ));
}

impl ToBytes for Request {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u8!(0x01) >> // Request
            gen_le_u8!(0x01) >> // Size
            gen_le_u8!(self.0 as u8)
        )
    }
}

impl FromBytes for MsiError {
    named!(from_bytes<MsiError>, do_parse!(
        tag!("\x02\x01") >>
        value: call!(MsiErrorKind::from_bytes) >>
        (MsiError(value))
    ));
}

impl ToBytes for MsiError {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u8!(0x02) >> // MsiError
            gen_le_u8!(0x01) >> // Size
            gen_le_u8!(self.0 as u8)
        )
    }
}

impl FromBytes for CapabilitiesKind {
    named!(from_bytes<CapabilitiesKind>, do_parse!(
        value: le_u8 >>
        (CapabilitiesKind {
            bits: value,
        })
    ));
}

impl FromBytes for Capabilities {
    named!(from_bytes<Capabilities>, do_parse!(
        tag!("\x03\x01") >>
        value: call!(CapabilitiesKind::from_bytes) >>
        (Capabilities(value))
    ));
}

impl ToBytes for Capabilities {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u8!(0x03) >> // Capabilities
            gen_le_u8!(0x01) >> // Size
            gen_le_u8!(self.0.bits)
        )
    }
}

impl FromBytes for RequestKind {
    named!(from_bytes<RequestKind>, switch!(le_u8,
        1 => value!(RequestKind::Init) |
        2 => value!(RequestKind::Push) |
        3 => value!(RequestKind::Pop)
    ));
}

impl FromBytes for MsiErrorKind {
    named!(from_bytes<MsiErrorKind>, switch!(le_u8,
        0 => value!(MsiErrorKind::MsiNone) |
        1 => value!(MsiErrorKind::InvalidMessage) |
        2 => value!(MsiErrorKind::InvalidParam) |
        3 => value!(MsiErrorKind::InvalidState) |
        4 => value!(MsiErrorKind::StrayMessage) |
        5 => value!(MsiErrorKind::System) |
        6 => value!(MsiErrorKind::Handle) |
        7 => value!(MsiErrorKind::Undisclosed)
    ));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MsiSubPacket {
    Request(Request),
    MsiError(MsiError),
    Capabilities(Capabilities),
}

impl FromBytes for MsiSubPacket {
    named!(from_bytes<MsiSubPacket>, alt!(
        map!(Request::from_bytes, MsiSubPacket::Request) |
        map!(MsiError::from_bytes, MsiSubPacket::MsiError) |
        map!(Capabilities::from_bytes, MsiSubPacket::Capabilities)
    ));
}

impl ToBytes for MsiSubPacket {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            MsiSubPacket::Request(ref p) => p.to_bytes(buf),
            MsiSubPacket::MsiError(ref p) => p.to_bytes(buf),
            MsiSubPacket::Capabilities(ref p) => p.to_bytes(buf),
        }
    }
}

/** Msi is a struct that holds info for Media Session Interface.

Sub-packet: kind [1 byte], size [1 byte], value [$size bytes] : but actually size is always 1, so a sub-packet is always 3 bytes long

- kind: one of Request, Capabilities, Error
- size: the length in byte of value(always 1)
- value: enum value depending on kind

Payload: |sub_packet| |...{sub-packet}| |0|

Serialized form:

Length    | Content
--------- | -------
`1`       | `0x45`
`0..255`  | payload

Sub-packet serialized form:

Length    | Content
--------- | -------
`1`       | kind(1 = Request, 2 = Error, 3 = Capabilities)
`1`       | size(always 1)
`1`       | value(it depends on kind)

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Msi {
    request: Request,
    error: Option<MsiError>,
    capabilities: Capabilities,
}

//FIXME : use custom ErrorKind
//const NOM_CUSTOM_ERR_REQUEST_SUBPACKET_OMITTED: u32 = 1;
//const NOM_CUSTOM_ERR_CAPABILITIES_SUBPACKET_OMITTED: u32 = 2;

impl Msi {
    /// Make new msi struct
    pub fn new(request: RequestKind, error: Option<MsiErrorKind>, capabilities: CapabilitiesKind) -> Self {
        Msi {
            request: Request(request),
            error: error.map(|error| MsiError(error)),
            capabilities: Capabilities(capabilities),
        }
    }

    fn remove_redundant(input: &[u8], sub_packets: Vec<MsiSubPacket>) -> IResult<&[u8], Msi> {
        let mut request = None;
        let mut error = None;
        let mut capabilities = None;
        for sub in sub_packets {
            match sub {
                MsiSubPacket::Request(req) => { request = Some(req); },
                MsiSubPacket::MsiError(err) => { error = Some(err); },
                MsiSubPacket::Capabilities(capa) => { capabilities = Some(capa); },
            };
        }
        let request = if let Some(request) = request {
            request
        } else {
            return Err(Err::Error((input, ErrorKind::NoneOf)));
        };
        let capabilities = if let Some(capabilities) = capabilities {
            capabilities
        } else {
            return Err(Err::Error((input, ErrorKind::NoneOf)));
        };

        let msi = Msi {
            request,
            error,
            capabilities,
        };
        Ok((input, msi))
    }
}

impl FromBytes for Msi {
    named!(from_bytes<Msi>, do_parse!(
        tag!("\x45") >>
        verify!(rest_len, |len| *len < MAX_MSI_PAYLOAD_SIZE) >>
        sub_pack: many_till!(call!(MsiSubPacket::from_bytes), tag!("\x00")) >>
        msi: call!(Msi::remove_redundant, sub_pack.0) >>
        (msi)
    ));
}

impl ToBytes for Msi {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u8!(0x45) >>
            gen_call!(|buf, request| Request::to_bytes(request, buf), &self.request) >>
            gen_cond!(self.error.is_some(), gen_call!(|buf, error| MsiError::to_bytes(error, buf), &self.error.unwrap())) >>
            gen_call!(|buf, capabilities| Capabilities::to_bytes(capabilities, buf), &self.capabilities) >>
            gen_le_u8!(0x00)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        msi_encode_decode,
        Msi::new(RequestKind::Init, Some(MsiErrorKind::MsiNone), CapabilitiesKind::SEND_AUDIO)
    );

    #[test]
    fn msi_from_bytes_too_long() {
        let mut input = vec![0x45,
            1, 1, 1,
        ];
        let too_long = [47; MAX_MSI_PAYLOAD_SIZE];
        input.extend_from_slice(&too_long);
        assert!(Msi::from_bytes(&input).is_err());
    }

    #[test]
    fn msi_redundant() {
        let input = [0x45,
            1, 1, 1, // request
            1, 1, 2, // redundant request
            2, 1, 1, // last error
            3, 1, 4, // last capabilities
            1, 1, 3, // last request, it should remain
            0,
        ];
        let (_rest, value) = Msi::from_bytes(&input).unwrap();
        let mut buf = [0; MAX_MSI_PAYLOAD_SIZE];
        let (after_value, size) = value.to_bytes((&mut buf, 0)).unwrap();
        assert_eq!(after_value[..size], [0x45,
            1, 1, 3, // last request of input
            2, 1, 1,
            3, 1, 4,
            0,
        ])
    }
}
