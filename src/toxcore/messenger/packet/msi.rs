/*! Msi struct. Used by tox-av
*/

use nom::le_u8;

use crate::toxcore::binary_io::*;

/// Maximum size in bytes of msi message packet
const MAX_MSI_PAYLOAD_SIZE: usize = 256;

/*
Msi Capabilities

const MSI_CAP_S_AUDIO: u8 = 4;  /* sending audio */
const MSI_CAP_S_VIDEO: u8 = 8;  /* sending video */
const MSI_CAP_R_AUDIO: u8 = 16; /* receiving audio */
const MSI_CAP_R_VIDEO: u8 = 32; /* receiving video */
*/

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Errors of msi session
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

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Kind of msi request
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MsiError(MsiErrorKind);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Capabilities(u8);

impl FromBytes for Request {
    named!(from_bytes<Request>, do_parse!(
        tag!("\x01") >>
        verify!(le_u8, |size| size == 1) >>
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
        tag!("\x02") >>
        verify!(le_u8, |size| size == 1) >>
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

impl FromBytes for Capabilities {
    named!(from_bytes<Capabilities>, do_parse!(
        tag!("\x03") >>
        verify!(le_u8, |size| size == 1) >>
        value: le_u8 >>
        (Capabilities(value))
    ));
}

impl ToBytes for Capabilities {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u8!(0x03) >> // Capabilities
            gen_le_u8!(0x01) >> // Size
            gen_le_u8!(self.0 as u8)
        )
    }
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
    sub_packets: Vec<MsiSubPacket>,
}

impl Msi {
    /// Make new msi struct
    pub fn new(request: RequestKind, error: MsiErrorKind, capabilities: u8) -> Self {
        Msi {
            sub_packets: vec![
                MsiSubPacket::Request(
                    Request(request)
                ),
                MsiSubPacket::MsiError(
                    MsiError(error)
                ),
                MsiSubPacket::Capabilities(
                    Capabilities(capabilities)
                )
            ]
        }
    }

    fn remove_redundant(input: &[u8], sub_packets: Vec<MsiSubPacket>) -> IResult<&[u8], Vec<MsiSubPacket>> {
        let mut result = Vec::new();
        let mut request = Vec::new();
        let mut error = Vec::new();
        let mut capabilities = Vec::new();

        for sub in sub_packets {
            match sub {
                MsiSubPacket::Request(_) => { request.push(sub); },
                MsiSubPacket::MsiError(_) => { error.push(sub); },
                MsiSubPacket::Capabilities(_) => { capabilities.push(sub); },
            };
        }
        if let Some(packet) = request.last() {
            result.push(*packet);
        }
        if let Some(packet) = error.last() {
            result.push(*packet);
        }
        if let Some(packet) = capabilities.last() {
            result.push(*packet);
        }
        IResult::Done(input, result)
    }

}

impl FromBytes for Msi {
    named!(from_bytes<Msi>, do_parse!(
        tag!("\x45") >>
        verify!(rest_len, |len| len < MAX_MSI_PAYLOAD_SIZE) >>
        sub_pack: many_till!(call!(MsiSubPacket::from_bytes), tag!("\x00")) >>
        sub_packets: call!(Msi::remove_redundant, sub_pack.0) >>
        (Msi {
            sub_packets
        })
    ));
}

impl ToBytes for Msi {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u8!(0x45) >>
            gen_many_ref!(&self.sub_packets, |buf, header| MsiSubPacket::to_bytes(header, buf)) >>
            gen_le_u8!(0x00)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        msi_encode_decode,
        Msi::new(RequestKind::Init, MsiErrorKind::MsiNone, 4)
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
            3, 1, 1, // last capabilities
            1, 1, 3, // last request, it should remain
            0,
        ];
        let (_rest, value) = Msi::from_bytes(&input).unwrap();
        let mut buf = [0; MAX_MSI_PAYLOAD_SIZE];
        let (after_value, size) = value.to_bytes((&mut buf, 0)).unwrap();
        assert_eq!(after_value[..size], [0x45,
            1, 1, 3, // last request of input
            2, 1, 1,
            3, 1, 1,
            0,
        ])
    }
}
