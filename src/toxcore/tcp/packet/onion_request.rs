/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2018 Roman Proskuryakov <humbug@deeptown.org>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

/*! OnionRequest packet
*/

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::onion::packet::IPV4_PADDING_SIZE;

use nom::{le_u8, be_u16, rest};

use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
};

/** Sent by client to server.
The server will pack payload from this request to `OnionRequest1` packet and send
it to UDP socket. The server can accept both TCP and UDP families as destination
IP address but regardless of this it will always send `OnionRequest1` to UDP
socket. Return address from `OnionRequest1` will contain TCP address so that
when we get `OnionResponse2` we will know that this response should be sent to
TCP client connected to our server.

Serialized form:

Length   | Content
-------- | ------
`1`      | `0x08`
`24`     | Nonce
`1`      | IpType
`4` or `16` | IPv4 or IPv6 address
`0` or `12` | Padding for IPv4
`2`      | Port
`32`     | PublicKey
variable | Payload

*/
#[derive(Debug, PartialEq, Clone)]
pub struct OnionRequest {
    /// Nonce that was used for payload encryption
    pub nonce: Nonce,
    /// IP address of the next onion node
    pub addr: IpAddr,
    /// Port of the next onion node
    pub port: u16,
    /// Temporary `PublicKey` for the current encrypted payload
    pub temporary_pk: PublicKey,
    /// Encrypted payload
    pub payload: Vec<u8>
}

impl FromBytes for OnionRequest {
    named!(from_bytes<OnionRequest>, do_parse!(
        tag!("\x08") >>
        nonce: call!(Nonce::from_bytes) >>
        ip_type: le_u8 >>
        addr: alt!(
            cond_reduce!(ip_type == 2 || ip_type == 130, terminated!(
                map!(Ipv4Addr::from_bytes, IpAddr::V4),
                take!(IPV4_PADDING_SIZE)
            )) |
            cond_reduce!(ip_type == 10 || ip_type == 138, map!(Ipv6Addr::from_bytes, IpAddr::V6))
        ) >>
        port: be_u16 >>
        temporary_pk: call!(PublicKey::from_bytes) >>
        payload: rest >>
        (OnionRequest { nonce, addr, port, temporary_pk, payload: payload.to_vec() })
    ));
}

impl ToBytes for OnionRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x08) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_if_else!(self.addr.is_ipv4(), gen_be_u8!(130), gen_be_u8!(138)) >>
            gen_call!(|buf, addr| IpAddr::to_bytes(addr, buf), &self.addr) >>
            gen_cond!(self.addr.is_ipv4(), gen_slice!(&[0; IPV4_PADDING_SIZE])) >>
            gen_be_u16!(self.port) >>
            gen_slice!(self.temporary_pk.as_ref()) >>
            gen_slice!(self.payload)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    encode_decode_test!(
        onion_request_encode_decode,
        OnionRequest {
            nonce: gen_nonce(),
            addr: "5.6.7.8".parse().unwrap(),
            port: 12345,
            temporary_pk: gen_keypair().0,
            payload: vec![42; 123]
        }
    );
}
