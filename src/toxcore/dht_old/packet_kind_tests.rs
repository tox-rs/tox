/*
    Copyright © 2016 Zetok Zalbavar <zexavexxe@gmail.com>

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


use toxcore::binary_io::*;
use toxcore::packet_kind::PacketKind;

use quickcheck::{Arbitrary, Gen, quickcheck};

// PacketKind::

impl Arbitrary for PacketKind {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        *g.choose(&[PacketKind::PingReq,
                   PacketKind::PingResp,
                   PacketKind::GetN,
                   PacketKind::SendN,
                   PacketKind::CookieReq,
                   PacketKind::CookieResp,
                   PacketKind::CryptoHs,
                   PacketKind::CryptoData,
                   PacketKind::DhtReq,
                   PacketKind::LanDisc,
                   PacketKind::OnionReq0,
                   PacketKind::OnionReq1,
                   PacketKind::OnionReq2,
                   PacketKind::AnnReq,
                   PacketKind::AnnResp,
                   PacketKind::OnionDataReq,
                   PacketKind::OnionDataResp,
                   PacketKind::OnionResp3,
                   PacketKind::OnionResp2,
                   PacketKind::OnionResp1])
            .unwrap()
    }
}

// PacketKind::from_bytes

#[test]
fn packet_kind_from_bytes_test() {
    fn with_bytes(bytes: Vec<u8>) {
        if bytes.is_empty() {
            assert_eq!(None, PacketKind::from_bytes(&bytes));
            return
        }
        match bytes[0] {
            0x00 => assert_eq!(PacketKind::PingReq, PacketKind::from_bytes(&bytes).unwrap()),
            0x01 => assert_eq!(PacketKind::PingResp, PacketKind::from_bytes(&bytes).unwrap()),
            0x02 => assert_eq!(PacketKind::GetN, PacketKind::from_bytes(&bytes).unwrap()),
            0x04 => assert_eq!(PacketKind::SendN, PacketKind::from_bytes(&bytes).unwrap()),
            0x18 => assert_eq!(PacketKind::CookieReq, PacketKind::from_bytes(&bytes).unwrap()),
            0x19 => assert_eq!(PacketKind::CookieResp, PacketKind::from_bytes(&bytes).unwrap()),
            0x1a => assert_eq!(PacketKind::CryptoHs, PacketKind::from_bytes(&bytes).unwrap()),
            0x1b => assert_eq!(PacketKind::CryptoData, PacketKind::from_bytes(&bytes).unwrap()),
            0x20 => assert_eq!(PacketKind::DhtReq, PacketKind::from_bytes(&bytes).unwrap()),
            0x21 => assert_eq!(PacketKind::LanDisc, PacketKind::from_bytes(&bytes).unwrap()),
            0x80 => assert_eq!(PacketKind::OnionReq0, PacketKind::from_bytes(&bytes).unwrap()),
            0x81 => assert_eq!(PacketKind::OnionReq1, PacketKind::from_bytes(&bytes).unwrap()),
            0x82 => assert_eq!(PacketKind::OnionReq2, PacketKind::from_bytes(&bytes).unwrap()),
            0x83 => assert_eq!(PacketKind::AnnReq, PacketKind::from_bytes(&bytes).unwrap()),
            0x84 => assert_eq!(PacketKind::AnnResp, PacketKind::from_bytes(&bytes).unwrap()),
            0x85 => assert_eq!(PacketKind::OnionDataReq, PacketKind::from_bytes(&bytes).unwrap()),
            0x86 => assert_eq!(PacketKind::OnionDataResp, PacketKind::from_bytes(&bytes).unwrap()),
            0x8c => assert_eq!(PacketKind::OnionResp3, PacketKind::from_bytes(&bytes).unwrap()),
            0x8d => assert_eq!(PacketKind::OnionResp2, PacketKind::from_bytes(&bytes).unwrap()),
            0x8e => assert_eq!(PacketKind::OnionResp1, PacketKind::from_bytes(&bytes).unwrap()),
            _ => assert_eq!(None, PacketKind::from_bytes(&bytes)),
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));

    // just in case
    with_bytes(vec![]);
    for i in 0x00 .. 0xff {
        with_bytes(vec![i]);
    }
}

// PacketKind::parse_bytes()

#[test]
fn user_status_parse_bytes_rest_test() {
    fn with_bytes(sk: PacketKind, r_rest: Vec<u8>) {
        let mut bytes = vec![sk as u8];
        bytes.extend_from_slice(&r_rest);

        let (rest, _) = PacketKind::parse_bytes(&bytes)
            .expect("PacketKind parsing failure.");
        assert_eq!(&r_rest[..], rest);
    }
    quickcheck(with_bytes as fn(PacketKind, Vec<u8>));
}
