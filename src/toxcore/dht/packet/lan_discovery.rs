/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2016-2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2018 Namsoo CHO <nscho66@gmail.com>
    Copyright © 2018 Evgeny Kurnevsky <kurnevsky@gmail.com>
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

/*! LanDiscovery packet
*/

use toxcore::binary_io::*;
use toxcore::crypto_core::*;

/** LanDiscovery packet struct.
LanDiscovery packets contain the DHT public key of the sender. When a LanDiscovery packet
is received, a NodesRequest packet will be sent to the sender of the packet. This means that
the DHT instance will bootstrap itself to every peer from which it receives one of these packet.
Through this mechanism, Tox clients will bootstrap themselve
 automatically from other Tox clients running on the local network.


Serialized form:

Length | Content
------ | ------
`1`    | `0x21`
`32`   | Public Key

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LanDiscovery {
    /// DHT public key of the sender
    pub pk: PublicKey,
}

impl ToBytes for LanDiscovery {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x21) >>
            gen_slice!(self.pk.as_ref())
        )
    }
}

impl FromBytes for LanDiscovery {
    named!(from_bytes<LanDiscovery>, do_parse!(
        tag!("\x21") >>
        pk: call!(PublicKey::from_bytes) >>
        (LanDiscovery { pk })
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        lan_discovery_encode_decode,
        LanDiscovery {
            pk: gen_keypair().0
        }
    );
}
