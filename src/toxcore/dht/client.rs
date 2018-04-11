/*
    Copyright © 2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2018 Namsoo CHO <nscho66@gmail.com>

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


/*!
Hold infomation of a peer.
The object of this struct is one per a peer.
*/

use std::time::Instant;

use toxcore::crypto_core::*;

/// peer info.
#[derive(Clone, Debug)]
pub struct Client {
    /// Public key of dht node
    pub pk: PublicKey,
    /// last sent ping_id to check PingResponse is correct
    pub ping_id: u64,
    /// last received ping-response time
    pub last_resp_time: Instant
}

impl Client {
    /// create Client object
    pub fn new(pk: PublicKey) -> Client {
        Client {
            pk,
            ping_id: 0,
            last_resp_time: Instant::now(),
        }
    }
    /// set new random ping id to the client and return it
    pub fn new_ping_id(&mut self) -> u64 {
        self.ping_id = random_u64();
        self.ping_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_is_clonable() {
        let (alice_pk, _alice_sk) = gen_keypair();
        let client = Client::new(alice_pk);
        let _ = client.clone();
    }
}
