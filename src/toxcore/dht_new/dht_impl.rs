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
Implements Dht related structures.
*/

use std::collections::HashMap;
use toxcore::dht_new::packet::*;
use toxcore::dht_new::packed_node::*;
use toxcore::dht_new::kbucket::*;
use toxcore::dht_new::binary_io::*;
use toxcore::dht_new::codec::*;
use toxcore::crypto_core::*;
use toxcore::dht_new::packet_kind::*;
use std::io::{Error, ErrorKind};
use nom::IResult;
use std::hash::{Hash, Hasher};


#[derive(Clone, Eq, Debug, PartialEq)]
struct HashKeys(SecretKey, PublicKey);

impl Hash for HashKeys {
    fn hash<H>(&self, state: &mut H) where H: Hasher {
        let SecretKey(sk) = self.0;
        let PublicKey(pk) = self.1;
        for byte in sk.iter() {
            state.write_u8(*byte);
        }
        for byte in pk.iter() {
            state.write_u8(*byte);
        }
        state.finish();
    }
}

/// Manage hash table for precomputed keys.
#[derive(Clone, Eq, Debug, PartialEq)]
pub struct PrecomputedKeys {
    cache: HashMap<HashKeys, PrecomputedKey>,
}

impl PrecomputedKeys {
    /// manage hash table for precomputed keys
    pub fn new () -> PrecomputedKeys {
        PrecomputedKeys {
            cache: HashMap::new(),
        }
    }

    /// Get precomputed keys
    /// If the Key is not found in cache, create symmetric key and insert it into cache for later use.
    pub fn get_symmetric_key (&mut self, key_pair: (&SecretKey, &PublicKey)) -> Result<PrecomputedKey, Error> {
        let key = HashKeys(key_pair.0.clone(), key_pair.1.clone());
        match self.cache.get(&key) {       // if symmetric key exists in cache, returns with the value
            Some(k) => {
                return Ok(k.clone()); 
            },
            None => {},
        };

        // Key don't exist in cache, So create one
        // must separate logic into two blocks because self.cache is barrowed mutably
        let shared_secret = encrypt_precompute(key_pair.1, key_pair.0);
        self.cache.insert (key, shared_secret.clone());
        Ok(shared_secret)
    }
}

impl DhtPacket {
    /// create new DhtPacket object
    pub fn new(shared_secret: &PrecomputedKey, pk: &PublicKey, dp: DhtPacketPayload) -> DhtPacket {
        let nonce = &gen_nonce();
        let mut buf = [0; MAX_DHT_PACKET_SIZE];
        let (_, size) = dp.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size] , nonce, shared_secret);

        DhtPacket {
            packet_kind: dp.kind(),
            pk: *pk,
            nonce: *nonce,
            payload: payload,
        }

    }

    /**
    Decrypt payload and try to parse it as packet type.

    To get info about it's packet type use
    [`.kind()`](./struct.DhtPacket.html#method.kind) method.

    Returns `None` in case of faliure:

    - fails to decrypt
    - fails to parse as given packet type
    */
    /* TODO: perhaps switch to using precomputed symmetric key?
              - given that computing shared key is apparently the most
                costly operation when it comes to crypto, using precomputed
                key might (would significantly?) lower resource usage

                Alternatively, another method `get_payloadnm()` which would use
                symmetric key.
    */
    pub fn get_payload(&self, own_secret_key: &SecretKey) -> Result<Option<DhtPacketPayload>, Error>
    {
        debug!(target: "DhtPacket", "Getting packet data from DhtPacket.");
        trace!(target: "DhtPacket", "With DhtPacket: {:?}", self);
        let decrypted = open(&self.payload, &self.nonce, &self.pk,
                            own_secret_key)
            .and_then(|d| Ok(d))
            .map_err(|e| {
                debug!("Decrypting DhtPacket failed!");
                Error::new(ErrorKind::Other,
                    format!("DhtPacket decrypt error: {:?}", e))
            });

        match self.packet_kind {
            PacketKind::PingRequest => {
                match PingRequest::from_bytes(&decrypted.unwrap_or(vec![0])) {
                    IResult::Incomplete(e) => {
                        error!(target: "DhtPacket", "PingRequest deserialize error: {:?}", e);
                        Err(Error::new(ErrorKind::Other,
                            format!("PingRequest deserialize error: {:?}", e)))
                    },
                    IResult::Error(e) => {
                        error!(target: "DhtPacket", "PingRequest deserialize error: {:?}", e);
                        Err(Error::new(ErrorKind::Other,
                            format!("PingRequest deserialize error: {:?}", e)))
                    },
                    IResult::Done(_, packet) => {
                        Ok(Some(DhtPacketPayload::PingRequest(packet)))
                    }
                }
            },
            PacketKind::PingResponse => {
                match PingResponse::from_bytes(&decrypted.unwrap_or(vec![0])) {
                    IResult::Incomplete(e) => {
                        error!(target: "DhtPacket", "PingResponse deserialize error: {:?}", e);
                        Err(Error::new(ErrorKind::Other,
                            format!("PingResponse deserialize error: {:?}", e)))
                    },
                    IResult::Error(e) => {
                        error!(target: "DhtPacket", "PingResponse deserialize error: {:?}", e);
                        Err(Error::new(ErrorKind::Other,
                            format!("PingResponse deserialize error: {:?}", e)))
                    },
                    IResult::Done(_, packet) => {
                        Ok(Some(DhtPacketPayload::PingResponse(packet)))
                    }
                }
            },
            PacketKind::GetNodes => {
                match GetNodes::from_bytes(&decrypted.unwrap_or(vec![0])) {
                    IResult::Incomplete(e) => {
                        error!(target: "DhtPacket", "GetNodes deserialize error: {:?}", e);
                        Err(Error::new(ErrorKind::Other,
                            format!("GetNodes deserialize error: {:?}", e)))
                    },
                    IResult::Error(e) => {
                        error!(target: "DhtPacket", "GetNodes deserialize error: {:?}", e);
                        Err(Error::new(ErrorKind::Other,
                            format!("GetNodes deserialize error: {:?}", e)))
                    },
                    IResult::Done(_, packet) => {
                        Ok(Some(DhtPacketPayload::GetNodes(packet)))
                    }
                }
            },
            PacketKind::SendNodes => {
                match SendNodes::from_bytes(&decrypted.unwrap_or(vec![0])) {
                    IResult::Incomplete(e) => {
                        error!(target: "DhtPacket", "SendNodes deserialize error: {:?}", e);
                        Err(Error::new(ErrorKind::Other,
                            format!("SendNodes deserialize error: {:?}", e)))
                    },
                    IResult::Error(e) => {
                        error!(target: "DhtPacket", "SendNodes deserialize error: {:?}", e);
                        Err(Error::new(ErrorKind::Other,
                            format!("SendNodes deserialize error: {:?}", e)))
                    },
                    IResult::Done(_, packet) => {
                        Ok(Some(DhtPacketPayload::SendNodes(packet)))
                    }
                }
            },
            e => {
                    error!("Invalid PacketKind for DhtPacketPayload {:?}", e);
                    Err(Error::new(ErrorKind::Other,
                        format!("Invalid PacketKind for DhtPacketPayload {:?}", e)))
            }
        }
    }
}

impl DhtRequest {
    /// create new DhtRequest object
    pub fn new(shared_secret: &PrecomputedKey, rpk: &PublicKey, spk: &PublicKey, dp: DhtRequestPayload) -> DhtRequest {
        let nonce = &gen_nonce();

        let mut buf = [0; MAX_DHT_PACKET_SIZE];
        let (_, size) = dp.to_bytes((&mut buf, 0)).unwrap();
        let payload = seal_precomputed(&buf[..size], nonce, shared_secret);

        DhtRequest {
            rpk: *rpk,
            spk: *spk,
            nonce: *nonce,
            payload: payload,
        }
    }
}

impl DhtPacketPayload {
    /// Packet kind for enum DhtPacketPayload
    pub fn kind(&self) -> PacketKind {
        match *self {
            DhtPacketPayload::PingRequest(_) => PacketKind::PingRequest,
            DhtPacketPayload::PingResponse(_) => PacketKind::PingResponse,
            DhtPacketPayload::GetNodes(_) => PacketKind::GetNodes,
            DhtPacketPayload::SendNodes(_) => PacketKind::SendNodes,
        }
    }
}

impl DhtBase {
    /// Packet kind for enum DhtPacketPayload
    pub fn kind(&self) -> PacketKind {
        match *self {
            DhtBase::DhtPacket(ref p) => p.packet_kind,
            DhtBase::DhtRequest(ref p) => PacketKind::from_bytes(&[p.payload[1]]).unwrap().1,
        }
    }
}

impl GetNodes {
    /**
    Create response to `self` request with nodes provided from the `Kbucket`.

    Fails (returns `None`) if `Kbucket` is empty.
    */
    pub fn response(&self, kbucket: &Kbucket) -> Option<DhtPacketPayload> {
        let nodes = kbucket.get_closest(&self.pk);
        if !nodes.is_empty() {
            Some(DhtPacketPayload::SendNodes(SendNodes::with_nodes(self, nodes).unwrap()))
        }
        else {
            None
        }
    }
}

impl SendNodes {
    /**
    Create new `SendNodes`. Returns `None` if 0 or more than 4 nodes are
    supplied.

    Created as a response to `GetNodes` request.
    */
    pub fn with_nodes(request: &GetNodes, nodes: Vec<PackedNode>) -> Option<Self> {
        debug!(target: "SendNodes", "Creating SendNodes from GetNodes.");
        trace!(target: "SendNodes", "With GetNodes: {:?}", request);
        trace!("With nodes: {:?}", &nodes);

        if nodes.is_empty() || nodes.len() > 4 {
            warn!(target: "SendNodes", "Wrong number of nodes supplied!");
            return None
        }

        Some(SendNodes { nodes: nodes, id: request.id })
    }
}

impl From<PingRequest> for PingResponse {
    fn from(p: PingRequest) -> Self {
        PingResponse { id: p.id }
    }
}
