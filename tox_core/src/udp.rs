use crate::dht::ip_port::IsGlobal;
use crate::dht::server::Server as DhtServer;
use crate::dht::server::errors::*;
use crate::net_crypto::NetCrypto;
use crate::onion::client::OnionClient;
use tox_packet::dht::*;
use tox_packet::onion::*;
use std::net::SocketAddr;

/// UDP server that handles DHT, onion and net_crypto packets. Onion and
/// net_crypro handlers are optional since appropriate packets are not handled
/// when operating in DHT server mode.
pub struct Server {
    /// DHT server.
    pub dht: DhtServer,
    /// Onion client that handles `OnionDataResponse` and
    /// `OnionAnnounceResponse` packets. It can be `None` in case of pure
    /// bootstrap server.
    onion_client: Option<OnionClient>,
    /// Net crypto module that handles `CookieRequest`, `CookieResponse`,
    /// `CryptoHandshake` and `CryptoData` packets. It can be `None` in case of
    /// pure bootstrap server when we don't have friends and therefore don't
    /// have to handle related packets.
    net_crypto: Option<NetCrypto>,
}

impl Server {
    /// Create new `Server` instance.
    pub fn new(dht: DhtServer) -> Self {
        Self {
            dht,
            onion_client: None,
            net_crypto: None,
        }
    }

    /// Function to handle incoming packets and send responses if necessary.
    pub async fn handle_packet(&self, packet: Packet, addr: SocketAddr) -> Result<(), HandlePacketError> {
        match packet {
            Packet::PingRequest(packet) =>
                self.dht.handle_ping_req(packet, addr).await,
            Packet::PingResponse(packet) =>
                self.dht.handle_ping_resp(packet, addr).await,
            Packet::NodesRequest(packet) =>
                self.dht.handle_nodes_req(packet, addr).await,
            Packet::NodesResponse(packet) =>
                self.dht.handle_nodes_resp(packet, addr).await,
            Packet::CookieRequest(packet) =>
                self.handle_cookie_request(&packet, addr).await,
            Packet::CookieResponse(packet) =>
                self.handle_cookie_response(&packet, addr).await,
            Packet::CryptoHandshake(packet) =>
                self.handle_crypto_handshake(&packet, addr).await,
            Packet::DhtRequest(packet) =>
                self.dht.handle_dht_req(packet, addr).await,
            Packet::LanDiscovery(packet) =>
                self.dht.handle_lan_discovery(&packet, addr).await,
            Packet::OnionRequest0(packet) =>
                self.dht.handle_onion_request_0(packet, addr).await,
            Packet::OnionRequest1(packet) =>
                self.dht.handle_onion_request_1(packet, addr).await,
            Packet::OnionRequest2(packet) =>
                self.dht.handle_onion_request_2(packet, addr).await,
            Packet::OnionAnnounceRequest(packet) =>
                self.dht.handle_onion_announce_request(packet, addr).await,
            Packet::OnionDataRequest(packet) =>
                self.dht.handle_onion_data_request(packet).await,
            Packet::OnionResponse3(packet) =>
                self.dht.handle_onion_response_3(packet).await,
            Packet::OnionResponse2(packet) =>
                self.dht.handle_onion_response_2(packet).await,
            Packet::OnionResponse1(packet) =>
                self.dht.handle_onion_response_1(packet).await,
            Packet::BootstrapInfo(packet) =>
                self.dht.handle_bootstrap_info(&packet, addr).await,
            Packet::CryptoData(packet) =>
                self.handle_crypto_data(&packet, addr).await,
            Packet::OnionDataResponse(packet) =>
                self.handle_onion_data_response(&packet).await,
            Packet::OnionAnnounceResponse(packet) =>
                self.handle_onion_announce_response(&packet, addr).await,
        }
    }

    /// Handle received `OnionDataResponse` packet and pass it to `onion_client` module.
    async fn handle_onion_data_response(&self, packet: &OnionDataResponse) -> Result<(), HandlePacketError> {
        if let Some(ref onion_client) = self.onion_client {
            onion_client.handle_data_response(packet).await
                .map_err(HandlePacketError::HandleOnionClientData)
        } else {
            Err(HandlePacketError::OnionClient)
        }
    }

    /// Handle received `OnionAnnounceResponse` packet and pass it to `onion_client` module.
    async fn handle_onion_announce_response(&self, packet: &OnionAnnounceResponse, addr: SocketAddr) -> Result<(), HandlePacketError> {
        if let Some(ref onion_client) = self.onion_client {
            onion_client.handle_announce_response(packet, IsGlobal::is_global(&addr.ip())).await
                .map_err(HandlePacketError::HandleOnionClientAnnounce)
        } else {
            Err(HandlePacketError::OnionClient)
        }
    }

    /// Set `onion_client` module.
    pub fn set_onion_client(&mut self, onion_client: OnionClient) {
        self.onion_client = Some(onion_client);
    }

    /// Handle received `CookieRequest` packet and pass it to `net_crypto`
    /// module.
    pub async fn handle_cookie_request(&self, packet: &CookieRequest, addr: SocketAddr)
        -> Result<(), HandlePacketError> {
        if let Some(ref net_crypto) = self.net_crypto {
            net_crypto.handle_udp_cookie_request(packet, addr).await
                .map_err(HandlePacketError::HandleNetCrypto)
        } else {
            Err(HandlePacketError::NetCrypto)
        }
    }

    /// Handle received `CookieResponse` packet and pass it to `net_crypto`
    /// module.
    pub async fn handle_cookie_response(&self, packet: &CookieResponse, addr: SocketAddr)
        -> Result<(), HandlePacketError> {
        if let Some(ref net_crypto) = self.net_crypto {
            net_crypto.handle_udp_cookie_response(packet, addr).await
                .map_err(HandlePacketError::HandleNetCrypto)
        } else {
            Err(HandlePacketError::NetCrypto)
        }
    }

    /// Handle received `CryptoHandshake` packet and pass it to `net_crypto`
    /// module.
    pub async fn handle_crypto_handshake(&self, packet: &CryptoHandshake, addr: SocketAddr)
        -> Result<(), HandlePacketError> {
        if let Some(ref net_crypto) = self.net_crypto {
            net_crypto.handle_udp_crypto_handshake(packet, addr).await
                .map_err(HandlePacketError::HandleNetCrypto)
        } else {
            Err(HandlePacketError::NetCrypto)
        }
    }

    /// Handle received `CryptoData` packet and pass it to `net_crypto` module.
    pub async fn handle_crypto_data(&self, packet: &CryptoData, addr: SocketAddr) -> Result<(), HandlePacketError> {
        if let Some(ref net_crypto) = self.net_crypto {
            net_crypto.handle_udp_crypto_data(packet, addr).await
                .map_err(HandlePacketError::HandleNetCrypto)
        } else {
            Err(HandlePacketError::NetCrypto)
        }
    }

    /// Set `net_crypto` module.
    pub fn set_net_crypto(&mut self, net_crypto: NetCrypto) {
        self.net_crypto = Some(net_crypto);
    }
}
