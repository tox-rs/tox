/*! The inner implementation of client used only by relay server.
*/

use crate::toxcore::crypto_core::*;
use crate::toxcore::tcp::packet::*;
use crate::toxcore::tcp::connection_id::ConnectionId;
use crate::toxcore::tcp::links::Links;
use crate::toxcore::onion::packet::InnerOnionResponse;
use crate::toxcore::time::*;
use crate::toxcore::utils::*;

use std::io::{Error, ErrorKind};
use std::net::IpAddr;
use std::time::{Instant, Duration};

use futures::Future;
use futures::channel::mpsc;
use futures::{FutureExt, SinkExt};

/// Interval of time for sending TCP PingRequest
pub const TCP_PING_FREQUENCY: Duration = Duration::from_secs(30);
/// Interval of time for waiting response of PingRequest sent
pub const TCP_PING_TIMEOUT: Duration = Duration::from_secs(10);
/// Interval of time for packet sending
pub const TCP_SEND_TIMEOUT: Duration = Duration::from_secs(1);

/** Structure that represents how Server keeps connected clients. A write-only socket with
human interface. A client cannot send a message directly to another client, whereas server can.
*/
pub struct Client {
    /// PublicKey of the client.
    pk: PublicKey,
    /// IpAddr of the client.
    ip_addr: IpAddr,
    /// Port of the client.
    port: u16,
    /// The transmission end of a channel which is used to send values.
    tx: mpsc::Sender<Packet>,
    /** links - a table of indexing links from this client to another

    A client requests to link him with another client by PK with RouteRequest.
    The server inserts that PK into links and gives the index of the link back to client
    via RouteResponse. Now the client may use this index to communicate with the connection
    using that index, e.g. send Data by index. Our links are 0-based while wire indices are
    16-based. E.g. `::get_connection_id` and `::insert_connection_id` return `Some(x+16)`,
    `::get_link` and `::take_link` accept ids in `[0; 240) + 16`. All conversions are done only
    inside this module.
    */
    links: Links,
    /// Used to check whether PongResponse is correct
    ping_id: u64,
    /// Last time sent PingRequest packet
    last_pinged: Instant,
    /// Last time received PongResponse
    last_pong_resp: Instant
}

impl Client {
    /** Create new Client
    */
    pub fn new(tx: mpsc::Sender<Packet>, pk: &PublicKey, ip_addr: IpAddr, port: u16) -> Client {
        Client {
            pk: *pk,
            ip_addr,
            port,
            tx,
            links: Links::new(),
            ping_id: 0,
            last_pinged: clock_now(),
            last_pong_resp: clock_now()
        }
    }

    /** PK of the `Client`
    */
    pub fn pk(&self) -> PublicKey {
        self.pk
    }

    /** `std::net::IpAddr` of the `Client`
    */
    pub fn ip_addr(&self) -> IpAddr {
        self.ip_addr
    }

    /** Port of the `Client`
    */
    pub fn port(&self) -> u16 {
        self.port
    }

    /** Last ping_id sent to client.
    */
    pub fn ping_id(&self) -> u64 {
        self.ping_id
    }

    /** Set last_pong_resp
    */
    pub fn set_last_pong_resp(&mut self, time: Instant) {
        self.last_pong_resp = time;
    }

    /** Check if PongResponse timed out
    */
    pub fn is_pong_timedout(&self) -> bool {
        clock_elapsed(self.last_pong_resp) > TCP_PING_TIMEOUT + TCP_PING_FREQUENCY
    }

    /** Check if Ping interval is elapsed
    */
    pub fn is_ping_interval_passed(&self) -> bool {
        clock_elapsed(self.last_pinged) >= TCP_PING_FREQUENCY
    }

    /** Get the Links of the Client
    */
    pub fn links(&self) -> &Links {
        &self.links
    }

    /** Get the Links of the Client
    */
    pub fn links_mut(&mut self) -> &mut Links {
        &mut self.links
    }

    /** Send a packet. This method does not ignore IO error
    */
    fn send(&self, packet: Packet) -> impl Future<Output = Result<(), Error>> + Send {
        let mut tx = self.tx.clone();

        async move {
            let timeout = tokio::time::timeout(
                TCP_SEND_TIMEOUT,
                tx.send(packet)
            );

            match timeout.await {
                Err(e) => Err(Error::new(
                    ErrorKind::Other,
                    format!("Failed to send packet: {:?}", e)
                )),
                Ok(Err(e)) => Err(Error::new(
                    ErrorKind::Other,
                    format!("Failed to send packet: {:?}", e)
                )),
                Ok(_) => Ok(())
            }
        }
    }
    /** Send a packet. This method ignores IO error
    */
    fn send_ignore_error(&self, packet: Packet) -> impl Future<Output = Result<(), Error>> + Send {
        self.send(packet)
            .then(|_| futures::future::ok(())) // ignore if somehow failed to send it
    }
    /** Construct RouteResponse and send it to Client
    */
    pub fn send_route_response(&self, pk: &PublicKey, connection_id: ConnectionId) -> impl Future<Output = Result<(), Error>> + Send {
        self.send(
            Packet::RouteResponse(RouteResponse { connection_id, pk: *pk })
        )
    }
    /** Construct ConnectNotification and send it to Client ignoring IO error
    */
    pub fn send_connect_notification(&self, connection_id: ConnectionId) -> impl Future<Output = Result<(), Error>> + Send {
        self.send_ignore_error(
            Packet::ConnectNotification(ConnectNotification { connection_id })
        )
    }
    /** Construct DisconnectNotification and send it to Client ignoring IO error
    */
    pub fn send_disconnect_notification(&self, connection_id: ConnectionId) -> impl Future<Output = Result<(), Error>> + Send {
        self.send_ignore_error(
            Packet::DisconnectNotification(DisconnectNotification { connection_id })
        )
    }
    /** Construct PongResponse and send it to Client
    */
    pub fn send_pong_response(&self, ping_id: u64) -> impl Future<Output = Result<(), Error>> + Send {
        self.send(
            Packet::PongResponse(PongResponse { ping_id })
        )
    }
    /** Construct OobReceive and send it to Client ignoring IO error
    */
    pub fn send_oob(&self, sender_pk: &PublicKey, data: Vec<u8>) -> impl Future<Output = Result<(), Error>> + Send {
        self.send_ignore_error(
            Packet::OobReceive(OobReceive { sender_pk: *sender_pk, data })
        )
    }
    /** Construct OnionResponse and send it to Client
    */
    pub fn send_onion_response(&self, payload: InnerOnionResponse) -> impl Future<Output = Result<(), Error>> + Send {
        self.send(
            Packet::OnionResponse(OnionResponse { payload })
        )
    }
    /** Construct Data and send it to Client
    */
    pub fn send_data(&self, connection_id: ConnectionId, data: DataPayload) -> impl Future<Output = Result<(), Error>> + Send {
        self.send(
            Packet::Data(Data { connection_id, data })
        )
    }
    /** Construct PingRequest and send it to Client
    */
    pub fn send_ping_request(&mut self) -> impl Future<Output = Result<(), Error>> + Send {
        let ping_id = gen_ping_id();

        self.last_pinged = Instant::now();
        self.ping_id = ping_id;

        self.send(
            Packet::PingRequest(PingRequest { ping_id })
        )
    }
}
