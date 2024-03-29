/*! The inner implementation of client used only by relay server.
*/

use crate::relay::links::Links;
use crate::time::*;
use crate::utils::*;
use tox_crypto::*;
use tox_packet::relay::*;

use std::net::IpAddr;
use std::time::{Duration, Instant};

use futures::channel::mpsc;
use rand::thread_rng;

/// Interval of time for sending TCP PingRequest
pub const TCP_PING_FREQUENCY: Duration = Duration::from_secs(30);
/// Interval of time for waiting response of PingRequest sent
pub const TCP_PING_TIMEOUT: Duration = Duration::from_secs(10);

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
    last_pong_resp: Instant,
}

impl Client {
    /** Create new Client
     */
    pub fn new(tx: mpsc::Sender<Packet>, pk: &PublicKey, ip_addr: IpAddr, port: u16) -> Client {
        Client {
            pk: pk.clone(),
            ip_addr,
            port,
            tx,
            links: Links::new(),
            ping_id: 0,
            last_pinged: clock_now(),
            last_pong_resp: clock_now(),
        }
    }

    /** PK of the `Client`
     */
    pub fn pk(&self) -> PublicKey {
        self.pk.clone()
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

    pub fn tx(&self) -> mpsc::Sender<Packet> {
        self.tx.clone()
    }

    pub fn new_ping_id(&mut self) -> u64 {
        let ping_id = gen_ping_id(&mut thread_rng());

        self.last_pinged = Instant::now();
        self.ping_id = ping_id;

        ping_id
    }
}
