/*! Onion module allows nodes to announce their long term public keys and find
friends by their long term public keys.

There are two basic onion requests - `OnionAnnounceRequest` and
`OnionDataRequest`. They are enclosed to OnionRequest packets and sent though
the onion path to prevent nodes finding out long term public key when they know
only temporary DHT public key. There are three types of OnionRequest packets:
`OnionRequest0`, `OnionRequest1` and `OnionRequest2`. `OnionAnnounceRequest` and
`OnionDataRequest` when created are enclosed to `OnionRequest2`, `OnionRequest2`
is enclosed to `OnionRequest1` and `OnionRequest1` is enclosed to
`OnionRequest0`. When DHT node receives OnionRequest packet it decrypts inner
packet and sends it to the next node.

<pre style="white-space:pre;">
+--------+                       +--------+                       +--------+                       +--------+   +----------------------+   +------------+
|        |   +---------------+   |        |   +---------------+   |        |   +---------------+   |        |   | OnionAnnounceRequest |   |            |
| Sender |---| OnionRequest0 |-->| Node 1 |---| OnionRequest1 |-->| Node 2 |---| OnionRequest2 |-->| Node 3 |---+----------------------+-->| Onion node |
|        |   +---------------+   |        |   +---------------+   |        |   +---------------+   |        |   | OnionDataRequest     |   |            |
+--------+                       +--------+                       +--------+                       +--------+   +----------------------+   +------------+
</pre>

Similarly to requests there are responses `OnionAnnounceResponse` and
`OnionDataResponse` that enclosed to three kind of OnionRespose packets:
`OnionResponse3`, `OnionResponse2` and `OnionResponse1`. OnionResponse
packets are processed in the same way but with reverse ordering.

<pre style="white-space:pre;">
+------------+                        +--------+                        +--------+                        +--------+   +-----------------------+   +----------+
|            |   +----------------+   |        |   +----------------+   |        |   +----------------+   |        |   | OnionAnnounceResponse |   |          |
| Onion node |---| OnionResponse3 |-->| Node 3 |---| OnionResponse2 |-->| Node 2 |---| OnionResponse1 |-->| Node 1 |---+-----------------------+-->| Receiver |
|            |   +----------------+   |        |   +----------------+   |        |   +----------------+   |        |   | OnionDataResponse     |   |          |
+------------+                        +--------+                        +--------+                        +--------+   +-----------------------+   +----------+
</pre>

When onion node handles `OnionAnnounceRequest` packet it sends answer to
original sender using the same onion path with the help of received onion return
addresses. But when it handles `OnionDataRequest` packet it should send response
packet to another destination node by its long term public key. That means that
when onion node should store long term public keys of announced node along with
onion return addresses.

*/

pub mod client;
pub mod onion_announce;
pub mod packet;
