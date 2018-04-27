# 0.0.4 (April 27, 2018)

* Implement OnionAnnounce struct (#77)
* Use InnerOnionResponse as onion response payload (#85)
* Handle onion request/response packets in DHT Node (#88)
* Handle OnionAnnounceRequest/OnionDataRequest packets (#106)
* Add sender's address to TCP's onion sink (#113)
* Update TCP onion packets (#115)
* Migrate to parking_lot::RwLock instead of std (#82)
* Refactor DHT Node, remove client struct (#96)
* Fix "Decrypting DhtRequest failed" (#102)
* Add TCP Relay client connection (#10)
* Improve TCP Relay tests (#103)
* Add hash of pings to DHT server (#98)
* Fix ".ping_id does not match" (#86, #87)
* Migrate to tokio-timer v0.2 (#108)
* Remove timedout clients from DHT Node (#73)
* Remove useless union value from decryption errors (#110)
* Implement Lan Discovery handler (#71, #78)
* Split Onion, TCP, DHT Packet into multiple files (#72, #83, #109)
* Move to our IoFuture since it is going to be deprecated in tokio (#112)

# 0.0.3 (March 27, 2018)

* Parse all Onion packets (#50)
* Update Onion docs (#46)
* Enable OsX builds in CI (#62)
* Multithreaded TCP Relay (#58)
* Multithreaded DHT Node (#65)
* Update DHT Codec (#48)
* Fix clippy warnings (#63, #64)

# 0.0.2 (March 7, 2018)

* Parse TCP all packets
* Parse DHT Ping/Nat/NodesRequest/NodeResponse packets
* Parse Onion Request/Response packets
* Add example for TCP Relay
* Add example for DHT Node

# 0.0.1 (December 31, 2014)

* Squatter release (we did not make it)
