/*
    Copyright © 2017 Zetok Zalbavar <zexavexxe@gmail.com>

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


// an example of DHT node with current code
//
// it's not supposed to be an actual example, more like try to find out
// which parts in zetox are still missing to make a DHT node easy to run
//
// to get some meaningful info, run it with `RUST_LOG` env variable
// set, e.g. `RUST_LOG="tox=debug,dht_node=debug"`

extern crate futures;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate tox;
extern crate tokio_core;
extern crate tokio_timer;
extern crate rustc_serialize;


use futures::*;
// to get bytes from PK in hex and to make PK from them
use rustc_serialize::hex::FromHex;
use tokio_core::reactor::Core;
use tokio_timer::*;

use std::net::SocketAddr;
use std::time::Duration;
use std::cell::RefCell;
use std::sync::Arc;

use tox::toxcore::crypto_core::*;
use tox::toxcore::dht::*;
use tox::toxcore::dht_node::*;
use tox::toxcore::network::*;
use tox::toxcore::timeout::*;

fn main() {
    env_logger::init();

    // the way RefCell is used below can result in a panic
    let node = Arc::new(RefCell::new(DhtNode::new().unwrap()));
    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let socket = bind_udp("::".parse().unwrap(), PORT_MIN..PORT_MAX, &handle)
        .unwrap();

    // get PK bytes of some "random" bootstrap node (Impyy's)
    let bootstrap_pk_bytes = FromHex::from_hex(
        "6FC41E2BD381D37E9748FC0E0328CE086AF9598BECC8FEB7DDF2E440475F300E")
        .unwrap();
    // create PK from bytes
    let bootstrap_pk = PublicKey::from_slice(&bootstrap_pk_bytes).unwrap();

                 //"51.15.37.145:33445".parse().unwrap()
    let saddr: SocketAddr = "51.15.37.145:33445".parse().unwrap();
    let bootstrap_pn = PackedNode::new(true, saddr, &bootstrap_pk);
    let (sink, stream) = socket.framed(ToxCodec).split();

    let timer = Timer::default();
    // GetNodes timeout
    let getn_time = timer.interval(Duration::from_secs(20));
    let eject_nodes = timer.interval(Duration::from_secs(1));

    let send_tx = send_packets(sink);

    // bootstrap
    // TODO: add method to DhtNode for adding timeouts ?
    //let req_some_nodes = send_tx.clone()
    //    .send(node.borrow_mut().request_nodes(&bootstrap_pn).map)
    //    .then(|_| Ok(()));
    //handle.spawn(req_some_nodes);

    // node will automatically "bootstrap", but bootstrapping is not
    // reliable, restarting a few times might be necessary to join the
    // network (bootstrapping from multiple nodes would help with that)
    assert!(node.borrow_mut().try_add(&bootstrap_pn));


    //// handle incoming stuff

    let deal_with_it = receive_packets(stream).for_each(|(addr, packet)| {
        debug!("Handling packet from {:?}", addr);
        let resp = node.borrow_mut().handle_packet(&packet);

        if let Some(r) = resp {
            let tx = send_tx.clone();
            handle.spawn(tx.send((addr, r)).then(|_| Ok(())));
        }

        Ok(())
    });

    // make getn requests
    let hc = core.handle();
    let send_tx = send_tx.clone();
    let getn_f = getn_time.then(|_| {
        debug!("Requesting nodes 20s");
        let requests = node.borrow_mut().request_nodes_close();
        for req in requests {
            let request_it = send_tx.clone()
                .send(req)
                .then(|_| Ok(()));
            hc.spawn(request_it);
        }
        Ok::<(), ()>(())
    }).for_each(|_| Ok(()));


    let eject = eject_nodes.then(|_| {
        //debug!("Checking for timed out nodes");
        node.borrow_mut().remove_timed_out(RESPONSE_CHECK);
        Ok(())
    }).for_each(|_| Ok(()));

    let joined = getn_f.join3(deal_with_it, eject);
    drop(core.run(joined));
}
