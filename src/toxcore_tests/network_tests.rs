/*
    Copyright © 2016-2017 Zetok Zalbavar <zexavexxe@gmail.com>

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

//! Tests for network module.


use tokio_core::reactor::Core;

use std::thread;
use std::time::Duration;

use toxcore::network::*;

// NetworkingCore::

// NetworkingCore::new()

#[test]
fn networking_core_new_test() {
    let core = Core::new().unwrap();
    let handle = core.handle();
    NetworkingCore::new("::".parse().unwrap(), 33445..33545, &handle).unwrap();
}


// NetworkingCore::new()

#[test]
fn networking_core_register_test() {
    use std::rc::Rc;
    use std::any::Any;
    use std::cell::RefCell;
    use std::net::SocketAddr;

    let core = Core::new().unwrap();
    let handle = core.handle();
    let mut net = NetworkingCore::new("::".parse().unwrap(), .., &handle).unwrap();
    fn callback(num: Rc<RefCell<Any>>, _: SocketAddr, _: &[u8]) -> usize {
        match num.borrow().downcast_ref::<usize>() {
            Some(_) => unimplemented!(),
            None => 0
        }
    }

    net.register(99, callback, Rc::new(RefCell::new(1usize)) as Rc<RefCell<Any>>);
}

// bind_udp()

#[test]
/* there's no way to reliably test whole range for both success and faliure;
   at least as long as there's no assumption that there are no other instances
   running.

   Thus test only whether binding to at least 50 ports works :/
*/
fn bind_udp_test() {
    for _ in 0..50 {
        thread::spawn(move || {
            let core = Core::new().unwrap();
            let handle = core.handle();
            let socket = bind_udp("::".parse().unwrap(), 33445..33546, &handle);
            match socket {
                Some(_) => {},
                None => panic!("This should have worked; bind_udp()"),
            }
            thread::sleep(Duration::from_millis(100)); // probably enough?
        });
    }
}
