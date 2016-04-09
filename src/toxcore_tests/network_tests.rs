/*
    Copyright © 2016 Zetok Zalbavar <zexavexxe@gmail.com>

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


use std::thread;
use std::time::Duration;

use toxcore::network::*;

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
            let socket = bind_udp();
            match socket {
                Some(_) => {},
                None => panic!("This should have worked; bind_udp()"),
            }
            thread::sleep(Duration::from_millis(100)); // probably enough?
        });
    }
}
