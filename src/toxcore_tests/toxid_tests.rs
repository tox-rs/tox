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

//! Tests for `toxid` module.

use super::quickcheck::quickcheck;

use toxcore::toxid::*;


// NoSpam::new()

#[test]
fn no_spam_new_test() {
    // check if NoSpam is the same if created from bytes
    let nospam = NoSpam::new();
    let NoSpam(ns_bytes) = nospam;
    let nospam2 = NoSpam(ns_bytes);
    assert_eq!(nospam, nospam2);
}

// NoSpam::deref()

#[test]
fn no_spam_deref_test() {
    let nospam = NoSpam::new();
    let NoSpam(ns_bytes) = nospam;
    assert_eq!(*nospam, ns_bytes);
}
