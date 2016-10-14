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
use super::regex::Regex;

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::toxid::*;


// NoSpam::

#[cfg(test)]
fn no_spam_no_empty(ns: &NoSpam) {
    // shouldn't be empty, unless your PRNG is crappy
    assert!(ns.0 != [0; NOSPAMBYTES])
}

// NoSpam::new()

#[test]
fn no_spam_new_test() {
    let ns = NoSpam::new();
    no_spam_no_empty(&ns);
}

// NoSpam::default()

#[test]
fn no_spam_default_test() {
    let ns = NoSpam::default();
    no_spam_no_empty(&ns);
}

// NoSpam::fmt()

#[test]
fn no_spam_fmt_test() {
    // check if formatted NoSpam is always upper-case hexadecimal with matching
    // length
    let re = Regex::new("^([0-9A-F]){8}$").expect("Creating regex failed!");
    let nospam = NoSpam::new();
    assert_eq!(true, re.is_match(&format!("{:X}", nospam)));
    assert_eq!(true, re.is_match(&format!("{}", nospam)));
    assert_eq!(true, re.is_match(&format!("{:X}", NoSpam([0, 0, 0, 0]))));
    assert_eq!(true, re.is_match(&format!("{}", NoSpam([0, 0, 0, 0]))));
    assert_eq!(true, re.is_match(&format!("{:X}", NoSpam([15, 15, 15, 15]))));
    assert_eq!(true, re.is_match(&format!("{}", NoSpam([15, 15, 15, 15]))));
}

// NoSpam::from_bytes()

#[test]
fn no_spam_from_bytes_test() {
    fn with_bytes(bytes: Vec<u8>) {
        if bytes.len() < NOSPAMBYTES {
            assert_eq!(None, NoSpam::from_bytes(&bytes));
        } else {
            let nospam = NoSpam::from_bytes(&bytes)
                            .expect("Failed to get NoSpam!");
            assert_eq!(bytes[0], nospam.0[0]);
            assert_eq!(bytes[1], nospam.0[1]);
            assert_eq!(bytes[2], nospam.0[2]);
            assert_eq!(bytes[3], nospam.0[3]);
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));
}

// NoSpam::parse_bytes()

#[test]
fn no_spam_parse_bytes_rest_test() {
    fn with_bytes(bytes: Vec<u8>) {
        if bytes.len() >= NOSPAMBYTES {
            let Parsed(_, rest) = NoSpam::parse_bytes(&bytes)
                            .expect("Failed to get NoSpam!");
            assert_eq!(&bytes[NOSPAMBYTES..], rest);
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));
}


// ToxId::from_bytes()

#[test]
fn tox_id_from_bytes_test() {
    fn with_bytes(bytes: Vec<u8>) {
        if bytes.len() < TOXIDBYTES {
            assert_eq!(None, ToxId::from_bytes(&bytes));
        } else {
            let toxid = ToxId::from_bytes(&bytes)
                            .expect("Failed to get ToxId!");
            let PublicKey(ref pk) = toxid.pk;
            assert_eq!(pk, &bytes[..PUBLICKEYBYTES]);
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));
}

// ToxId::parse_bytes()

#[test]
fn tox_id_parse_bytes_rest_test() {
    fn with_bytes(bytes: Vec<u8>) {
        if bytes.len() >= TOXIDBYTES {
            let Parsed(_, rest) = ToxId::parse_bytes(&bytes)
                            .expect("Failed to get ToxId!");
            assert_eq!(&bytes[TOXIDBYTES..], rest);
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));
}

// ToxId::fmt()

#[test]
fn tox_id_fmt_test() {
    // check if formatted ToxId is always upper-case hexadecimal with matching
    // length
    let right = Regex::new("^([0-9A-F]){76}$").expect("Creating regex failed!");
    let wrong = Regex::new("F{76}").expect("Creating 2nd regexp failed!");
    let (pk, _) = gen_keypair();
    let toxid = ToxId::new(pk);
    assert_eq!(true, right.is_match(&format!("{:X}", toxid)));
    assert_eq!(true, right.is_match(&format!("{}", toxid)));
    assert_eq!(false, wrong.is_match(&format!("{:X}", toxid)));
    assert_eq!(false, wrong.is_match(&format!("{}", toxid)));
}
