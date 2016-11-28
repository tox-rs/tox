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


//! File with testing macros. **Use only in tests!**


/// Assert that function with given data fails with given error.
macro_rules! contains_err {
    ($func: path, $data: expr, $error: expr) => (
        { // ← ensure that expanded macro won't interfere with other code
            let e = format!("{:?}", $func($data).unwrap_err());
            assert!(e.contains($error),
                    format!("e: {}", e));
        }
    )
}


/** Implement `Arbitrary` trait for given struct with bytes.

E.g.

```
#[cfg(test)]
use ::toxcore_tests::quickcheck::Arbitrary;

struct Name(Vec<u8>);

#[cfg(test)]
impl_arb_for_bytes!(Name, 100);
```
*/
// FIXME: ↑ make it a real test, since doctest doesn't work
macro_rules! impl_arb_for_bytes {
    ($name: ident, $len: expr) => (
        impl Arbitrary for $name {
            fn arbitrary<G: Gen>(g: &mut G) -> Self {
                let n = g.gen_range(0, $len + 1);
                let mut bytes = vec![0; n];
                g.fill_bytes(&mut bytes[..n]);
                $name(bytes)
            }
        }
    )
}


/** Implement `Arbitrary` for given struct containing only `PackedNodes`.

E.g.

```
use ::toxcore_tests::quickcheck::Arbitrary;
use ::toxcore::dht::*;

struct Nodes(Vec<PackedNode>);

impl_arb_for_pn!(Nodes);
```
*/
// FIXME: ↑ make it a real test, since doctest doesn't work
macro_rules! impl_arb_for_pn {
    ($name:ident) => (
        impl Arbitrary for $name {
            fn arbitrary<G: Gen>(g: &mut G) -> Self {
                $name(Arbitrary::arbitrary(g))
            }
        }
    )
}

/** PublicKey from bytes. Returns `TestResult::discard()` if there are not
enough bytes.
*/
macro_rules! quick_pk_from_bytes {
    ($input:ident, $out:ident) => (
        if $input.len() < PUBLICKEYBYTES {
            return TestResult::discard()
        }

        let $out = PublicKey::from_slice(&$input[..PUBLICKEYBYTES])
            .expect("Failed to make PK from slice");
    )
}
