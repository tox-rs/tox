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

extern crate tox;

use tox::toxcore::binary_io::*;
use tox::toxcore::state_format::old::*;

/*
Load bytes of a real™ profile, de-serialize it and serialize again. Serialized
again bytes must be identical, except for the zeros that trail after the data
in original implementation – they're ommited. Just check if smaller length of
the resulting bytes are in fact due to original being appended with `0`s.
*/

#[test]
fn test_state_format_to_and_from_bytes() {
    let bytes = include_bytes!("state-format-old-data/profile-with-contacts.tox");
    assert!(State::is_state(bytes));
    let profile_b = State::from_bytes(bytes).expect("Works.").to_bytes();
    assert_eq!(&bytes[..profile_b.len()], profile_b.as_slice());
    // c-toxcore appends `0`s after EOF because reasons
    for b in &bytes[profile_b.len()..] {
        assert_eq!(0, *b);
    }
}
