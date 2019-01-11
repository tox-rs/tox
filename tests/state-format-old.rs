use tox::toxcore::binary_io::*;
use tox::toxcore::state_format::old::*;

/*
Load bytes of a real™ profile, de-serialize it and serialize again. Serialized
again bytes must be identical, except for the zeros that trail after the data
in original implementation – they're ommited. Just check if smaller length of
the resulting bytes are in fact due to original being appended with `0`s.
*/

#[test]
fn load_old_state_format_with_contacts() {
    let bytes = include_bytes!("data/old-profile-with-contacts.tox");

    let (_rest, profile) = State::from_bytes(bytes).unwrap();

    let mut buf = [0; 1024 * 1024];
    let (_, size) = profile.to_bytes((&mut buf, 0)).unwrap();

    assert_eq!(&bytes[..size], &buf[..size]);

    // c-toxcore appends `0`s after EOF because reasons
    for b in &bytes[size..] {
        assert_eq!(0, *b);
    }
}

#[test]
fn load_old_state_format_no_friends() {
    let bytes = include_bytes!("data/old-profile-no-friends.tox");

    let (_rest, profile) = State::from_bytes(bytes).unwrap();

    let mut buf = [0; 1024 * 1024];
    let (_, size) = profile.to_bytes((&mut buf, 0)).unwrap();

    assert_eq!(&bytes[..size], &buf[..size]);

    // c-toxcore appends `0`s after EOF because reasons
    for b in &bytes[size..] {
        assert_eq!(0, *b);
    }
}
