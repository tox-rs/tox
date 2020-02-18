/*! State format – for saving / loading data across restarts.

*Currently there's only supported old, custom binary format used by toxcore. At
some point it will be deprecated in favour of something better.*

*After deprecation of the old format there will be a period where it still will
be supported. After deprecation period code for handling old format will be
moved out of toxcore into a separate library and maintained there.*

https://zetok.github.io/tox-spec/#state-format
*/


// FIXME: use new dht code instead of old
pub mod old;
