/*! Common utility functions
*/

use rand::Rng;

/// Generate non-zero ping_id
pub fn gen_ping_id<R: Rng>(rng: &mut R) -> u64 {
    let mut ping_id = 0;
    while ping_id == 0 {
        ping_id = rng.gen();
    }
    ping_id
}
