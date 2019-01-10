//! LRU cache for `PrecomputedKey`s.

use std::sync::Arc;

use lru::LruCache;
use parking_lot::Mutex;

use crate::toxcore::crypto_core::*;

/// LRU cache for `PrecomputedKey`s.
///
/// Calculation of `PrecomputedKey` from the `PublicKey`-`SecretKey` pair is an
/// expensive operation. `PrecomputedKey`s should be cached whenever possible
/// and reused later.
#[derive(Clone)]
pub struct PrecomputedCache {
    sk: SecretKey,
    precomputed_keys: Arc<Mutex<LruCache<PublicKey, PrecomputedKey>>>,
}

impl PrecomputedCache {
    /// Create new `PrecomputedCache`.
    pub fn new(sk: SecretKey, capacity: usize) -> PrecomputedCache {
        PrecomputedCache {
            sk,
            precomputed_keys: Arc::new(Mutex::new(LruCache::new(capacity))),
        }
    }

    /// Get `PrecomputedKey` for the given `PublicKey`.
    pub fn get(&self, pk: PublicKey) -> PrecomputedKey {
        let mut keys = self.precomputed_keys.lock();

        if let Some(precomputed_key) = keys.get(&pk) {
            return precomputed_key.clone();
        }

        let precomputed_key = precompute(&pk, &self.sk);
        keys.put(pk, precomputed_key.clone());
        precomputed_key
    }
}
