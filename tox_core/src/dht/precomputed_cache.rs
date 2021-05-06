//! LRU cache for `SalsaBox`es.

use std::sync::Arc;

use crypto_box::SalsaBox;
use lru::LruCache;

use tox_crypto::*;
use futures::lock::Mutex;

/// LRU cache for `SalsaBox`es.
///
/// Calculation of `SalsaBox` from the `PublicKey`-`SecretKey` pair is an
/// expensive operation. `SalsaBox`es should be cached whenever possible
/// and reused later.
#[derive(Clone)]
pub struct PrecomputedCache {
    sk: SecretKey,
    precomputed_keys: Arc<Mutex<LruCache<PublicKey, SalsaBox>>>,
}

impl PrecomputedCache {
    /// Create new `PrecomputedCache`.
    pub fn new(sk: SecretKey, capacity: usize) -> PrecomputedCache {
        PrecomputedCache {
            sk,
            precomputed_keys: Arc::new(Mutex::new(LruCache::new(capacity))),
        }
    }

    /// Get `SalsaBox` for the given `PublicKey`.
    pub async fn get(&self, pk: PublicKey) -> SalsaBox {
        let mut keys = self.precomputed_keys.lock().await;

        if let Some(precomputed_key) = keys.get(&pk) {
            return precomputed_key.clone();
        }

        let precomputed_key = SalsaBox::new(&pk, &self.sk);
        keys.put(pk, precomputed_key.clone());
        precomputed_key
    }
}
