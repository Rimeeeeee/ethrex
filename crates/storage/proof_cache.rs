//! Byte-charged LRU for immutable proof objects. Charges include lazy data.
use lru::LruCache;
use rustc_hash::FxBuildHasher;
use std::hash::Hash;

#[derive(Debug)]
pub(crate) struct ProofCache<K: Hash + Eq, V> {
    entries: LruCache<K, (V, usize), FxBuildHasher>,
    bytes: usize,
    budget: usize,
}

impl<K: Hash + Eq, V> ProofCache<K, V> {
    pub(crate) fn new(budget: usize) -> Self {
        Self {
            entries: LruCache::unbounded_with_hasher(FxBuildHasher),
            bytes: 0,
            budget,
        }
    }

    pub(crate) fn get(&mut self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|(value, _)| value)
    }

    pub(crate) fn put(&mut self, key: K, value: V, bytes: usize) {
        // Charge cache bookkeeping as well, including for empty tables.
        let bytes = bytes.saturating_add(std::mem::size_of::<K>() + 128);
        if let Some((_, previous)) = self.entries.pop(&key) {
            self.bytes -= previous;
        }
        if bytes > self.budget {
            return;
        }
        while self.bytes > self.budget - bytes {
            if let Some((_, (_, removed))) = self.entries.pop_lru() {
                self.bytes -= removed;
            } else {
                break;
            }
        }
        self.entries.put(key, (value, bytes));
        self.bytes += bytes;
    }

    pub(crate) fn set_budget(&mut self, budget: usize) {
        self.budget = budget;
        while self.bytes > budget {
            if let Some((_, (_, bytes))) = self.entries.pop_lru() {
                self.bytes -= bytes;
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charges_bytes_updates_recency_and_replaces_weights() {
        let charge = 10 + std::mem::size_of::<u64>() + 128;
        let mut cache = ProofCache::new(2 * charge);
        cache.put(1u64, "a", 10);
        cache.put(2, "b", 10);
        assert_eq!(cache.get(&1), Some(&"a"));
        cache.put(3, "c", 10);
        assert!(cache.get(&2).is_none());
        cache.put(1, "large", 10 + charge);
        assert!(cache.get(&3).is_none());
        assert_eq!(cache.bytes, 2 * charge);
        cache.put(1, "oversized", 3 * charge);
        assert!(cache.get(&1).is_none());
        assert_eq!(cache.bytes, 0);
        cache.put(4, "d", 10);
        cache.set_budget(0);
        assert!(cache.get(&4).is_none());
        cache.put(5, "e", 0);
        assert_eq!(cache.bytes, 0);
    }
}
