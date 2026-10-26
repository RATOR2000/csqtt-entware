// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Preserve 64-bit counters and generations on MIPS32 without 64-bit atomics.
//! portable-atomic's safe lock fallback is required in Linux userspace; do not
//! enable its privileged interrupt or unsafe single-core assumptions.

#[cfg(target_has_atomic = "64")]
pub use std::sync::atomic::{AtomicI64, AtomicU64};

#[cfg(not(target_has_atomic = "64"))]
pub use portable_atomic::{AtomicI64, AtomicU64};

#[cfg(test)]
mod tests {
    use portable_atomic::{AtomicI64, AtomicU64, Ordering};
    use std::sync::Arc;

    #[test]
    fn portable_generations_cross_32_bits_under_contention() {
        let counter = Arc::new(AtomicU64::new(u32::MAX as u64 - 100));
        let threads: Vec<_> = (0..4).map(|_| {
            let counter = counter.clone();
            std::thread::spawn(move || {
                for _ in 0..1_000 { counter.fetch_add(1, Ordering::SeqCst); }
            })
        }).collect();
        for thread in threads { thread.join().unwrap(); }
        assert_eq!(counter.load(Ordering::SeqCst), u32::MAX as u64 + 3_900);
        let signed = AtomicI64::new(i32::MIN as i64 - 1);
        assert_eq!(signed.fetch_sub(1, Ordering::AcqRel), i32::MIN as i64 - 1);
        assert_eq!(signed.load(Ordering::Acquire), i32::MIN as i64 - 2);
    }
}
