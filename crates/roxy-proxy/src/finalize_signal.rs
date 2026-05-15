//! Deterministic signal that the background `tee_pump` task fires whenever
//! it consumes a cache writer (either `finish()` succeeded/failed or the
//! writer was aborted). Tests use this to await cache materialization
//! instead of sleeping for an arbitrary 200ms — see `roxy-2w1`.
//!
//! Production code constructs a default signal that nobody waits on; the
//! cost is one `Arc<FinalizeSignal>` per Handler and a single atomic
//! increment per response that touched the cache writer.

use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Notify;

#[derive(Default)]
pub struct FinalizeSignal {
    counter: AtomicU64,
    notify: Notify,
}

impl FinalizeSignal {
    /// Total number of cache-writer completions observed since this signal
    /// was created. Increments on both successful `finish()` and on
    /// `abort()` — both end the writer's lifetime, which is what waiters
    /// care about.
    pub fn count(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }

    /// Resolve once `count() >= target`. Race-free: registers as a waiter
    /// before checking the counter, so increments that race with the check
    /// still wake us. Safe to call repeatedly with the same or higher
    /// targets.
    pub async fn wait_for_count(&self, target: u64) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            // `enable()` registers the future as a waiter so a subsequent
            // `notify_waiters()` wakes it. Without this, the wake between
            // the count check below and the `.await` could be lost.
            notified.as_mut().enable();
            if self.count() >= target {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn record(&self) {
        self.counter.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn count_starts_at_zero_and_increments_on_record() {
        let s = FinalizeSignal::default();
        assert_eq!(s.count(), 0);
        s.record();
        assert_eq!(s.count(), 1);
        s.record();
        assert_eq!(s.count(), 2);
    }

    #[tokio::test]
    async fn wait_returns_immediately_when_target_already_met() {
        let s = FinalizeSignal::default();
        s.record();
        s.record();
        // wait_for_count(<=current) must resolve without blocking.
        tokio::time::timeout(Duration::from_millis(50), s.wait_for_count(2))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn wait_resolves_after_record() {
        let s = Arc::new(FinalizeSignal::default());
        let s2 = s.clone();
        let waiter = tokio::spawn(async move { s2.wait_for_count(1).await });
        // Yield so the waiter has a chance to enter the wait.
        tokio::task::yield_now().await;
        s.record();
        tokio::time::timeout(Duration::from_millis(50), waiter)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn record_during_wait_is_not_lost() {
        // Stress the race: spawn a waiter, immediately record. The race-free
        // `enable()-before-check` pattern means the waiter must always wake.
        for _ in 0..100 {
            let s = Arc::new(FinalizeSignal::default());
            let s2 = s.clone();
            let waiter = tokio::spawn(async move { s2.wait_for_count(1).await });
            s.record();
            tokio::time::timeout(Duration::from_millis(100), waiter)
                .await
                .unwrap()
                .unwrap();
        }
    }
}
