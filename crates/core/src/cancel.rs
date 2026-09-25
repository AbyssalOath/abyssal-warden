use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Cooperative cancellation flag shared between the caller and scan threads.
///
/// Cloning yields a handle to the same flag. Cancellation is one-way: once
/// cancelled, a token stays cancelled. Scan code polls the token between
/// files and between read chunks, so cancellation latency is bounded by the
/// time taken to read one chunk or evaluate one file with one detector.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    flag: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation. Safe to call from any thread, including a
    /// signal-handling thread, any number of times.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_state() {
        let a = CancellationToken::new();
        let b = a.clone();
        assert!(!b.is_cancelled());
        a.cancel();
        assert!(b.is_cancelled());
        a.cancel();
        assert!(a.is_cancelled());
    }
}
