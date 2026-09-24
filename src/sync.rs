//! A mutex that recovers from poisoning.
//!
//! `std::sync::Mutex` poisons itself when a thread panics while holding the
//! lock, and every later `lock().unwrap()` panics too. In a resolver that is an
//! amplifier: one bug on one thread, at any moment in the process's life,
//! converts into a permanent refusal to answer *any* query, because a poisoned
//! mutex stays poisoned forever and every future lock takes the same path. The
//! mutexes in this crate guard a cache, a popularity model, a rate limiter, and
//! connection pools. Each is either revalidated on use or safely discardable,
//! and none holds an invariant whose violation could turn into a wrong answer
//! rather than a failed lookup. The crate also denies `unsafe_code`, so a torn
//! value cannot become undefined behaviour.
//!
//! The recovery is therefore deliberate, and it lives in exactly one place.
//! Introducing this type is what makes it *unanimous*: `.unwrap()` and
//! `unwrap_or_else(|e| e.into_inner())` were previously mixed across the same
//! kind of lock, which means the policy was decided per call site and nobody
//! could tell which choice a given site had made. With [`Mutex`] there is
//! nothing to choose — its `lock` cannot fail, so a call site cannot
//! accidentally pick the panic.

use std::sync::{Mutex as StdMutex, MutexGuard, PoisonError};

/// A [`std::sync::Mutex`] whose [`lock`](Mutex::lock) hands back a guard even
/// after the mutex has been poisoned.
///
/// A drop-in for the standard mutex: the lock is still exclusive, the guard is
/// still a [`MutexGuard`], and `Condvar::wait` still accepts it. The only
/// difference is that a panic somewhere else cannot make this lock fatal.
#[derive(Debug, Default)]
pub struct Mutex<T> {
    inner: StdMutex<T>,
}

impl<T> Mutex<T> {
    /// Wrap a value. Mirrors `std::sync::Mutex::new` aside from the recovery
    /// policy.
    pub const fn new(value: T) -> Self {
        Self {
            inner: StdMutex::new(value),
        }
    }

    /// Take the lock, recovering from poisoning instead of panicking.
    ///
    /// Poisoning means another thread panicked while holding this lock. The
    /// panic was already the defect; refusing every subsequent lock would
    /// upgrade it from "one query failed" to "the resolver is down until it is
    /// restarted". The mutex stays poisoned, so later locks take this same
    /// path — there is no flag to reset and no state to remember.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Take the lock without blocking, or `None` if there is no guard to hand
    /// out.
    ///
    /// This exists for the `Debug` implementations, which must never block: a
    /// lock taken while formatting can deadlock, because formatting runs inside
    /// panic messages and while a caller may already hold the same lock. It
    /// reports a poisoned mutex as unavailable too — that is the same "not
    /// freely readable" answer, and this path must never be the one that blocks
    /// or mutates.
    ///
    /// `TryLockError` is not nameable on this crate's minimum supported Rust,
    /// which is no loss here: both failure modes want the same answer.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        self.inner.try_lock().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The point of the type: a panic on another thread while the lock is held
    /// must not make every later lock fail.
    #[test]
    fn a_poisoned_mutex_is_still_usable() {
        let m: Mutex<u32> = Mutex::new(1);
        // The panic below is the test's subject, not a failure, so its message
        // is silenced. `catch_unwind` returns, so the hook is always restored
        // before the first assertion.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut guard = m.lock();
            assert_eq!(*guard, 1);
            *guard = 9;
            panic!("deliberate: unwind while holding the lock");
        }));
        std::panic::set_hook(previous);

        assert!(outcome.is_err(), "the panic must have unwound through the guard");
        assert!(
            m.inner.is_poisoned(),
            "the mutex must actually be poisoned, or this test proves nothing"
        );
        // The write made before the panic is still there, and the lock is
        // usable again.
        assert_eq!(*m.lock(), 9);
        *m.lock() = 10;
        assert_eq!(*m.lock(), 10);
    }

    #[test]
    fn try_lock_reports_a_held_lock_without_blocking() {
        let m = Mutex::new(7u8);
        let guard = m.lock();
        assert!(m.try_lock().is_none(), "a held lock is not available");
        drop(guard);
        assert_eq!(m.try_lock().map(|g| *g), Some(7));
    }

    #[test]
    fn guards_are_exclusive_and_debug_is_available() {
        let m = Mutex::new(vec![1u8, 2]);
        {
            let mut guard = m.lock();
            guard.push(3);
        }
        assert_eq!(*m.lock(), vec![1, 2, 3]);
        // The crate requires `Debug` on every public type, so the derive has to
        // reach the guarded value rather than stopping at the wrapper.
        let rendered = std::format!("{m:?}");
        assert!(
            rendered.contains("[1, 2, 3]"),
            "Debug must show the guarded value, got {rendered}"
        );
    }
}
