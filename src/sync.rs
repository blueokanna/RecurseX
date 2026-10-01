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
//! rather than a failed lookup. The one reader/writer lock guards the manual
//! clock, which is a single `i128` read on every query and mutated only by the
//! caller driving it; it is revalidated by construction rather than by use,
//! and a panic while advancing it cannot invent a time. The crate also denies
//! `unsafe_code`, so a torn value cannot become undefined behaviour.
//!
//! The recovery is therefore deliberate, and it lives in exactly one place.
//! Introducing these types is what makes it *unanimous*: `.unwrap()` and
//! `unwrap_or_else(|e| e.into_inner())` were previously mixed across the same
//! kind of lock, which means the policy was decided per call site and nobody
//! could tell which choice a given site had made. With [`Mutex`] and [`RwLock`]
//! there is nothing to choose — their `lock`/`read`/`write` cannot fail, so a
//! call site cannot accidentally pick the panic.
//!
//! [`RwLock`] exists for the same reason and covers the one remaining raw lock
//! in the crate. It is not redundant with [`Mutex`]: the manual clock is read on
//! every query and written only by the caller driving it, so a reader/writer
//! split is the honest shape. The rule is about *which* type is used, not about
//! which standard module it is re-exported from.

use std::sync::{
    Mutex as StdMutex, MutexGuard, PoisonError, RwLock as StdRwLock, RwLockReadGuard,
    RwLockWriteGuard,
};

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

/// A [`std::sync::RwLock`] whose [`read`](RwLock::read) and
/// [`write`](RwLock::write) hand back guards even after the lock has been
/// poisoned.
///
/// Same recovery policy as [`Mutex`], and the same reasoning applies with one
/// addition specific to this shape: a reader/writer lock is the type whose
/// poisoning is most likely to be *reached*, because the write side is where a
/// mutation panic happens and the read side is where it is then observed. Every
/// subsequent read would take the panicking path, which is a strictly larger set
/// of call sites than the single writer that caused it.
#[derive(Debug, Default)]
pub struct RwLock<T> {
    inner: StdRwLock<T>,
}

impl<T> RwLock<T> {
    /// Wrap a value. Mirrors `std::sync::RwLock::new` aside from the recovery
    /// policy.
    pub const fn new(value: T) -> Self {
        Self {
            inner: StdRwLock::new(value),
        }
    }

    /// Take a shared guard, recovering from poisoning instead of panicking.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        self.inner.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Take an exclusive guard, recovering from poisoning instead of panicking.
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        self.inner.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Take a shared guard without blocking, or `None` if the lock is held for
    /// writing or unavailable.
    ///
    /// This exists for `Debug` and `Display` implementations, which must never
    /// block. A lock taken while formatting can deadlock, because formatting
    /// runs inside panic messages and while a caller may already hold the same
    /// lock — and re-entering a read while the current thread holds the write
    /// guard is the one case `std` documents as liable to deadlock *or* panic,
    /// neither of which is acceptable while a panic is already being reported.
    /// It reports a poisoned lock as unavailable too: that is the same "not
    /// freely readable" answer, and this path must never be the one that blocks
    /// or mutates.
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        self.inner.try_read().ok()
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

        assert!(
            outcome.is_err(),
            "the panic must have unwound through the guard"
        );
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

    /// The same point as `a_poisoned_mutex_is_still_usable`, for the
    /// reader/writer lock: the writer's panic must not turn every later read
    /// into a panic. This test is written through the *public* surface — a
    /// writer that panics inside the guard, then reads from other threads —
    /// because the failure it guards against is exactly "the read side inherited
    /// the write side's panic".
    #[test]
    fn a_poisoned_rwlock_is_still_usable() {
        let lock: RwLock<u32> = RwLock::new(1);
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut guard = lock.write();
            *guard = 9;
            panic!("deliberate: unwind while holding the write guard");
        }));
        std::panic::set_hook(previous);

        assert!(outcome.is_err(), "the panic must have unwound");
        assert!(
            lock.inner.is_poisoned(),
            "the lock must actually be poisoned, or this test proves nothing"
        );
        // The write survived, reads still work, and a later write still works.
        assert_eq!(*lock.read(), 9);
        *lock.write() = 10;
        assert_eq!(*lock.read(), 10);
        // Several readers at once, which is the whole reason this is not a Mutex.
        let a = lock.read();
        let b = lock.read();
        assert_eq!((*a, *b), (10, 10));
    }

    #[test]
    fn try_read_reports_a_write_held_lock_without_blocking() {
        let lock = RwLock::new(7u8);
        let guard = lock.write();
        assert!(
            lock.try_read().is_none(),
            "a write-held lock has no shared guard to hand out"
        );
        drop(guard);
        assert_eq!(lock.try_read().map(|g| *g), Some(7));
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
