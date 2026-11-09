//! Resource budget for functional encrypted-DNS loopback tests.

use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

pub const IO_TIMEOUT_MS: u64 = 10_000;
pub const IO_TIMEOUT: Duration = Duration::from_millis(IO_TIMEOUT_MS);

static NETWORK_TEST: Mutex<()> = Mutex::new(());

pub fn serial() -> MutexGuard<'static, ()> {
    NETWORK_TEST
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}
