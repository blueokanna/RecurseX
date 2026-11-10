//! A monotonic deadline shared by connection, framing and payload I/O.

use crate::error::{Error, ErrorKind, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

#[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
pub(crate) fn certificate_time(fixed: i64) -> Result<i64> {
    if fixed != 0 {
        return Ok(fixed);
    }
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::config("certificate validation requires a valid system clock"))?
        .as_secs();
    i64::try_from(seconds)
        .map_err(|_| Error::config("certificate clock is outside the supported range"))
}

#[derive(Clone, Copy)]
pub(crate) struct Deadline(Instant);

impl Deadline {
    #[cfg(feature = "doq")]
    pub(crate) fn instant(self) -> Instant {
        self.0
    }
    pub(crate) fn after(timeout_ms: u64) -> Result<Self> {
        if timeout_ms == 0 {
            return Err(Error::new(
                ErrorKind::Timeout,
                "exchange deadline exhausted",
            ));
        }
        Instant::now()
            .checked_add(Duration::from_millis(timeout_ms))
            .map(Self)
            .ok_or_else(|| Error::config("exchange timeout is too large"))
    }

    pub(crate) fn remaining(self) -> std::io::Result<Duration> {
        let duration = self.0.saturating_duration_since(Instant::now());
        if duration.is_zero() {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "exchange deadline exhausted",
            ))
        } else {
            Ok(duration)
        }
    }

    #[cfg(feature = "doq")]
    pub(crate) fn remaining_ms(self) -> Result<u64> {
        self.remaining()
            .map(|remaining| remaining.as_millis().min(u64::MAX as u128).max(1) as u64)
            .map_err(|error| network_error("DoQ deadline", error))
    }
}

#[cfg(feature = "doq")]
pub(crate) fn lock_until<T>(
    mutex: &crate::sync::Mutex<T>,
    deadline: Deadline,
) -> Result<std::sync::MutexGuard<'_, T>> {
    loop {
        let remaining = deadline
            .remaining()
            .map_err(|error| network_error("DoQ pool wait", error))?;
        if let Some(guard) = mutex.try_lock() {
            return Ok(guard);
        }
        std::thread::sleep(remaining.min(Duration::from_millis(1)));
    }
}

#[cfg(any(feature = "doh", feature = "doq"))]
pub(crate) fn same_roots(
    left: &courierust::courierust_tls::RootStore,
    right: &courierust::courierust_tls::RootStore,
) -> bool {
    left.len() == right.len()
        && left
            .roots()
            .iter()
            .zip(right.roots())
            .all(|(a, b)| a.der == b.der)
}

pub(crate) fn network_error(context: &str, error: std::io::Error) -> Error {
    let kind = if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        ErrorKind::Timeout
    } else {
        ErrorKind::Io
    };
    Error::new(kind, format!("{context}: {error}"))
}

pub(crate) struct DeadlineStream<'a> {
    pub stream: &'a TcpStream,
    pub deadline: Deadline,
}

impl Read for DeadlineStream<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream
            .set_read_timeout(Some(self.deadline.remaining()?))?;
        self.stream.read(bytes)
    }
}

impl Write for DeadlineStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream
            .set_write_timeout(Some(self.deadline.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(feature = "dot")]
impl courierust::courierust_io::Read for DeadlineStream<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> courierust::courierust_error::Result<usize> {
        Read::read(self, bytes).map_err(Into::into)
    }
}

#[cfg(feature = "dot")]
impl courierust::courierust_io::Write for DeadlineStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> courierust::courierust_error::Result<usize> {
        Write::write(self, bytes).map_err(Into::into)
    }
    fn flush(&mut self) -> courierust::courierust_error::Result<()> {
        Write::flush(self).map_err(Into::into)
    }
}
