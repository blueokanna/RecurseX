//! Bounded, cancellation-aware frame I/O for accepted TCP connections.
//!
//! Preserve partial progress across polling timeouts. A single absolute
//! deadline applies to the entire operation, including short reads/writes.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn poll_timeout(shutdown: &AtomicBool, deadline: Instant) -> Option<Duration> {
    if shutdown.load(Ordering::Relaxed) {
        return None;
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        None
    } else {
        Some(remaining.min(Duration::from_millis(super::SHUTDOWN_POLL_MS)))
    }
}

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// `false` means EOF, shutdown or deadline: callers must close the connection
/// rather than interpret a partial frame as the next message.
pub(super) fn read_deadline(
    stream: &mut TcpStream,
    mut bytes: &mut [u8],
    shutdown: &AtomicBool,
    deadline: Instant,
) -> io::Result<bool> {
    while !bytes.is_empty() {
        let Some(timeout) = poll_timeout(shutdown, deadline) else {
            return Ok(false);
        };
        stream.set_read_timeout(Some(timeout))?;
        match stream.read(bytes) {
            Ok(0) => return Ok(false),
            Ok(count) => {
                bytes = bytes.get_mut(count..).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid TCP read count")
                })?
            }
            Err(error) if retryable(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

/// Bound the complete response, not each individual write. A slow reader
/// cannot keep a worker forever or prevent it from observing shutdown.
pub(super) fn write_deadline(
    stream: &mut TcpStream,
    bytes: &[u8],
    shutdown: &AtomicBool,
    deadline: Instant,
) -> io::Result<bool> {
    write_with_deadline(bytes, shutdown, deadline, |remaining, timeout| {
        stream.set_write_timeout(Some(timeout))?;
        stream.write(remaining)
    })
}

// Keep the progress/deadline policy independent of socket buffering. Tests can
// force short writes and errors without assuming platform-specific capacities.
fn write_with_deadline(
    mut bytes: &[u8],
    shutdown: &AtomicBool,
    deadline: Instant,
    mut write: impl FnMut(&[u8], Duration) -> io::Result<usize>,
) -> io::Result<bool> {
    while !bytes.is_empty() {
        let Some(timeout) = poll_timeout(shutdown, deadline) else {
            return Ok(false);
        };
        match write(bytes, timeout) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TCP response write made no progress",
                ))
            }
            Ok(count) => {
                bytes = bytes.get(count..).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid TCP write count")
                })?
            }
            Err(error) if retryable(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn read_preserves_partial_progress_across_poll_timeouts() {
        let (mut client, mut server) = pair();
        let worker = std::thread::spawn(move || {
            let mut bytes = [0; 4];
            assert!(read_deadline(
                &mut server,
                &mut bytes,
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(2)
            )
            .unwrap());
            bytes
        });
        client.write_all(&[0, 2]).unwrap();
        std::thread::sleep(Duration::from_millis(150));
        client.write_all(&[7, 9]).unwrap();
        assert_eq!(worker.join().unwrap(), [0, 2, 7, 9]);
    }

    #[test]
    fn a_partial_frame_followed_by_eof_is_not_complete() {
        let (mut client, mut server) = pair();
        client.write_all(&[0]).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(!read_deadline(
            &mut server,
            &mut [0; 2],
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(2)
        )
        .unwrap());
    }

    #[test]
    fn slow_partial_writes_cannot_restart_the_response_deadline() {
        let bytes = [7; 100];
        let mut sent = Vec::new();
        let began = Instant::now();
        let complete = write_with_deadline(
            &bytes,
            &AtomicBool::new(false),
            began + Duration::from_millis(50),
            |remaining, timeout| {
                assert!(timeout <= Duration::from_millis(super::super::SHUTDOWN_POLL_MS));
                std::thread::sleep(Duration::from_millis(10));
                sent.push(remaining[0]);
                Ok(1)
            },
        )
        .unwrap();
        assert!(!complete);
        assert!(sent.len() < bytes.len());
        assert!(began.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn shutdown_between_partial_writes_stops_the_frame() {
        let shutdown = AtomicBool::new(false);
        let mut sent = Vec::new();
        let complete = write_with_deadline(
            &[1, 2, 3, 4],
            &shutdown,
            Instant::now() + Duration::from_secs(10),
            |remaining, _| {
                sent.extend_from_slice(&remaining[..2]);
                shutdown.store(true, Ordering::Relaxed);
                Ok(2)
            },
        )
        .unwrap();
        assert!(!complete);
        assert_eq!(sent, [1, 2]);
    }

    #[test]
    fn short_and_interrupted_writes_preserve_the_frame() {
        let mut sent = Vec::new();
        let mut interrupted = true;
        assert!(write_with_deadline(
            &[1, 2, 3, 4],
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(2),
            |remaining, _| {
                if interrupted {
                    interrupted = false;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                sent.push(remaining[0]);
                Ok(1)
            }
        )
        .unwrap());
        assert_eq!(sent, [1, 2, 3, 4]);
        for kind in [io::ErrorKind::WriteZero, io::ErrorKind::BrokenPipe] {
            let mut calls = 0;
            let error = write_with_deadline(
                &[1],
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(2),
                |_, _| {
                    calls += 1;
                    if kind == io::ErrorKind::WriteZero {
                        Ok(0)
                    } else {
                        Err(kind.into())
                    }
                },
            )
            .unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(calls, 1);
        }
    }
}
