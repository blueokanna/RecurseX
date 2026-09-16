//! Client-facing DNS server (the Client Layer).
//!
//! Listens for plain UDP and TCP queries and answers them through the
//! resolver. Responses are built per query, truncated to the client's
//! advertised EDNS size with the TC bit set when they do not fit.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use crate::message::Message;
use crate::resolver::Resolver;

/// Server tuning.
#[derive(Clone, Copy, Debug)]
pub struct ServerConfig {
    /// Number of UDP receiver threads (each blocks in `recv_from`).
    pub udp_workers: usize,
    /// Number of resolution threads shared by the UDP and TCP paths.
    ///
    /// Datagrams are queued for these threads instead of each spawning its
    /// own, so the cost of a flood is bounded by the pool, not by how fast
    /// the attacker can send.
    pub udp_handlers: usize,
    /// Maximum queued UDP datagrams awaiting a handler. A full queue sheds
    /// the datagram, which is the only honest response under overload.
    pub udp_queue: usize,
    /// Maximum concurrent TCP connections (0 = unlimited).
    pub max_tcp_connections: usize,
    /// Close a TCP connection that sends nothing for this long (ms).
    ///
    /// TCP connections cost a thread each, so without an idle timeout a
    /// client can park threads for free by opening connections and never
    /// using them. RFC 7766 §6.2.3 recommends a few seconds to a few
    /// minutes; 30 s is long enough for a client between two queries on a
    /// kept-alive connection and short enough to bound the leak.
    pub tcp_idle_timeout_ms: u64,
    /// Maximum UDP receive buffer.
    pub udp_recv_buffer: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            udp_workers: 2,
            udp_handlers: 8,
            udp_queue: 1024,
            max_tcp_connections: 1024,
            tcp_idle_timeout_ms: 30_000,
            udp_recv_buffer: 4096,
        }
    }
}

/// How often a blocking loop wakes up to notice a shutdown request (ms).
/// The loops use socket/queue timeouts of this length while shutting down,
/// so the bound on shutdown latency is this value, not the loop interval.
const SHUTDOWN_POLL_MS: u64 = 100;

/// The client-facing DNS server.
///
/// Binds sockets, spawns a bounded set of threads, and answers through the
/// resolver. Every loop it starts can be stopped: [`Server::shutdown`] sets
/// a flag that the receiver, handler, accept and per-connection loops check
/// at least every 100 ms, after which [`Server::join`] returns and the
/// process can exit cleanly.
pub struct Server {
    resolver: Resolver,
    config: ServerConfig,
    /// Thread handles (kept alive by the server).
    handles: std::sync::Mutex<Vec<JoinHandle<()>>>,
    /// Live TCP connection count.
    tcp_connections: Arc<AtomicUsize>,
    /// Datagrams shed because the handler queue was full.
    udp_shed: Arc<AtomicU64>,
    /// Set by `shutdown`; every loop checks it.
    shutdown: Arc<AtomicBool>,
    /// TCP listeners to poke awake when shutting down.
    tcp_addrs: std::sync::Mutex<Vec<SocketAddr>>,
}

/// Live counters and thread count; the resolver's own `Debug` is reachable
/// through [`Server::resolver`].
impl core::fmt::Debug for Server {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Server(threads={}, tcp_connections={}, udp_shed={}, shutting_down={})",
            self.handles.lock().map(|h| h.len()).unwrap_or(0),
            self.tcp_connections.load(Ordering::Relaxed),
            self.udp_shed.load(Ordering::Relaxed),
            self.shutdown.load(Ordering::Relaxed)
        )
    }
}

impl Server {
    /// A server wrapping a resolver.
    pub fn new(resolver: Resolver) -> Self {
        Self::with_config(resolver, ServerConfig::default())
    }

    /// A server with custom tuning.
    pub fn with_config(resolver: Resolver, config: ServerConfig) -> Self {
        Self {
            resolver,
            config,
            handles: std::sync::Mutex::new(Vec::new()),
            tcp_connections: Arc::new(AtomicUsize::new(0)),
            udp_shed: Arc::new(AtomicU64::new(0)),
            shutdown: Arc::new(AtomicBool::new(false)),
            tcp_addrs: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Stop every loop this server started, then return.
    ///
    /// Queued datagrams and parked TCP connections are dropped: a shutdown
    /// is not a drain. A TCP connection is additionally woken by connecting
    /// to our own listener, because `accept` cannot be interrupted from the
    /// outside any other way.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let addrs: Vec<SocketAddr> = self.tcp_addrs.lock().map(|a| a.clone()).unwrap_or_default();
        for addr in addrs {
            // Wake the accept loop; the connection itself is dropped on the
            // floor by the loop when it sees the flag.
            let _ = TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(200));
        }
    }

    /// Whether a shutdown has been requested.
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// The underlying resolver.
    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    /// Datagrams dropped because the handler queue was full (overload
    /// counter; non-zero means the pool is saturated).
    pub fn udp_shed(&self) -> u64 {
        self.udp_shed.load(Ordering::Relaxed)
    }

    /// Bind a UDP socket and start the receiver and handler pools. Returns
    /// the bound address (useful with port 0).
    ///
    /// Receivers are spawned *before* handlers: if a receiver thread cannot
    /// be created, this returns an error while nothing is blocked waiting on
    /// a queue that will never be fed.
    pub fn bind_udp(&self, addr: SocketAddr) -> std::io::Result<SocketAddr> {
        let sock = Arc::new(UdpSocket::bind(addr)?);
        let local = sock.local_addr()?;
        // A receive timeout is what makes the receiver loop interruptible:
        // it wakes up at least once per `SHUTDOWN_POLL_MS` to check the flag.
        sock.set_read_timeout(Some(std::time::Duration::from_millis(SHUTDOWN_POLL_MS)))?;
        let queue = Arc::new(WorkQueue::new(
            self.config.udp_queue.max(self.config.udp_handlers.max(1)),
            self.shutdown.clone(),
        ));
        for _ in 0..self.config.udp_workers.max(1) {
            let sock = sock.clone();
            let queue = queue.clone();
            let shed = self.udp_shed.clone();
            let shutdown = self.shutdown.clone();
            let handle = std::thread::Builder::new()
                .name("dns-udp-recv".into())
                .spawn(move || udp_recv_loop(sock, queue, shed, shutdown))?;
            self.handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(handle);
        }
        for _ in 0..self.config.udp_handlers.max(1) {
            let queue = queue.clone();
            let resolver = self.resolver.clone();
            let handle = std::thread::Builder::new()
                .name("dns-udp-handler".into())
                .spawn(move || udp_handler_loop(queue, resolver))?;
            self.handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(handle);
        }
        Ok(local)
    }

    /// Bind a TCP listener and start the accept loop. Returns the bound
    /// address.
    pub fn bind_tcp(&self, addr: SocketAddr) -> std::io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr)?;
        let local = listener.local_addr()?;
        let resolver = self.resolver.clone();
        let max = self.config.max_tcp_connections;
        let conns = self.tcp_connections.clone();
        let shutdown = self.shutdown.clone();
        let idle = self.config.tcp_idle_timeout_ms;
        let handle = std::thread::Builder::new()
            .name("dns-tcp-accept".into())
            .spawn(move || tcp_accept_loop(listener, resolver, max, conns, shutdown, idle))?;
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(handle);
        self.tcp_addrs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(local);
        Ok(local)
    }

    /// Block until every server thread has exited.
    ///
    /// Returns once [`Server::shutdown`] has been called: until then the
    /// loops are meant to run forever, so this blocks forever too.
    pub fn join(&self) {
        let handles: Vec<JoinHandle<()>> = self
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .collect();
        for h in handles {
            let _ = h.join();
        }
    }
}

/// One queued datagram, owned by a handler thread.
struct UdpJob {
    bytes: Vec<u8>,
    src: SocketAddr,
    sock: Arc<UdpSocket>,
}

/// A bounded FIFO with a condition variable, used as the datagram queue.
///
/// It is closable so a handler parked on an empty queue can be released at
/// shutdown; `pop` returns `None` once the server is stopping and the queue
/// is empty.
struct WorkQueue<T> {
    inner: Mutex<VecDeque<T>>,
    cv: Condvar,
    capacity: usize,
    shutdown: Arc<AtomicBool>,
}

impl<T> WorkQueue<T> {
    fn new(capacity: usize, shutdown: Arc<AtomicBool>) -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
            capacity: capacity.max(1),
            shutdown,
        }
    }

    /// Enqueue an item. Returns `false` — dropping the item — when the
    /// queue is full; shedding is the correct overload behaviour, since
    /// queueing without bound would just move the flood into memory.
    fn push(&self, item: T) -> bool {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() >= self.capacity || self.shutdown.load(Ordering::Relaxed) {
            return false;
        }
        q.push_back(item);
        self.cv.notify_one();
        true
    }

    /// Block until an item is available, or return `None` when the server
    /// is shutting down.
    fn pop(&self) -> Option<T> {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(item) = q.pop_front() {
                return Some(item);
            }
            if self.shutdown.load(Ordering::Relaxed) {
                self.cv.notify_all();
                return None;
            }
            let (guard, _) = self
                .cv
                .wait_timeout(q, std::time::Duration::from_millis(SHUTDOWN_POLL_MS))
                .unwrap_or_else(|e| e.into_inner());
            q = guard;
        }
    }
}

/// Receiver loop: read a datagram, hand it to the handler pool.
fn udp_recv_loop(
    sock: Arc<UdpSocket>,
    queue: Arc<WorkQueue<UdpJob>>,
    shed: Arc<AtomicU64>,
    shutdown: Arc<AtomicBool>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            // Read timeout (and, on Windows, a stray ICMP error reported on
            // a bound socket): check the flag and try again.
            Err(_) => continue,
        };
        let job = UdpJob {
            bytes: buf[..n].to_vec(),
            src,
            sock: sock.clone(),
        };
        if !queue.push(job) {
            shed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Handler loop: answer one queued datagram, send the response.
fn udp_handler_loop(queue: Arc<WorkQueue<UdpJob>>, resolver: Resolver) {
    while let Some(job) = queue.pop() {
        // UDP answers are truncated to the client's advertised EDNS payload
        // size (RFC 6891 §6.2.5), so we never emit an oversized,
        // fragmenting datagram or amplify past the client's buffer.
        let udp_limit = Message::parse(&job.bytes)
            .ok()
            .and_then(|q| q.edns.map(|e| e.udp_payload_size as usize))
            .unwrap_or(512);
        let response = answer(&resolver, &job.bytes, Some(job.src.ip()), Some(udp_limit));
        let _ = job.sock.send_to(&response, job.src);
    }
}

fn tcp_accept_loop(
    listener: TcpListener,
    resolver: Resolver,
    max: usize,
    conns: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
    idle_ms: u64,
) {
    for stream in listener.incoming() {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        let Ok(stream) = stream else {
            continue;
        };
        let resolver = resolver.clone();
        let conns = conns.clone();
        // Bound concurrent connections.
        if max > 0 && conns.load(Ordering::Relaxed) >= max {
            continue;
        }
        let shutdown = shutdown.clone();
        conns.fetch_add(1, Ordering::Relaxed);
        let _ = std::thread::Builder::new()
            .name("dns-tcp".into())
            .spawn(move || {
                let _ = tcp_conn(stream, resolver, &shutdown, idle_ms);
                conns.fetch_sub(1, Ordering::Relaxed);
            });
    }
}

/// Read exactly `buf.len()` bytes under a deadline, tolerating socket
/// timeouts.
///
/// `read_exact` cannot be used here: it gives up on the first timeout, and a
/// partial read would leave the stream out of sync with the framing. Reading
/// in a loop keeps the protocol state intact while still letting the caller
/// enforce a deadline between reads. Returns `false` when the connection
/// should be closed (peer closed, deadline passed, or shutdown).
fn read_deadline(
    stream: &mut TcpStream,
    buf: &mut [u8],
    shutdown: &AtomicBool,
    deadline: std::time::Instant,
) -> std::io::Result<bool> {
    let mut filled = 0usize;
    while filled < buf.len() {
        if shutdown.load(Ordering::Relaxed) || std::time::Instant::now() >= deadline {
            return Ok(false);
        }
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Ok(false), // peer closed cleanly
            Ok(n) => filled += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                // Socket poll interval; the deadline above is the real bound.
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Serve length-prefixed queries on one connection until the peer closes it,
/// it goes idle for `idle_ms`, or the server shuts down.
///
/// Two deadlines apply, and they bound different things: the *idle* deadline
/// (time since the last complete message) reclaims a thread from a client
/// that holds a connection open without using it, and the *message* deadline
/// bounds a client that drips bytes forever to keep the thread alive without
/// ever completing a query.
fn tcp_conn(
    mut stream: TcpStream,
    resolver: Resolver,
    shutdown: &AtomicBool,
    idle_ms: u64,
) -> std::io::Result<()> {
    let client_ip = stream.peer_addr().ok().map(|p| p.ip());
    let idle = std::time::Duration::from_millis(idle_ms.max(SHUTDOWN_POLL_MS));
    let message_timeout = std::time::Duration::from_secs(10).min(idle);
    stream.set_read_timeout(Some(std::time::Duration::from_millis(SHUTDOWN_POLL_MS)))?;
    stream.set_write_timeout(Some(idle))?;

    loop {
        let mut len_buf = [0u8; 2];
        if !read_deadline(
            &mut stream,
            &mut len_buf,
            shutdown,
            std::time::Instant::now() + idle,
        )? {
            return Ok(());
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return Ok(());
        }
        let mut query = vec![0u8; len];
        if !read_deadline(
            &mut stream,
            &mut query,
            shutdown,
            std::time::Instant::now() + message_timeout,
        )? {
            return Ok(());
        }
        // TCP carries full responses; no truncation.
        let response = answer(&resolver, &query, client_ip, None);
        let mut framed = Vec::with_capacity(response.len() + 2);
        framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
        framed.extend_from_slice(&response);
        stream.write_all(&framed)?;
    }
}

/// Answer one query, returning the wire response. When `udp_limit` is set,
/// the response is truncated to that many bytes with the TC bit (RFC 6891).
fn answer(
    resolver: &Resolver,
    query_bytes: &[u8],
    client_ip: Option<IpAddr>,
    udp_limit: Option<usize>,
) -> Vec<u8> {
    match Message::parse(query_bytes) {
        Ok(query) => {
            let mut resp = resolver.handle_query(&query, client_ip);
            if let Some(limit) = udp_limit {
                resp.truncate_for_udp(limit);
            }
            match resp.to_bytes() {
                Ok(bytes) => bytes,
                Err(_) => query
                    .error_response(crate::qtype::Rcode::SERVFAIL)
                    .to_bytes()
                    .unwrap_or_default(),
            }
        }
        Err(_) => {
            // Unparseable query: FORMERR, but echo the 16-bit ID and the RD
            // bit straight out of the header so a client can still match the
            // response to its request.
            let mut m = Message::new(query_id(query_bytes));
            m.flags.qr = true;
            m.flags.ra = true;
            m.flags.rd = query_bytes.get(2).map(|b| b & 0x01 != 0).unwrap_or(false);
            m.flags.rcode = crate::qtype::Rcode::FORMERR;
            m.to_bytes().unwrap_or_default()
        }
    }
}

/// The message ID from a raw query, when the two bytes are present.
fn query_id(bytes: &[u8]) -> u16 {
    match (bytes.first(), bytes.get(1)) {
        (Some(&hi), Some(&lo)) => u16::from_be_bytes([hi, lo]),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::Name;
    use crate::qtype::{Rcode, RrClass, RrType};
    use crate::rdata::{RData, Record};
    use crate::resolver::ResolverConfig;

    /// A stub authoritative server: answers every query with one A record
    /// for the queried name. Tests point the resolver's root hints at it,
    /// so the whole client → resolver → upstream path is exercised without
    /// touching the public Internet.
    fn stub_upstream() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                let Ok((n, src)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                let Ok(q) = Message::parse(&buf[..n]) else {
                    continue;
                };
                let Some(question) = q.question() else {
                    continue;
                };
                let mut m = Message::new(q.id);
                m.flags.qr = true;
                m.flags.aa = true;
                m.flags.ra = true;
                m.flags.rd = q.flags.rd;
                m.questions.clone_from(&q.questions);
                m.answers.push(Record {
                    name: question.qname.clone(),
                    rr_type: question.qtype,
                    class: RrClass::IN,
                    ttl: 60,
                    rdata: RData::A("192.0.2.33".parse().unwrap()),
                });
                if let Ok(bytes) = m.to_bytes() {
                    let _ = sock.send_to(&bytes, src);
                }
            }
        });
        addr
    }

    fn resolver_pointed_at(addr: SocketAddr) -> Resolver {
        let mut cfg = ResolverConfig::default();
        cfg.engine.root_servers = vec![addr];
        cfg.engine.timeout_ms = 1_000;
        Resolver::new(cfg)
    }

    #[test]
    fn server_binds_and_answers_udp() {
        let upstream = stub_upstream();
        let server = Server::new(resolver_pointed_at(upstream));
        let addr = server.bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let query = Message::query(
            0x1234,
            Name::from_ascii("example.com").unwrap(),
            RrType::A,
            true,
        )
        .to_bytes()
        .unwrap();
        sock.send_to(&query, addr).unwrap();
        let mut buf = [0u8; 4096];
        sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let (n, _) = sock.recv_from(&mut buf).unwrap();
        let resp = Message::parse(&buf[..n]).unwrap();
        assert!(resp.flags.qr);
        assert_eq!(resp.id, 0x1234);
        assert_eq!(resp.flags.rcode, Rcode::NOERROR);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(
            resp.answers[0].rdata,
            RData::A("192.0.2.33".parse().unwrap())
        );
    }

    /// A client that advertises a small EDNS buffer must get a response
    /// that fits it, with TC set — never a datagram it cannot receive.
    #[test]
    fn server_truncates_udp_to_advertised_size() {
        let upstream = stub_upstream();
        let server = Server::new(resolver_pointed_at(upstream));
        let addr = server.bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut query = Message::query(
            0x2345,
            Name::from_ascii("example.com").unwrap(),
            RrType::A,
            true,
        );
        query.edns = Some(crate::edns::Edns::new(512));
        sock.send_to(&query.to_bytes().unwrap(), addr).unwrap();
        let mut buf = [0u8; 4096];
        sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let (n, _) = sock.recv_from(&mut buf).unwrap();
        assert!(n <= 512, "response was {n} bytes");
        let resp = Message::parse(&buf[..n]).unwrap();
        assert_eq!(resp.id, 0x2345);
    }

    /// Malformed input still gets a response a client can match by ID.
    #[test]
    fn server_answers_formerr_with_id() {
        let upstream = stub_upstream();
        let server = Server::new(resolver_pointed_at(upstream));
        let addr = server.bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        // A 4-byte "message": header ID, then garbage.
        sock.send_to(&[0xab, 0xcd, 0x01, 0x00], addr).unwrap();
        let mut buf = [0u8; 512];
        sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let (n, _) = sock.recv_from(&mut buf).unwrap();
        let resp = Message::parse(&buf[..n]).unwrap();
        assert_eq!(resp.id, 0xabcd);
        assert_eq!(resp.flags.rcode, Rcode::FORMERR);
    }

    #[test]
    fn server_answers_tcp() {
        let upstream = stub_upstream();
        let server = Server::new(resolver_pointed_at(upstream));
        let addr = server.bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
        let query = Message::query(
            0x4321,
            Name::from_ascii("example.com").unwrap(),
            RrType::A,
            true,
        )
        .to_bytes()
        .unwrap();
        let mut framed = Vec::new();
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(&query);
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        stream.write_all(&framed).unwrap();
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).unwrap();
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).unwrap();
        let resp = Message::parse(&body).unwrap();
        assert!(resp.flags.qr);
        assert_eq!(resp.id, 0x4321);
        assert_eq!(resp.answers.len(), 1);
    }

    /// Join a thread with a deadline, so a broken shutdown fails the test
    /// instead of hanging the whole suite.
    fn join_within(handle: JoinHandle<()>, secs: u64) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = handle.join();
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(secs))
            .is_ok()
    }

    /// Every loop the server starts must stop on request: receiver threads
    /// (parked in `recv_from`), handler threads (parked on the queue), the
    /// accept loop (parked in `accept`) and per-connection threads.
    #[test]
    fn shutdown_stops_every_loop() {
        let upstream = stub_upstream();
        let server = Server::new(resolver_pointed_at(upstream));
        let udp = server.bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        let tcp = server.bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();

        // Hold an idle TCP connection open so a per-connection thread exists.
        let idle_conn = TcpStream::connect(tcp).unwrap();
        // And make sure the UDP path is live.
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let query = Message::query(1, Name::from_ascii("example.com").unwrap(), RrType::A, true)
            .to_bytes()
            .unwrap();
        sock.send_to(&query, udp).unwrap();
        let mut buf = [0u8; 4096];
        sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        sock.recv_from(&mut buf).unwrap();

        assert!(!server.is_shutting_down());
        server.shutdown();
        assert!(server.is_shutting_down());
        assert!(
            join_within(std::thread::spawn(move || server.join()), 5),
            "join() must return once shutdown() has been called"
        );
        drop(idle_conn);
    }

    /// An idle TCP connection must not park a thread indefinitely, and a
    /// client that drips one byte must not extend its lifetime either.
    #[test]
    fn tcp_idle_and_drip_are_bounded() {
        let upstream = stub_upstream();
        let server = Server::with_config(
            resolver_pointed_at(upstream),
            ServerConfig {
                tcp_idle_timeout_ms: 200,
                ..ServerConfig::default()
            },
        );
        let addr = server.bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();

        // (a) Idle: open, send nothing, expect the server to close.
        let mut idle = TcpStream::connect(addr).unwrap();
        idle.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(
            idle.read(&mut byte).unwrap(),
            0,
            "an idle connection must be closed by the server"
        );

        // (b) Drip: send half a length prefix and stop.
        let mut drip = TcpStream::connect(addr).unwrap();
        drip.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        drip.write_all(&[0x00]).unwrap();
        assert_eq!(
            drip.read(&mut byte).unwrap(),
            0,
            "a partially framed message must not hold the thread"
        );

        server.shutdown();
        assert!(join_within(std::thread::spawn(move || server.join()), 5));
    }
}
