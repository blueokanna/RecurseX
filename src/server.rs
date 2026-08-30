//! Client-facing DNS server (the Client Layer).
//!
//! Listens for plain UDP and TCP queries and answers them through the
//! resolver. Responses are built per query, truncated to the client's
//! advertised EDNS size with the TC bit set when they do not fit.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::message::Message;
use crate::resolver::Resolver;

/// Server tuning.
#[derive(Clone, Copy, Debug)]
pub struct ServerConfig {
    /// Number of UDP receiver threads.
    pub udp_workers: usize,
    /// Maximum concurrent TCP connections (0 = unlimited).
    pub max_tcp_connections: usize,
    /// Maximum UDP receive buffer.
    pub udp_recv_buffer: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            udp_workers: 4,
            max_tcp_connections: 1024,
            udp_recv_buffer: 4096,
        }
    }
}

/// The client-facing DNS server.
pub struct Server {
    resolver: Resolver,
    config: ServerConfig,
    /// Thread handles (kept alive by the server).
    handles: std::sync::Mutex<Vec<JoinHandle<()>>>,
    /// Live TCP connection count.
    tcp_connections: Arc<AtomicUsize>,
}

impl Server {
    /// A server wrapping a resolver.
    pub fn new(resolver: Resolver) -> Self {
        Self {
            resolver,
            config: ServerConfig::default(),
            handles: std::sync::Mutex::new(Vec::new()),
            tcp_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// A server with custom tuning.
    pub fn with_config(resolver: Resolver, config: ServerConfig) -> Self {
        Self {
            resolver,
            config,
            handles: std::sync::Mutex::new(Vec::new()),
            tcp_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The underlying resolver.
    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    /// Bind a UDP socket and start the receiver pool. Returns the bound
    /// address (useful with port 0).
    pub fn bind_udp(&self, addr: SocketAddr) -> std::io::Result<SocketAddr> {
        let sock = Arc::new(UdpSocket::bind(addr)?);
        let local = sock.local_addr()?;
        let workers = self.config.udp_workers.max(1);
        for _ in 0..workers {
            let sock = sock.clone();
            let resolver = self.resolver.clone();
            let handle = std::thread::spawn(move || udp_loop(sock, resolver));
            self.handles.lock().unwrap().push(handle);
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
        let handle = std::thread::spawn(move || tcp_accept_loop(listener, resolver, max, conns));
        self.handles.lock().unwrap().push(handle);
        Ok(local)
    }

    /// Block until the server's threads exit (they never do on their own).
    pub fn join(&self) {
        let handles: Vec<JoinHandle<()>> = self.handles.lock().unwrap().drain(..).collect();
        for h in handles {
            let _ = h.join();
        }
    }
}

fn udp_loop(sock: Arc<UdpSocket>, resolver: Resolver) {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let query_bytes = buf[..n].to_vec();
        let responder = sock.clone();
        let resolver = resolver.clone();
        let _ = std::thread::Builder::new()
            .name("dns-udp".into())
            .spawn(move || {
                let client_ip = Some(src.ip());
                let response = answer(&resolver, &query_bytes, client_ip);
                let _ = responder.send_to(&response, src);
            });
    }
}

fn tcp_accept_loop(listener: TcpListener, resolver: Resolver, max: usize, conns: Arc<AtomicUsize>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        let resolver = resolver.clone();
        let conns = conns.clone();
        // Bound concurrent connections.
        if max > 0 && conns.load(Ordering::Relaxed) >= max {
            continue;
        }
        conns.fetch_add(1, Ordering::Relaxed);
        let _ = std::thread::Builder::new()
            .name("dns-tcp".into())
            .spawn(move || {
                let _ = tcp_conn(stream, resolver);
                conns.fetch_sub(1, Ordering::Relaxed);
            });
    }
}

fn tcp_conn(mut stream: TcpStream, resolver: Resolver) -> std::io::Result<()> {
    let peer = stream.peer_addr().ok();
    let client_ip = peer.map(|p| p.ip());
    loop {
        // Read the 2-byte length prefix.
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(_) => return Ok(()),
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return Ok(());
        }
        let mut query = vec![0u8; len];
        stream.read_exact(&mut query)?;
        let response = answer(&resolver, &query, client_ip);
        let mut framed = Vec::with_capacity(response.len() + 2);
        framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
        framed.extend_from_slice(&response);
        stream.write_all(&framed)?;
    }
}

/// Answer one query, returning the wire response.
fn answer(resolver: &Resolver, query_bytes: &[u8], client_ip: Option<IpAddr>) -> Vec<u8> {
    match Message::parse(query_bytes) {
        Ok(query) => {
            let resp = resolver.handle_query(&query, client_ip);
            match resp.to_bytes() {
                Ok(bytes) => bytes,
                Err(_) => query
                    .error_response(crate::qtype::Rcode::SERVFAIL)
                    .to_bytes()
                    .unwrap_or_default(),
            }
        }
        Err(_) => {
            // Formerr for unparseable queries.
            let mut m = Message::new(0);
            m.flags.qr = true;
            m.flags.rcode = crate::qtype::Rcode::FORMERR;
            m.to_bytes().unwrap_or_default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::Name;
    use crate::qtype::RrType;
    use crate::resolver::ResolverConfig;

    #[test]
    fn server_binds_and_answers_udp() {
        let resolver = Resolver::new(ResolverConfig::default());
        let server = Server::new(resolver);
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
        sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let (n, _) = sock.recv_from(&mut buf).unwrap();
        let resp = Message::parse(&buf[..n]).unwrap();
        assert!(resp.flags.qr);
        assert_eq!(resp.id, 0x1234);
    }

    #[test]
    fn server_answers_tcp() {
        let resolver = Resolver::new(ResolverConfig::default());
        let server = Server::new(resolver);
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
        stream.write_all(&framed).unwrap();
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).unwrap();
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).unwrap();
        let resp = Message::parse(&body).unwrap();
        assert!(resp.flags.qr);
        assert_eq!(resp.id, 0x4321);
    }
}
