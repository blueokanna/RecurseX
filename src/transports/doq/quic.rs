//! A QUIC v1 (RFC 9000 / 9001 / 9002) client connection tailored for
//! DNS over QUIC (RFC 9250).
//!
//! courierust exposes the full QUIC wire codecs publicly
//! ([`courierust::courierust_quic`]) but keeps its QUIC *transport* behind
//! the HTTP/3 runtime (hard-wired to the `h3` ALPN), so a real `doq`
//! client has to run the transport itself. This module is that client: a
//! focused, client-only QUIC stack that interoperates with RFC 9250
//! servers (Cloudflare, AdGuard, ...).
//!
//! Scope — deliberately bounded to what a DoQ *client* needs, so the
//! surface area is small enough to audit end to end:
//!
//! * QUIC version 1 only; version negotiation is rejected and a Retry is
//!   honoured with a fresh ClientHello and token;
//! * one client-initiated bidirectional stream per query (RFC 9250 §4.2);
//! * server-initiated unidirectional streams are accepted and drained so
//!   the mandatory DoQ session stream (RFC 9250 §4.3) never stalls flow
//!   control;
//! * PTO-based retransmission with RTT estimation (RFC 9002 §5–6), a
//!   loss-time floor, and a retransmit cap;
//! * flow control in both directions: the peer's limits are respected
//!   when sending, and our advertised windows are replenished as data is
//!   consumed;
//! * no 0-RTT, no key update, no connection migration, no
//!   NEW_CONNECTION_ID churn (extra server CIDs are retired).
//!
//! The TLS handshake lives in [`super::tls`]; this module feeds it CRYPTO
//! data and derives packet-protection keys from its secrets.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use courierust::courierust_quic::frame::Frame;
use courierust::courierust_quic::packet::{self, LongType};
use courierust::courierust_quic::protection::{self, PacketKey};
use courierust::courierust_quic::stream;
use courierust::courierust_quic::varint;
use courierust::courierust_quic::VERSION_1;
use courierust::courierust_tls::RootStore;

use super::tls::{self, ClientHandshake};
use crate::error::{Error, Result};
use crate::upstream::Endpoint;

/// The minimum size of a UDP datagram carrying an Initial packet
/// (RFC 9000 §14.1).
const MIN_INITIAL_DATAGRAM: usize = 1200;
/// Packet number length used for every packet we send (RFC 9000 §17.1).
const PN_LEN: usize = 4;
/// The AEAD tag size for all our cipher suites.
const TAG_LEN: usize = 16;
/// Upper bound on a single STREAM/CRYPTO chunk inside a packet; keeps a
/// datagram well under the 1280-byte path MTU for IPv6.
const MAX_CHUNK: usize = 1100;
/// Cap on total buffered CRYPTO data (memory DoS guard).
const MAX_CRYPTO_BUFFER: usize = 64 * 1024;
/// Cap on total buffered stream response data.
const MAX_RESPONSE_BUFFER: usize = 1 << 20;
/// PTO floor: sub-millisecond RTT estimates on loaded machines make a
/// naive PTO fire spuriously; the floor absorbs scheduling jitter.
const PTO_FLOOR_MS: u64 = 50;
/// Maximum consecutive PTOs before giving up.
const MAX_PTO_COUNT: u32 = 10;
/// Handshake PTO before any RTT sample (RFC 9002 §6.2.1).
const INITIAL_PTO: Duration = Duration::from_millis(500);
/// The ACK delay we advertise in transport parameters (ms).
const MAX_ACK_DELAY: Duration = Duration::from_millis(25);

/// Whether to trace DoQ protocol events (`RECURSEX_DOQ_TRACE=1`).
fn trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("RECURSEX_DOQ_TRACE").is_some())
}

/// Emit a trace line when `RECURSEX_DOQ_TRACE` is set.
fn trace(args: std::fmt::Arguments<'_>) {
    if trace_enabled() {
        eprintln!("[doq] {}", args);
    }
}

/// Hex dump helper for traces.
fn hex_dump(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A QUIC packet-number space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Space {
    Initial = 0,
    Handshake = 1,
    Application = 2,
}

impl Space {
    fn idx(self) -> usize {
        self as usize
    }
}

/// A sent, not-yet-acknowledged packet (only ack-eliciting ones are
/// tracked; they are what a PTO retransmits).
#[derive(Debug)]
struct SentPacket {
    space: Space,
    pn: u64,
    sent: Instant,
    /// The ack-eliciting frames to retransmit (CRYPTO / STREAM / PING).
    frames: Vec<Frame>,
}

/// One in-flight query's send state (flow-control limited).
#[derive(Debug)]
struct QuerySend {
    data: Vec<u8>,
    offset: u64,
    conn_used: u64,
    fin_sent: bool,
}

/// The response reassembly for the current query stream.
#[derive(Debug, Default)]
struct QueryRecv {
    buf: Vec<u8>,
    fin: bool,
}

impl QueryRecv {
    fn complete(&self) -> bool {
        self.fin
    }
}

/// CRYPTO-stream reassembly for one packet-number space.
///
/// The stream is consumed strictly in order (only complete leading
/// handshake messages are popped), so the buffered region is tracked by
/// its *absolute* stream offset: `buf` holds contiguous unread bytes
/// starting at `start`. Tracking absolute offsets — and never
/// reinterpreting the buffer as starting at zero after a pop — is what
/// keeps retransmitted / out-of-order CRYPTO frames from being spliced
/// into the wrong place (a frame retransmitted from offset 0 must not be
/// appended after the leftover tail of an already-popped flight).
#[derive(Debug, Default)]
struct CryptoRx {
    /// Contiguous unread bytes starting at absolute stream offset `start`.
    buf: Vec<u8>,
    /// Absolute stream offset of `buf[0]`.
    start: u64,
    /// Out-of-order data keyed by offset.
    pending: BTreeMap<u64, Vec<u8>>,
}

impl CryptoRx {
    fn buffered(&self) -> usize {
        self.buf.len() + self.pending.values().map(Vec::len).sum::<usize>()
    }

    fn insert(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        if self.buffered() + data.len() > MAX_CRYPTO_BUFFER {
            return Err(Error::transport("doq CRYPTO buffer overflow"));
        }
        let end = offset + data.len() as u64;
        let contiguous_end = self.start + self.buf.len() as u64;
        // Fully before the unread region: already consumed or a stale
        // duplicate — drop it.
        if end <= self.start {
            return Ok(());
        }
        // A gap after the contiguous region: park it until the hole is
        // filled.
        if offset > contiguous_end {
            self.pending.entry(offset).or_insert_with(|| data.to_vec());
            return Ok(());
        }
        // Overlaps or is contiguous with the buffered region. Slice off
        // any portion that lies before `start` (already consumed).
        let data = if offset < self.start {
            &data[(self.start - offset) as usize..]
        } else {
            data
        };
        let present = (contiguous_end.saturating_sub(offset.max(self.start))) as usize;
        if data.len() > present {
            self.buf.extend_from_slice(&data[present..]);
        }
        self.drain_pending();
        Ok(())
    }

    fn drain_pending(&mut self) {
        loop {
            let contiguous_end = self.start + self.buf.len() as u64;
            let mut advance = None;
            for (&off, chunk) in self.pending.iter() {
                if off <= contiguous_end {
                    let end = off + chunk.len() as u64;
                    if end > contiguous_end {
                        let skip = (contiguous_end.saturating_sub(off)) as usize;
                        self.buf.extend_from_slice(&chunk[skip..]);
                    }
                    advance = Some(off);
                    break;
                }
            }
            match advance {
                Some(off) => {
                    self.pending.remove(&off);
                }
                None => break,
            }
        }
    }

    /// Pop one complete TLS handshake message (header + body) if one is
    /// buffered, else `None`.
    fn pop_message(&mut self) -> Option<Vec<u8>> {
        if self.buf.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes([0, self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if self.buf.len() < 4 + len {
            return None;
        }
        let msg = self.buf[..4 + len].to_vec();
        self.buf.drain(..4 + len);
        self.start += (4 + len) as u64;
        self.drain_pending();
        Some(msg)
    }
}

/// The QUIC client connection.
pub struct QuicConnection {
    socket: UdpSocket,
    remote: SocketAddr,
    // Connection IDs.
    local_cid: Vec<u8>,
    server_cid: Vec<u8>,
    original_dcid: Vec<u8>,
    retry_token: Vec<u8>,
    retry_scid: Option<Vec<u8>>,
    saw_server_scid: bool,
    // TLS configuration and handshake.
    tls_cfg: tls::ClientConfig,
    tls: ClientHandshake,
    // Packet-protection keys per space.
    initial_write: PacketKey,
    initial_read: PacketKey,
    hs_write: Option<PacketKey>,
    hs_read: Option<PacketKey>,
    app_write: Option<PacketKey>,
    app_read: Option<PacketKey>,
    // Packet-number spaces.
    next_pn: [u64; 3],
    largest_rx: [u64; 3],
    /// Received ack-eliciting packet numbers not yet acknowledged.
    pending_acks: [BTreeSet<u64>; 3],
    handshake_confirmed: bool,
    // CRYPTO streams (Initial, Handshake).
    crypto_rx: [CryptoRx; 2],
    crypto_tx: [u64; 2],
    // Query stream state.
    stream_id: u64,
    query_tx: Option<QuerySend>,
    query_rx: QueryRecv,
    opened_bidi: u64,
    // Peer (server) flow-control limits.
    peer_max_data: u64,
    peer_max_stream_data: u64,
    peer_max_streams_bidi: u64,
    peer_max_streams_uni: u64,
    // Our advertised receive windows (drives MAX_* updates).
    our_max_data: u64,
    our_max_stream_data_bidi_local: u64,
    our_max_stream_data_uni: u64,
    our_max_streams_uni: u64,
    conn_rx_consumed: u64,
    server_uni_opened: u64,
    uni_consumed: BTreeMap<u64, u64>,
    // Loss recovery.
    sent: Vec<SentPacket>,
    srtt: Option<Duration>,
    rttvar: Duration,
    pto_count: u32,
    // State.
    close_sent: bool,
    closed: Option<Error>,
}

/// Connection identity and live state, at a level of detail that is useful
/// in a log line: a full dump would be hundreds of packet numbers and keys.
impl core::fmt::Debug for QuicConnection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "QuicConnection(remote={}, local_cid={}B, server_cid={}B, confirmed={}, srtt={:?}, closed={})",
            self.remote,
            self.local_cid.len(),
            self.server_cid.len(),
            self.handshake_confirmed,
            self.srtt,
            self.closed.is_some()
        )
    }
}

impl QuicConnection {
    /// Establish a QUIC connection to `endpoint`, performing the full
    /// TLS 1.3 handshake with ALPN `doq`. `host` is the certificate
    /// verification name (and SNI) when known.
    pub fn connect(
        endpoint: &Endpoint,
        host: Option<&str>,
        roots: RootStore,
        verify: bool,
        now: i64,
        timeout_ms: u64,
    ) -> Result<Self> {
        let bind_addr: SocketAddr = match endpoint.ip {
            IpAddr::V4(_) => "0.0.0.0:0".parse().expect("static IPv4 bind address"),
            IpAddr::V6(_) => "[::]:0".parse().expect("static IPv6 bind address"),
        };
        let socket =
            UdpSocket::bind(bind_addr).map_err(|e| Error::io(format!("doq udp bind: {e}")))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(10)))
            .map_err(|e| Error::io(format!("doq udp timeout setup: {e}")))?;
        let remote = SocketAddr::new(endpoint.ip, endpoint.port);

        let local_cid = random_cid();
        let server_cid = random_cid();
        // The ALPN is normally `doq`; `RECURSEX_DOQ_ALPN` overrides it
        // (used to validate the transport against a local HTTP/3 peer).
        let alpn: Vec<u8> = std::env::var_os("RECURSEX_DOQ_ALPN")
            .map(|v| v.to_string_lossy().into_owned().into_bytes())
            .unwrap_or_else(|| b"doq".to_vec());
        let tls_cfg = tls::ClientConfig {
            alpn,
            server_name: host.map(|h| h.to_string()),
            hostname: host.map(|h| h.to_string()),
            roots,
            verify,
            now,
            transport_params: tls::TransportParams::client_defaults(local_cid.clone()),
        };
        let mut tls = ClientHandshake::new(tls_cfg.clone());
        let ch = tls.client_hello();

        let mut c = Self {
            socket,
            remote,
            local_cid,
            server_cid: server_cid.clone(),
            original_dcid: server_cid.clone(),
            retry_token: Vec::new(),
            retry_scid: None,
            saw_server_scid: false,
            tls_cfg,
            tls,
            initial_write: PacketKey::initial(&server_cid, false)
                .map_err(|e| Error::transport(format!("doq initial keys: {e}")))?,
            initial_read: PacketKey::initial(&server_cid, true)
                .map_err(|e| Error::transport(format!("doq initial keys: {e}")))?,
            hs_write: None,
            hs_read: None,
            app_write: None,
            app_read: None,
            next_pn: [0; 3],
            largest_rx: [0; 3],
            pending_acks: Default::default(),
            handshake_confirmed: false,
            crypto_rx: Default::default(),
            crypto_tx: [0; 2],
            stream_id: 0,
            query_tx: None,
            query_rx: QueryRecv::default(),
            opened_bidi: 0,
            peer_max_data: u64::MAX,
            peer_max_stream_data: u64::MAX,
            peer_max_streams_bidi: 1,
            peer_max_streams_uni: 1,
            our_max_data: 1 << 20,
            our_max_stream_data_bidi_local: 1 << 20,
            our_max_stream_data_uni: 1 << 20,
            our_max_streams_uni: 8,
            conn_rx_consumed: 0,
            server_uni_opened: 0,
            uni_consumed: BTreeMap::new(),
            sent: Vec::new(),
            srtt: None,
            rttvar: Duration::ZERO,
            pto_count: 0,
            close_sent: false,
            closed: None,
        };
        // Send the first Initial (padded to 1200) with the ClientHello.
        trace(format_args!(
            "connect {} ch={}B dcid={:02x?} scid={:02x?}\nch_hex={}",
            remote,
            ch.len(),
            c.server_cid,
            c.local_cid,
            hex_dump(&ch)
        ));
        c.send_crypto(Space::Initial, &ch, 0, true)?;
        c.crypto_tx[0] = ch.len() as u64;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(1000));
        c.drive_until(|c| c.tls.is_done(), deadline)?;
        Ok(c)
    }

    /// Whether the connection is still usable.
    pub fn is_open(&self) -> bool {
        self.closed.is_none() && !self.close_sent
    }

    /// The peer's close error, if the connection was closed remotely.
    pub fn close_error(&self) -> Option<&Error> {
        self.closed.as_ref()
    }

    /// Send a DoQ query (the raw DNS message) on a fresh client-initiated
    /// bidirectional stream and return the raw response. The caller
    /// frames the message (2-byte length prefix, RFC 9250 §4.2).
    pub fn exchange_query(&mut self, query: &[u8], timeout_ms: u64) -> Result<Vec<u8>> {
        if !self.handshake_confirmed {
            return Err(Error::transport("doq query before handshake confirmed"));
        }
        if let Some(err) = self.closed.clone() {
            return Err(err);
        }
        if self.opened_bidi >= self.peer_max_streams_bidi {
            return Err(Error::transport(
                "server's bidirectional stream limit reached (MAX_STREAMS)",
            ));
        }
        self.stream_id = stream::stream_id(stream::CLIENT_BIDI, self.opened_bidi);
        self.opened_bidi += 1;
        self.query_tx = Some(QuerySend {
            data: query.to_vec(),
            offset: 0,
            conn_used: 0,
            fin_sent: false,
        });
        self.query_rx = QueryRecv::default();
        let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(1000));
        self.flush_query_send()?;
        self.drive_until(|c| c.query_rx.complete(), deadline)?;
        if self.query_rx.buf.len() > MAX_RESPONSE_BUFFER {
            return Err(Error::transport("doq response exceeds buffer limit"));
        }
        Ok(self.query_rx.buf.clone())
    }

    /// Gracefully close the connection (RFC 9250 §4.2: DOQ_NO_ERROR).
    pub fn close(&mut self) {
        if self.close_sent || self.closed.is_some() {
            return;
        }
        let _ = self.send_packet(
            Space::Application,
            vec![Frame::ConnectionClose {
                error_code: 0x0, // DOQ_NO_ERROR
                frame_type: None,
                reason: Vec::new(),
            }],
            false,
        );
        self.close_sent = true;
    }

    // -- event loop -------------------------------------------------------

    /// Run the socket event loop until `done()` is true, the deadline
    /// passes, or the peer closes the connection.
    fn drive_until(&mut self, done: impl Fn(&Self) -> bool, deadline: Instant) -> Result<()> {
        let mut buf = [0u8; 65536];
        let start = Instant::now();
        while !done(self) {
            if let Some(err) = self.closed.clone() {
                return Err(err);
            }
            if Instant::now() >= deadline {
                return Err(Error::new(
                    crate::error::ErrorKind::Timeout,
                    format!(
                        "doq timed out after {} ms",
                        deadline.saturating_duration_since(start).as_millis()
                    ),
                ));
            }
            let mut received_any = false;
            loop {
                match self.socket.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        if src == self.remote {
                            received_any = true;
                            self.process_datagram(&buf[..n])?;
                        }
                        // Datagrams from other sources are ignored
                        // (source validation).
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(e) => {
                        return Err(Error::io(format!("doq recv: {e}")));
                    }
                }
            }
            if received_any {
                self.pto_count = 0;
            }
            self.flush_acks();
            self.run_pto()?;
            if self.handshake_confirmed {
                self.flush_query_send()?;
            }
        }
        Ok(())
    }

    // -- sending ----------------------------------------------------------

    /// Send a CRYPTO frame in `space`.
    fn send_crypto(&mut self, space: Space, data: &[u8], offset: u64, pad: bool) -> Result<()> {
        self.send_packet(
            space,
            vec![Frame::Crypto {
                offset,
                data: data.to_vec(),
            }],
            pad,
        )
    }

    /// Send (and account) a packet with the given ack-eliciting frames.
    /// `pad_initial` pads the datagram to at least 1200 bytes (required
    /// for the first Initial and for Initial ACKs until the handshake is
    /// confirmed, RFC 9000 §14.1).
    fn send_packet(&mut self, space: Space, frames: Vec<Frame>, pad_initial: bool) -> Result<()> {
        let pn = self.next_pn[space.idx()];
        let (key, is_long, token) = match space {
            Space::Initial => (self.initial_write.clone(), true, self.retry_token.clone()),
            Space::Handshake => {
                let k = self
                    .hs_write
                    .clone()
                    .ok_or_else(|| Error::transport("doq handshake write key missing"))?;
                (k, true, Vec::new())
            }
            Space::Application => {
                let k = self
                    .app_write
                    .clone()
                    .ok_or_else(|| Error::transport("doq application write key missing"))?;
                (k, false, Vec::new())
            }
        };
        let ack_eliciting = !frames.is_empty();

        let mut plaintext = Vec::new();
        for f in &frames {
            f.encode(&mut plaintext);
        }

        // Assemble header + payload, padding the first Initial datagram.
        // Note: `payload_len` counts the packet-number bytes, which live
        // in the header, so the UDP datagram is `header + payload_len -
        // PN_LEN` bytes. Pad so that *datagram* reaches 1200 bytes
        // (RFC 9000 §14.1) — a datagram 4 bytes short is silently
        // dropped by strict servers.
        let (header, sealed) = loop {
            let payload_len = PN_LEN + plaintext.len() + TAG_LEN;
            let header = match space {
                Space::Initial => packet::encode_long(
                    LongType::Initial,
                    &self.server_cid,
                    &self.local_cid,
                    pn,
                    PN_LEN,
                    &token,
                    payload_len as u64,
                )
                .map_err(|e| Error::transport(format!("doq header: {e}")))?,
                Space::Handshake => packet::encode_long(
                    LongType::Handshake,
                    &self.server_cid,
                    &self.local_cid,
                    pn,
                    PN_LEN,
                    &[],
                    payload_len as u64,
                )
                .map_err(|e| Error::transport(format!("doq header: {e}")))?,
                Space::Application => packet::encode_short(&self.server_cid, pn, PN_LEN, false)
                    .map_err(|e| Error::transport(format!("doq header: {e}")))?,
            };
            let datagram_len = header.len() + payload_len - PN_LEN;
            if pad_initial && datagram_len < MIN_INITIAL_DATAGRAM {
                // PADDING frames to bring the *datagram* up to 1200.
                plaintext.extend(std::iter::repeat(0u8).take(MIN_INITIAL_DATAGRAM - datagram_len));
                continue;
            }
            let sealed = key
                .seal(pn, &header, &plaintext)
                .map_err(|e| Error::transport(format!("doq seal: {e}")))?;
            break (header, sealed);
        };

        let mut wire = header.clone();
        wire.extend_from_slice(&sealed);
        let pn_offset = header.len() - PN_LEN;
        key.protect_header(&mut wire, pn_offset, is_long)
            .map_err(|e| Error::transport(format!("doq header protection: {e}")))?;

        self.socket
            .send_to(&wire, self.remote)
            .map_err(|e| Error::io(format!("doq send: {e}")))?;
        trace(format_args!(
            "send space={space:?} pn={pn} frames={} wire={}B",
            ack_eliciting,
            wire.len()
        ));
        self.next_pn[space.idx()] = pn.wrapping_add(1);
        if ack_eliciting {
            self.sent.push(SentPacket {
                space,
                pn,
                sent: Instant::now(),
                frames,
            });
        }
        Ok(())
    }

    /// Send ACK-only packets for any pending acknowledgements. ACKs are
    /// not ack-eliciting. Once the handshake is confirmed the Initial
    /// space is closed (keys discarded, RFC 9001 §4.9.2) and its
    /// pending ACKs are dropped.
    fn flush_acks(&mut self) {
        for space in [Space::Initial, Space::Handshake, Space::Application] {
            if self.pending_acks[space.idx()].is_empty() {
                continue;
            }
            if space == Space::Initial && self.handshake_confirmed {
                self.pending_acks[space.idx()].clear();
                continue;
            }
            let pns: Vec<u64> = self.pending_acks[space.idx()].iter().copied().collect();
            self.pending_acks[space.idx()].clear();
            let frames = vec![build_ack_frame(&pns)];
            let pad = space == Space::Initial && !self.handshake_confirmed;
            if let Err(e) = self.send_packet(space, frames, pad) {
                // ACK send failures are non-fatal: the peer will
                // retransmit.
                let _ = e;
            }
        }
    }

    // -- receiving --------------------------------------------------------

    /// Parse the (protected) packet header.
    ///
    /// Returns `(is_long, packet_type, dcid, scid, token, pn_offset,
    /// payload_end)`. The packet number and its length are only known
    /// after header unprotection, so they are read by the caller.
    #[allow(clippy::type_complexity)]
    fn parse_header(
        &self,
        dg: &[u8],
    ) -> Result<
        Option<(
            bool,
            Option<LongType>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            usize,
            usize,
        )>,
    > {
        let first = dg[0];
        if first & 0x80 != 0 {
            // Long header.
            if dg.len() < 7 {
                return Err(Error::wire("doq long header truncated"));
            }
            let version = u32::from_be_bytes([dg[1], dg[2], dg[3], dg[4]]);
            if version != VERSION_1 {
                return Err(Error::wire("doq unsupported QUIC version"));
            }
            let ptype = match (first >> 4) & 0x03 {
                0 => LongType::Initial,
                1 => LongType::ZeroRtt,
                2 => LongType::Handshake,
                _ => LongType::Retry,
            };
            let dcid_len = dg[5] as usize;
            let mut pos = 6usize;
            if dcid_len > 20 || pos + dcid_len > dg.len() {
                return Err(Error::wire("doq DCID malformed"));
            }
            let dcid = dg[pos..pos + dcid_len].to_vec();
            pos += dcid_len;
            if pos >= dg.len() {
                return Err(Error::wire("doq long header truncated"));
            }
            let scid_len = dg[pos] as usize;
            pos += 1;
            if scid_len > 20 || pos + scid_len > dg.len() {
                return Err(Error::wire("doq SCID malformed"));
            }
            let scid = dg[pos..pos + scid_len].to_vec();
            pos += scid_len;
            let mut token = Vec::new();
            if ptype == LongType::Initial {
                let (tlen, used) = varint::decode(&dg[pos..])
                    .map_err(|_| Error::wire("doq token length malformed"))?;
                pos += used;
                let tlen = usize::try_from(tlen).map_err(|_| Error::wire("doq token too long"))?;
                if pos + tlen > dg.len() {
                    return Err(Error::wire("doq token truncated"));
                }
                token = dg[pos..pos + tlen].to_vec();
                pos += tlen;
            }
            let (plen, used) = varint::decode(&dg[pos..])
                .map_err(|_| Error::wire("doq payload length malformed"))?;
            pos += used;
            let pn_offset = pos;
            if plen < PN_LEN as u64 {
                return Err(Error::wire("doq payload shorter than packet number"));
            }
            let payload_end = pn_offset + plen as usize;
            if payload_end > dg.len() {
                return Err(Error::wire("doq packet payload truncated"));
            }
            Ok(Some((
                true,
                Some(ptype),
                dcid,
                scid,
                token,
                pn_offset,
                payload_end,
            )))
        } else {
            // Short header.
            let start = 1 + self.local_cid.len();
            if dg.len() < start + 1 {
                return Err(Error::wire("doq short header truncated"));
            }
            let dcid = dg[1..start].to_vec();
            Ok(Some((
                false,
                None,
                dcid,
                Vec::new(),
                Vec::new(),
                start,
                dg.len(),
            )))
        }
    }

    fn process_datagram(&mut self, mut dg: &[u8]) -> Result<()> {
        // A UDP datagram can carry several QUIC packets back to back
        // (coalescing, RFC 9000 §12.2); servers commonly coalesce the
        // ServerHello Initial with the Handshake flight, so each packet
        // in the datagram is processed in turn.
        while !dg.is_empty() {
            trace(format_args!(
                "recv {}B {:02x?}",
                dg.len(),
                &dg[..dg.len().min(24)]
            ));
            let first = dg[0];
            // Version negotiation packet (version 0 in a long header).
            if first & 0x80 != 0
                && dg.len() >= 5
                && u32::from_be_bytes([dg[1], dg[2], dg[3], dg[4]]) == 0
            {
                self.closed = Some(Error::transport(
                    "doq server does not support QUIC version 1 (version negotiation)",
                ));
                return Err(self.closed.clone().unwrap());
            }
            // Retry packet (always alone in a datagram, RFC 9000 §17.2.5).
            if first & 0x80 != 0
                && (first >> 4) & 0x03 == 3
                && dg.len() >= 5
                && u32::from_be_bytes([dg[1], dg[2], dg[3], dg[4]]) == VERSION_1
            {
                return self.process_retry(dg);
            }
            let Some((is_long, ptype, dcid, scid, _token, pn_offset, payload_end)) =
                self.parse_header(dg)?
            else {
                return Ok(());
            };
            trace(format_args!(
                "recv header long={is_long} type={ptype:?} dcid={:02x?} scid={:02x?} pn_off={pn_offset} end={payload_end}",
                dcid, scid
            ));
            // The datagram must be addressed to us.
            if !dcid.is_empty() && dcid != self.local_cid {
                return Ok(()); // not for this connection
            }
            let (space, key) = match (is_long, ptype) {
                (true, Some(LongType::Initial)) => (Space::Initial, self.initial_read.clone()),
                (true, Some(LongType::Handshake)) => match &self.hs_read {
                    Some(k) => (Space::Handshake, k.clone()),
                    None => {
                        // Handshake keys are derived right after the
                        // ServerHello; a Handshake packet that arrives
                        // before that (or after a lost ServerHello) is
                        // simply undecryptable — drop it and let the
                        // peer retransmit (RFC 9001 §5.2).
                        trace(format_args!("recv handshake packet before keys (dropped)"));
                        return Ok(());
                    }
                },
                (true, Some(LongType::ZeroRtt)) => return Ok(()), // we never send 0-RTT
                (true, Some(LongType::Retry)) => return Ok(()),   // handled above
                (false, None) => match &self.app_read {
                    Some(k) => (Space::Application, k.clone()),
                    None => {
                        trace(format_args!("recv 1-RTT packet before keys (dropped)"));
                        return Ok(());
                    }
                },
                _ => return Ok(()),
            };
            // Once the client sends its Finished, Initial keys are
            // discarded and no more Initial packets are expected
            // (RFC 9001 §4.9.2).
            if space == Space::Initial && self.handshake_confirmed {
                return Ok(());
            }
            // Remember the server's SCID so future packets use it as DCID.
            if is_long && !scid.is_empty() && !self.saw_server_scid {
                self.server_cid.clone_from(&scid);
                self.saw_server_scid = true;
            }
            // Remove header protection, then recover the packet number.
            let mut packet = dg.to_vec();
            let pn_len = match key.unprotect_header(&mut packet, pn_offset, is_long) {
                Ok(l) => l,
                Err(_) => return Ok(()), // not a valid packet for us
            };
            if !(1..=4).contains(&pn_len) {
                return Ok(());
            }
            let expected = self.largest_rx[space.idx()].wrapping_add(1);
            let pn = packet::decode_pn(&packet[pn_offset..pn_offset + pn_len], expected, pn_len);
            let payload_start = pn_offset + pn_len;
            if payload_start > payload_end {
                return Ok(());
            }
            let plaintext = match key.open(
                pn,
                &packet[..payload_start],
                &packet[payload_start..payload_end],
            ) {
                Ok(p) => p,
                Err(_) => {
                    trace(format_args!("recv open failed pn={pn} space={space:?}"));
                    return Ok(()); // authentication failure: drop
                }
            };
            trace(format_args!(
                "recv ok space={space:?} pn={pn} plaintext={}B",
                plaintext.len()
            ));
            if pn > self.largest_rx[space.idx()] {
                self.largest_rx[space.idx()] = pn;
            }
            self.process_plaintext(space, pn, &plaintext)?;
            // Advance to the next coalesced packet, if any.
            dg = &dg[payload_end..];
        }
        Ok(())
    }

    fn process_retry(&mut self, dg: &[u8]) -> Result<()> {
        if dg.len() < 7 + 20 {
            return Err(Error::wire("doq Retry packet truncated"));
        }
        let dcid_len = dg[5] as usize;
        let mut pos = 6usize;
        if dcid_len > 20 || pos + dcid_len + 1 > dg.len() {
            return Err(Error::wire("doq Retry malformed"));
        }
        let dcid = dg[pos..pos + dcid_len].to_vec();
        pos += dcid_len;
        let scid_len = dg[pos] as usize;
        pos += 1;
        if scid_len > 20 || pos + scid_len + 16 > dg.len() {
            return Err(Error::wire("doq Retry malformed"));
        }
        let scid = dg[pos..pos + scid_len].to_vec();
        pos += scid_len;
        let tag = dg[dg.len() - 16..].to_vec();
        let token = dg[pos..dg.len() - 16].to_vec();
        if dcid != self.local_cid {
            return Ok(()); // Retry for another connection
        }
        if self.retry_scid.is_some() || self.handshake_confirmed || self.saw_server_scid {
            self.closed = Some(Error::wire("doq unexpected Retry"));
            return Err(self.closed.clone().unwrap());
        }
        // Verify the integrity tag (RFC 9001 §5.8).
        let retry_wire = &dg[..dg.len() - 16];
        let ok = protection::verify_retry_integrity(&self.original_dcid, retry_wire, &tag)
            .map_err(|e| Error::wire(format!("doq Retry integrity check failed: {e}")))?;
        if !ok {
            return Ok(()); // drop a forged Retry
        }
        // Apply the Retry: new server CID + token, re-derive Initial
        // keys, regenerate the ClientHello (with the retry SCID in the
        // transport parameters), reset the Initial space, and resend the
        // first Initial.
        trace(format_args!(
            "retry received scid={:02x?} token={}B",
            scid,
            token.len()
        ));
        self.server_cid.clone_from(&scid);
        self.retry_scid = Some(scid);
        self.retry_token = token;
        self.initial_write = PacketKey::initial(&self.server_cid, false)
            .map_err(|e| Error::transport(format!("doq initial keys: {e}")))?;
        self.initial_read = PacketKey::initial(&self.server_cid, true)
            .map_err(|e| Error::transport(format!("doq initial keys: {e}")))?;
        self.next_pn[Space::Initial.idx()] = 0;
        self.largest_rx[Space::Initial.idx()] = 0;
        self.pending_acks[Space::Initial.idx()].clear();
        self.crypto_rx[0] = CryptoRx::default();
        self.crypto_tx[0] = 0;
        self.sent.retain(|p| p.space != Space::Initial);
        // Regenerate the ClientHello: a fresh ClientHandshake keeps the
        // transcript clean and lets the transport parameters carry the
        // retry SCID (RFC 9001 §8.2, RFC 9000 §17.2.5.2).
        let mut tp = self.tls_cfg.transport_params.clone();
        tp.retry_source_connection_id.clone_from(&self.retry_scid);
        let mut tls_cfg = self.tls_cfg.clone();
        tls_cfg.transport_params = tp;
        let mut tls = ClientHandshake::new(tls_cfg.clone());
        let ch = tls.client_hello();
        trace(format_args!(
            "post-retry ch={}B retry_scid={:02x?}\nch2_hex={}",
            ch.len(),
            self.retry_scid,
            hex_dump(&ch)
        ));
        self.tls_cfg = tls_cfg;
        self.tls = tls;
        self.send_crypto(Space::Initial, &ch, 0, true)?;
        self.crypto_tx[0] = ch.len() as u64;
        Ok(())
    }

    fn process_plaintext(&mut self, space: Space, pn: u64, plaintext: &[u8]) -> Result<()> {
        let mut pos = 0usize;
        let mut ack_eliciting = false;
        while pos < plaintext.len() {
            let (frame, used) = match Frame::decode(&plaintext[pos..]) {
                Ok(v) => v,
                Err(_) => break, // malformed frame: ignore the rest
            };
            pos += used;
            match frame {
                Frame::Padding(_) | Frame::Datagram { .. } => {}
                Frame::Ping => ack_eliciting = true,
                Frame::Ack {
                    largest_acked,
                    ack_delay,
                    ranges,
                    ..
                } => {
                    self.on_ack(space, largest_acked, ack_delay, &ranges);
                }
                Frame::Crypto { offset, data } => {
                    ack_eliciting = true;
                    self.on_crypto(space, offset, &data)?;
                }
                Frame::Stream {
                    stream_id,
                    offset,
                    data,
                    fin,
                    ..
                } => {
                    ack_eliciting = true;
                    self.on_stream(stream_id, offset.unwrap_or(0), &data, fin)?;
                }
                Frame::MaxData(max) => {
                    self.peer_max_data = self.peer_max_data.max(max);
                }
                Frame::MaxStreamData { stream_id, max } => {
                    if stream_id == self.stream_id {
                        self.peer_max_stream_data = self.peer_max_stream_data.max(max);
                    }
                }
                Frame::MaxStreams {
                    unidirectional,
                    max,
                } => {
                    if unidirectional {
                        self.peer_max_streams_uni = self.peer_max_streams_uni.max(max);
                    } else {
                        self.peer_max_streams_bidi = self.peer_max_streams_bidi.max(max);
                    }
                }
                Frame::ConnectionClose {
                    error_code,
                    frame_type,
                    reason,
                    ..
                } => {
                    let reason_str = String::from_utf8_lossy(&reason).into_owned();
                    trace(format_args!(
                        "recv CONNECTION_CLOSE error={error_code} frame_type={frame_type:?} reason={reason_str:?}"
                    ));
                    self.closed = Some(Error::transport(format!(
                        "doq server closed connection (error {}): {reason_str}",
                        error_code
                    )));
                    return Err(self.closed.clone().unwrap());
                }
                Frame::PathChallenge(tag) => {
                    // Respond to path validation (RFC 9000 §8.2.2).
                    self.send_packet(Space::Application, vec![Frame::PathResponse(tag)], false)?;
                }
                Frame::NewConnectionId { sequence, .. } => {
                    // We keep a single connection ID; retire extras.
                    if sequence > 0 {
                        self.send_packet(
                            Space::Application,
                            vec![Frame::RetireConnectionId(sequence)],
                            false,
                        )?;
                    }
                }
                Frame::ResetStream { stream_id, .. } | Frame::StopSending { stream_id, .. } => {
                    if stream_id == self.stream_id && !self.query_rx.complete() {
                        self.closed = Some(Error::transport("doq server reset the query stream"));
                        return Err(self.closed.clone().unwrap());
                    }
                }
                Frame::HandshakeDone
                | Frame::PathResponse(_)
                | Frame::NewToken { .. }
                | Frame::DataBlocked(_)
                | Frame::StreamDataBlocked { .. }
                | Frame::StreamsBlocked { .. }
                | Frame::RetireConnectionId(_) => {}
            }
        }
        if ack_eliciting {
            self.pending_acks[space.idx()].insert(pn);
        }
        Ok(())
    }

    fn on_ack(&mut self, space: Space, largest_acked: u64, ack_delay: u64, ranges: &[(u64, u64)]) {
        // Recover the acked packet numbers from (gap, range) pairs.
        let mut acked = BTreeSet::new();
        let mut prev_low = largest_acked.saturating_add(1);
        for (i, (gap, range_len)) in ranges.iter().enumerate() {
            let largest = if i == 0 {
                largest_acked
            } else {
                prev_low.saturating_sub(*gap + 2)
            };
            let low = largest.saturating_sub(*range_len);
            for pn in low..=largest {
                acked.insert(pn);
            }
            prev_low = low;
        }
        // RTT sample from the largest acked packet.
        let now = Instant::now();
        let mut rtt_sample = None;
        self.sent.retain(|p| {
            if p.space != space || !acked.contains(&p.pn) {
                return true;
            }
            if rtt_sample.is_none() {
                rtt_sample = Some(now.saturating_duration_since(p.sent));
            }
            false
        });
        if let Some(sample) = rtt_sample {
            // ack_delay is in units of 2^ack_delay_exponent ms; the
            // server's exponent defaults to 3.
            let ack_delay = Duration::from_millis(ack_delay.saturating_mul(8) / 1000);
            let sample = sample.saturating_sub(ack_delay.min(sample));
            match self.srtt {
                None => {
                    self.srtt = Some(sample);
                    self.rttvar = sample / 2;
                }
                Some(srtt) => {
                    let delta = if srtt > sample {
                        srtt - sample
                    } else {
                        sample - srtt
                    };
                    self.rttvar = self.rttvar * 3 / 4 + delta / 4;
                    self.srtt = Some(srtt * 7 / 8 + sample / 8);
                }
            }
            self.pto_count = 0;
        }
    }

    fn on_crypto(&mut self, space: Space, offset: u64, data: &[u8]) -> Result<()> {
        let idx = match space {
            Space::Initial => 0,
            Space::Handshake => 1,
            _ => return Ok(()),
        };
        self.crypto_rx[idx].insert(offset, data)?;
        while let Some(msg) = self.crypto_rx[idx].pop_message() {
            trace(format_args!(
                "crypto msg type={} len={} space={space:?}",
                msg[0],
                msg.len()
            ));
            if let Some(completed) = self.tls.feed(&msg)? {
                // Handshake complete: derive 1-RTT keys, validate the
                // server's transport parameters, and send the client
                // Finished in the Handshake space.
                let suite = completed.suite;
                let hs_write = PacketKey::from_secret(
                    suite,
                    self.tls
                        .client_handshake_secret()
                        .ok_or_else(|| Error::transport("doq client handshake secret missing"))?,
                )
                .map_err(|e| Error::transport(format!("doq handshake key: {e}")))?;
                let app_write = PacketKey::from_secret(
                    suite,
                    self.tls
                        .client_application_secret()
                        .ok_or_else(|| Error::transport("doq application secret missing"))?,
                )
                .map_err(|e| Error::transport(format!("doq application key: {e}")))?;
                let app_read = PacketKey::from_secret(
                    suite,
                    self.tls
                        .server_application_secret()
                        .ok_or_else(|| Error::transport("doq application secret missing"))?,
                )
                .map_err(|e| Error::transport(format!("doq application key: {e}")))?;
                self.hs_write = Some(hs_write);
                self.app_write = Some(app_write);
                self.app_read = Some(app_read);
                self.validate_server_transport_params()?;
                self.send_crypto(
                    Space::Handshake,
                    &completed.client_finished,
                    self.crypto_tx[1],
                    false,
                )?;
                self.crypto_tx[1] += completed.client_finished.len() as u64;
                self.handshake_confirmed = true;
                self.pto_count = 0;
                trace(format_args!("handshake completed suite=0x{suite:04x}"));
            } else if self.hs_read.is_none() {
                // The ServerHello just arrived. The server's Handshake
                // flight (EncryptedExtensions, Certificate,
                // CertificateVerify, Finished) is protected with the
                // server handshake traffic secret, so derive the
                // Handshake read key before the next datagram is
                // processed (RFC 8446 §7.1, RFC 9001 §4.1.1).
                if let Some(s_hs) = self.tls.server_handshake_secret() {
                    let suite = self.tls.suite().ok_or_else(|| {
                        Error::transport("doq cipher suite missing after ServerHello")
                    })?;
                    let hs_read = PacketKey::from_secret(suite, s_hs)
                        .map_err(|e| Error::transport(format!("doq handshake read key: {e}")))?;
                    self.hs_read = Some(hs_read);
                    trace(format_args!(
                        "handshake read key derived suite=0x{suite:04x}"
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_server_transport_params(&mut self) -> Result<()> {
        let Some(params) = self.tls.server_params() else {
            return Err(Error::wire("server sent no transport parameters"));
        };
        // RFC 9000 §7.3: the server must echo our original DCID and its
        // own initial SCID.
        if let Some(odcid) = &params.original_destination_connection_id {
            if odcid != &self.original_dcid {
                return Err(Error::wire(
                    "server original_destination_connection_id mismatch",
                ));
            }
        }
        if let Some(iscid) = &params.initial_source_connection_id {
            if iscid != &self.server_cid {
                return Err(Error::wire("server initial_source_connection_id mismatch"));
            }
        }
        if let (Some(expected), Some(got)) = (&self.retry_scid, &params.retry_source_connection_id)
        {
            if got != expected {
                return Err(Error::wire("server retry_source_connection_id mismatch"));
            }
        }
        // Apply the server's flow-control limits (RFC 9000 §4).
        if params.initial_max_data > 0 {
            self.peer_max_data = params.initial_max_data;
        }
        if params.initial_max_stream_data_bidi_local > 0 {
            self.peer_max_stream_data = params.initial_max_stream_data_bidi_local;
        }
        if params.initial_max_streams_bidi > 0 {
            self.peer_max_streams_bidi = params.initial_max_streams_bidi;
        }
        if params.initial_max_streams_uni > 0 {
            self.peer_max_streams_uni = params.initial_max_streams_uni;
        }
        if self.peer_max_streams_bidi == 0 {
            return Err(Error::transport(
                "server does not allow client-initiated bidirectional streams",
            ));
        }
        Ok(())
    }

    fn on_stream(&mut self, stream_id: u64, offset: u64, data: &[u8], fin: bool) -> Result<()> {
        let stype = stream::stream_type(stream_id);
        if stype == stream::SERVER_UNI {
            // The DoQ session stream (and any other server uni stream):
            // read and drain so flow control never stalls (RFC 9250 §4.3).
            self.server_uni_opened = self
                .server_uni_opened
                .max(stream::stream_index(stream_id) + 1);
            let consumed = self.uni_consumed.entry(stream_id).or_insert(0);
            *consumed = (*consumed).max(offset + data.len() as u64);
            self.maybe_replenish_uni(stream_id)?;
            return Ok(());
        }
        if stype != stream::CLIENT_BIDI || stream_id != self.stream_id {
            // A server-initiated bidi stream or an unexpected stream:
            // reset it so the server stops sending.
            self.send_packet(
                Space::Application,
                vec![Frame::ResetStream {
                    stream_id,
                    app_error_code: 0x5, // DOQ_UNSPECIFIED_ERROR
                    final_size: 0,
                }],
                false,
            )?;
            return Ok(());
        }
        // The query response stream.
        let expected = self.query_rx.buf.len() as u64;
        if offset > expected {
            // Out-of-order response data: buffer it for reassembly.
            self.query_rx.buf.resize(offset as usize + data.len(), 0);
            self.query_rx.buf[offset as usize..offset as usize + data.len()].copy_from_slice(data);
        } else {
            let skip = (expected - offset) as usize;
            if skip < data.len() {
                self.query_rx.buf.extend_from_slice(&data[skip..]);
            }
        }
        if fin {
            self.query_rx.fin = true;
        }
        if self.query_rx.buf.len() > MAX_RESPONSE_BUFFER {
            self.closed = Some(Error::transport("doq response exceeds buffer limit"));
            return Err(self.closed.clone().unwrap());
        }
        // Replenish the stream + connection windows as we consume.
        self.conn_rx_consumed = self.conn_rx_consumed.max(self.query_rx.buf.len() as u64);
        self.maybe_replenish_windows()?;
        Ok(())
    }

    fn maybe_replenish_windows(&mut self) -> Result<()> {
        // When more than half of our advertised window is consumed,
        // double it (RFC 9000 §4.1).
        if self.query_rx.buf.len() as u64 * 2 > self.our_max_stream_data_bidi_local {
            let new_limit = self.our_max_stream_data_bidi_local.saturating_mul(2);
            self.send_packet(
                Space::Application,
                vec![Frame::MaxStreamData {
                    stream_id: self.stream_id,
                    max: new_limit,
                }],
                false,
            )?;
            self.our_max_stream_data_bidi_local = new_limit;
        }
        if self.conn_rx_consumed * 2 > self.our_max_data {
            let new_limit = self.our_max_data.saturating_mul(2);
            self.send_packet(Space::Application, vec![Frame::MaxData(new_limit)], false)?;
            self.our_max_data = new_limit;
        }
        Ok(())
    }

    fn maybe_replenish_uni(&mut self, stream_id: u64) -> Result<()> {
        let consumed = self.uni_consumed.get(&stream_id).copied().unwrap_or(0);
        if consumed * 2 > self.our_max_stream_data_uni {
            let new_limit = self.our_max_stream_data_uni.saturating_mul(2);
            self.send_packet(
                Space::Application,
                vec![Frame::MaxStreamData {
                    stream_id,
                    max: new_limit,
                }],
                false,
            )?;
            self.our_max_stream_data_uni = new_limit;
        }
        if self.server_uni_opened * 2 > self.our_max_streams_uni {
            let new_limit = self.our_max_streams_uni.saturating_mul(2);
            self.send_packet(
                Space::Application,
                vec![Frame::MaxStreams {
                    unidirectional: true,
                    max: new_limit,
                }],
                false,
            )?;
            self.our_max_streams_uni = new_limit;
        }
        Ok(())
    }

    // -- flow-control-limited query sending -------------------------------

    fn flush_query_send(&mut self) -> Result<()> {
        // Compute the chunks to send under the borrow, release it, then
        // transmit (so `send_packet` can borrow `self` mutably).
        let stream_id = self.stream_id;
        let chunks: Vec<(u64, Vec<u8>, bool)> = {
            let q = match self.query_tx.as_mut() {
                Some(q) => q,
                None => return Ok(()),
            };
            if q.fin_sent {
                return Ok(());
            }
            // How much the peer allows us to send on this stream.
            let conn_allow = self.peer_max_data.saturating_sub(q.conn_used);
            let stream_allow = self.peer_max_stream_data.saturating_sub(q.offset);
            let remaining = (q.data.len() as u64).saturating_sub(q.offset);
            let allow = conn_allow.min(stream_allow).min(remaining);
            if allow == 0 {
                return Ok(());
            }
            let mut chunks = Vec::new();
            let mut sent = 0u64;
            while sent < allow {
                let chunk_start = (q.offset + sent) as usize;
                let chunk_end = (chunk_start + MAX_CHUNK).min(q.data.len());
                let fin = q.offset + sent + (chunk_end - chunk_start) as u64 >= q.data.len() as u64;
                chunks.push((
                    q.offset + sent,
                    q.data[chunk_start..chunk_end].to_vec(),
                    fin,
                ));
                sent += (chunk_end - chunk_start) as u64;
                if fin {
                    break;
                }
            }
            q.offset += sent;
            q.conn_used += sent;
            if chunks.last().map(|c| c.2).unwrap_or(false) {
                q.fin_sent = true;
            }
            chunks
        };
        for (off, data, fin) in chunks {
            let len = data.len() as u64;
            self.send_packet(
                Space::Application,
                vec![Frame::Stream {
                    stream_id,
                    offset: Some(off),
                    data,
                    length: Some(len),
                    fin,
                }],
                false,
            )?;
        }
        Ok(())
    }

    // -- loss recovery ----------------------------------------------------

    fn pto_timeout(&self) -> Duration {
        let base = match self.srtt {
            Some(srtt) => srtt + self.rttvar.max(Duration::from_millis(1)) + MAX_ACK_DELAY,
            None => INITIAL_PTO,
        };
        base.max(Duration::from_millis(PTO_FLOOR_MS))
            .saturating_mul(2u32.saturating_pow(self.pto_count))
    }

    fn run_pto(&mut self) -> Result<()> {
        if self.sent.is_empty() {
            return Ok(());
        }
        if self.pto_count >= MAX_PTO_COUNT {
            self.closed = Some(Error::new(
                crate::error::ErrorKind::Timeout,
                "doq too many PTOs",
            ));
            return Err(self.closed.clone().unwrap());
        }
        let timeout = self.pto_timeout();
        let last_sent = self.sent.iter().map(|p| p.sent).max().unwrap();
        if Instant::now() < last_sent + timeout {
            return Ok(());
        }
        // PTO fired: retransmit unacknowledged ack-eliciting data with
        // fresh packet numbers.
        self.pto_count += 1;
        let retransmit: Vec<SentPacket> = self.sent.drain(..).collect();
        for p in retransmit {
            self.send_packet(p.space, p.frames, false)?;
        }
        Ok(())
    }
}

/// A random 8-byte connection ID.
fn random_cid() -> Vec<u8> {
    let mut cid = [0u8; 8];
    if !courierust::courierust_tls::crypto::rng::fill_random(&mut cid) {
        let mut s = crate::entropy::seed_u64();
        for b in cid.iter_mut() {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (s >> 33) as u8;
        }
    }
    cid.to_vec()
}

/// Build an ACK frame covering the given (ascending) packet numbers.
///
/// RFC 9000 §19.3.1: a range `(gap, range_len)` acknowledges packets
/// `[largest - range_len, largest]` where `largest` is the largest
/// acknowledged (or `previous_low - gap - 2` for subsequent ranges).
/// `range_len` therefore counts the packets *below* the range's largest
/// (so a range of one packet carries `range_len = 0`).
fn build_ack_frame(pns: &[u64]) -> Frame {
    let mut sorted: Vec<u64> = pns.to_vec();
    sorted.sort_unstable();
    // Descending runs of consecutive packet numbers: (low, len).
    let mut runs: Vec<(u64, u64)> = Vec::new();
    let mut i = sorted.len();
    while i > 0 {
        let largest = sorted[i - 1];
        let mut len = 1u64;
        i -= 1;
        while i > 0 && largest.checked_sub(len) == Some(sorted[i - 1]) {
            len += 1;
            i -= 1;
        }
        runs.push((largest + 1 - len, len));
    }
    if runs.is_empty() {
        return Frame::Ack {
            largest_acked: 0,
            ack_delay: 0,
            ranges: vec![(0, 0)],
            ecn: None,
        };
    }
    let (top_low, top_len) = runs[0];
    let largest_acked = top_low + top_len - 1;
    let mut ranges = vec![(0u64, top_len - 1)];
    let mut prev_low = top_low;
    for &(low, len) in runs.iter().skip(1) {
        let run_largest = low + len - 1;
        let gap = prev_low.saturating_sub(run_largest + 2);
        ranges.push((gap, len - 1));
        prev_low = low;
    }
    Frame::Ack {
        largest_acked,
        ack_delay: 0,
        ranges,
        ecn: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_frame_single_run() {
        let f = build_ack_frame(&[0, 1, 2, 3]);
        let Frame::Ack {
            largest_acked,
            ref ranges,
            ..
        } = f
        else {
            panic!("expected ACK");
        };
        assert_eq!(largest_acked, 3);
        assert_eq!(*ranges, vec![(0, 3)]);
        // Round-trip through the codec.
        let wire = f.to_bytes();
        let (decoded, used) = Frame::decode(&wire).unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(decoded, f);
    }

    #[test]
    fn ack_frame_two_runs() {
        // Ack 5,6 and 0,1 (gap of 2 unacked: 2,3,4 between).
        let f = build_ack_frame(&[0, 1, 5, 6]);
        let Frame::Ack {
            largest_acked,
            ref ranges,
            ..
        } = f
        else {
            panic!("expected ACK");
        };
        assert_eq!(largest_acked, 6);
        // First range acked 6,5 (range_len = 1). Second range: gap from
        // low=5 to run largest=1 is 2, range_len = 1 (acked 1,0).
        assert_eq!(ranges[0], (0, 1));
        assert_eq!(ranges[1], (2, 1));
        let wire = f.to_bytes();
        let (decoded, used) = Frame::decode(&wire).unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(decoded, f);
    }

    #[test]
    fn crypto_reassembly_ordered_and_unordered() {
        let mut rx = CryptoRx::default();
        rx.insert(0, b"hello ").unwrap();
        rx.insert(6, b"world").unwrap();
        assert_eq!(rx.buf, b"hello world");
        // Out-of-order insert that fills the gap.
        let mut rx2 = CryptoRx::default();
        rx2.insert(5, b"xyz").unwrap();
        rx2.insert(0, b"abcde").unwrap();
        assert_eq!(rx2.buf, b"abcdexyz");
        // A full TLS message pops; an incomplete one does not.
        let mut rx3 = CryptoRx::default();
        let msg = {
            let body = [1u8, 2, 3];
            let mut m = vec![2u8, 0, 0, 3];
            m.extend_from_slice(&body);
            m
        };
        rx3.insert(0, &msg[..5]).unwrap();
        assert!(rx3.pop_message().is_none());
        rx3.insert(5, &msg[5..]).unwrap();
        let popped = rx3.pop_message().unwrap();
        assert_eq!(popped, msg);
        assert!(rx3.pop_message().is_none());
    }

    #[test]
    fn crypto_reassembly_retransmitted_head_does_not_corrupt() {
        // Regression: a server that retransmits the first CRYPTO frame
        // (offset 0) after we have already popped leading messages must
        // not splice the retransmitted bytes after the leftover tail of
        // the flight. The buffered region is tracked by absolute offset,
        // so the duplicate is dropped, not appended.
        let msg1 = vec![2u8, 0, 0, 3, 1, 2, 3]; // type 2, 3-byte body
        let msg2 = vec![4u8, 0, 0, 3, 4, 5, 6]; // type 4, 3-byte body
        let mut flight = msg1.clone();
        flight.extend_from_slice(&msg2);
        let mut rx = CryptoRx::default();
        // First packet: entire flight (offset 0).
        rx.insert(0, &flight).unwrap();
        assert_eq!(rx.pop_message().unwrap(), msg1);
        assert_eq!(rx.pop_message().unwrap(), msg2);
        // Retransmission of the same first packet (offset 0, same bytes):
        // must be ignored (all bytes already consumed), leaving no
        // garbage behind.
        rx.insert(0, &flight).unwrap();
        assert!(rx.pop_message().is_none());
        assert_eq!(rx.buf.len(), 0);
        // A continuation after the flight still lands in the right place.
        let msg3 = vec![6u8, 0, 0, 3, 7, 8, 9];
        rx.insert(flight.len() as u64, &msg3).unwrap();
        assert_eq!(rx.pop_message().unwrap(), msg3);
        assert!(rx.pop_message().is_none());
    }

    #[test]
    fn crypto_reassembly_split_flight_with_retransmission() {
        // The exact interop scenario: flight = EE(4+3) + Cert(4+3) + CV
        // split across two packets; the first packet is retransmitted
        // after the second has been buffered out of order.
        let ee = vec![8u8, 0, 0, 3, 0x11, 0x22, 0x33];
        let cert = vec![11u8, 0, 0, 3, 0xaa, 0xbb, 0xcc];
        let cv = vec![15u8, 0, 0, 3, 0xdd, 0xee, 0xff];
        let mut flight = ee.clone();
        flight.extend_from_slice(&cert);
        flight.extend_from_slice(&cv);
        let cut = ee.len() + cert.len();
        // Packet 1: EE + Cert (offset 0). Packet 2: CV (offset `cut`).
        let mut rx = CryptoRx::default();
        rx.insert(0, &flight[..cut]).unwrap();
        rx.insert(cut as u64, &cv).unwrap();
        assert_eq!(rx.pop_message().unwrap(), ee);
        assert_eq!(rx.pop_message().unwrap(), cert);
        // Now the server retransmits packet 1 (offset 0) — must be
        // dropped, and the buffered CV must remain intact.
        rx.insert(0, &flight[..cut]).unwrap();
        assert_eq!(rx.pop_message().unwrap(), cv);
        assert!(rx.pop_message().is_none());
    }

    #[test]
    fn short_header_offsets() {
        let local_cid = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let hdr = packet::encode_short(&local_cid, 42, PN_LEN, false).unwrap();
        // 1 (flags) + 8 (cid) + 4 (pn) = 13 bytes.
        assert_eq!(hdr.len(), 13);
        assert_eq!(&hdr[1..9], &local_cid[..]);
        // The first byte carries the fixed bit and pn-len field 3.
        assert_eq!(hdr[0] & 0x40, 0x40);
        assert_eq!(hdr[0] & 0x03, 3);
    }
}
