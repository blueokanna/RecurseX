//! Direct DoQ transport probe: establishes a QUIC connection to a real
//! RFC 9250 server and prints every error verbatim. Used to debug the
//! built-in QUIC client without the resolver's fallback logic.
//!
//! Set RECURSEX_CA_FILE to a PEM trust bundle before running.
//! Run: `cargo run --example doq_probe [name]`

use recurse_x::transport::DnsTransport;
use recurse_x::transports::doq::DoqTransport;
use recurse_x::upstream::{Endpoint, Proto};
use recurse_x::{Message, Name, RrType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".to_string());
    let server = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "1.1.1.1".to_string());
    let server_name = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "cloudflare-dns.com".to_string());

    let name = Name::from_ascii(&host)?;
    let query = Message::query((std::process::id() & 0xffff) as u16, name, RrType::A, true);
    let bytes = query.to_bytes()?;
    let ep = Endpoint::new(server.parse()?, 853, Proto::DoQ);
    let mut roots = courierust::courierust_tls::RootStore::new();
    roots
        .add_pem_file(
            std::env::var("RECURSEX_CA_FILE")
                .map_err(|_| "set RECURSEX_CA_FILE to a PEM trust bundle")?,
        )
        .map_err(|e| format!("trust roots: {e}"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let t = DoqTransport::for_host(server_name, roots, true, now);
    let started = std::time::Instant::now();
    match t.exchange(&bytes, &ep, 10_000) {
        Ok(resp) => {
            let msg = Message::parse(&resp)?;
            println!(
                "OK rcode={:?} answers={} [{}ms]",
                msg.rcode(),
                msg.answers.len(),
                started.elapsed().as_millis()
            );
            for r in &msg.answers {
                println!("    {} {:?}", r.name, r.rdata);
            }
        }
        Err(e) => {
            println!("ERROR: {:?}", e);
            println!("kind={:?} msg={}", e.kind, e.msg);
        }
    }
    Ok(())
}
