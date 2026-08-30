//! Direct DoQ transport probe: establishes a QUIC connection to a real
//! RFC 9250 server and prints every error verbatim. Used to debug the
//! built-in QUIC client without the resolver's fallback logic.
//!
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
    let t = DoqTransport::for_host(
        server_name,
        courierust::courierust_tls::RootStore::new(),
        false,
        0,
    );
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
