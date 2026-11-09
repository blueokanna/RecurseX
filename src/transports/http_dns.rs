//! HTTP DNS policy shared by the DoH and DoH3 adapters.

use crate::error::{Error, Result};
use crate::sync::Mutex;
use crate::transport::MAX_TCP_MESSAGE;
use crate::upstream::Endpoint;
use courierust::courierust_client::{Client, ClientConfig, TlsSettings};
use courierust::courierust_tls::RootStore;
use std::net::IpAddr;
use std::time::Duration;

/// courierust 1.1.1 uses the URL host for both routing and TLS identity.
/// Only a literal identity equal to the configured IP can guarantee that
/// no bootstrap lookup or different destination is used.
pub(crate) fn validate_endpoint(host: &str, endpoint: &Endpoint) -> Result<()> {
    if host.parse::<IpAddr>().ok() != Some(endpoint.ip) {
        return Err(Error::config(
            "pinned DoH requires a TLS IP identity equal to the upstream IP; courierust 1.1.1 cannot override the URL connection address",
        ));
    }
    Ok(())
}

pub(crate) struct Settings<'a> {
    pub host: &'a str,
    pub path: &'a str,
    pub roots: &'a RootStore,
    pub verify: bool,
    pub now: i64,
    pub http3: bool,
}

#[derive(Default)]
pub(crate) struct HttpDnsClient {
    cached: Mutex<Option<CachedClient>>,
}

struct CachedClient {
    endpoint: Endpoint,
    roots: RootStore,
    verify: bool,
    now: i64,
    timeout_ms: u64,
    client: Client,
}

impl HttpDnsClient {
    pub(crate) fn exchange(
        &self,
        settings: Settings<'_>,
        query: &[u8],
        endpoint: &Endpoint,
        timeout_ms: u64,
    ) -> Result<Vec<u8>> {
        validate_endpoint(settings.host, endpoint)?;
        if query.len() > MAX_TCP_MESSAGE {
            return Err(Error::transport("DNS query exceeds the wire size limit"));
        }
        if timeout_ms == 0 {
            return Err(Error::new(
                crate::error::ErrorKind::Timeout,
                "HTTP DNS exchange deadline exhausted",
            ));
        }
        let deadline = super::io::Deadline::after(timeout_ms)?;
        if !settings.path.starts_with('/')
            || settings
                .path
                .bytes()
                .any(|byte| byte <= b' ' || byte == 127 || byte == b'#')
        {
            return Err(Error::config(
                "DoH path must be an absolute URI path without whitespace or a fragment",
            ));
        }
        if settings.verify && settings.roots.is_empty() {
            return Err(Error::config("encrypted DNS requires trust roots"));
        }
        let now = super::io::certificate_time(settings.now)?;
        let client = {
            let mut cached = self.cached.lock();
            let reusable = cached.as_ref().is_some_and(|entry| {
                entry.endpoint == *endpoint
                    && entry.verify == settings.verify
                    && entry.now == now
                    && entry.timeout_ms == timeout_ms
                    && same_roots(&entry.roots, settings.roots)
            });
            if !reusable {
                let timeout = Some(Duration::from_millis(timeout_ms));
                let config = ClientConfig {
                    http2: !settings.http3,
                    http3: settings.http3,
                    max_connections_per_host: if settings.http3 { 1 } else { 4 },
                    connect_timeout: timeout,
                    handshake_timeout: timeout,
                    read_timeout: timeout,
                    max_redirects: 0,
                    accept_encoding: false,
                    retry: None,
                    tls: Some(TlsSettings {
                        roots: settings.roots.clone(),
                        verify: settings.verify,
                        alpn: if settings.http3 {
                            vec![b"h3".to_vec()]
                        } else {
                            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
                        },
                        now,
                        ..Default::default()
                    }),
                    max_body: MAX_TCP_MESSAGE,
                    max_header_list: 16 * 1024,
                    ..Default::default()
                };
                *cached = Some(CachedClient {
                    endpoint: *endpoint,
                    roots: settings.roots.clone(),
                    verify: settings.verify,
                    now,
                    timeout_ms,
                    client: Client::with_config(config),
                });
            }
            cached
                .as_ref()
                .map(|entry| entry.client.clone())
                .ok_or_else(|| Error::internal("HTTP DNS client initialization failed"))?
        };
        let authority = std::net::SocketAddr::new(endpoint.ip, endpoint.port);
        let response = client
            .request(
                &format!("https://{authority}{}", settings.path),
                courierust::courierust_http::Method::POST,
            )
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .header("accept-encoding", "identity")
            .body(query.to_vec())
            .timeout(Duration::from_millis(timeout_ms))
            .send()
            .map_err(|error| http_error("HTTP DNS request", error, deadline))?;
        if response.status.as_u16() != 200 {
            return Err(Error::transport(format!(
                "HTTP DNS status {}",
                response.status.as_u16()
            )));
        }
        let content_type = response
            .headers
            .get("content-type")
            .and_then(|value| core::str::from_utf8(value.as_bytes()).ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if !content_type.is_some_and(|value| value.eq_ignore_ascii_case("application/dns-message"))
        {
            return Err(Error::transport(
                "HTTP DNS response has an invalid content-type",
            ));
        }
        let body = response
            .body
            .collect()
            .map_err(|error| http_error("HTTP DNS body", error, deadline))?;
        deadline
            .remaining()
            .map_err(|error| super::io::network_error("HTTP DNS deadline", error))?;
        if !(12..=MAX_TCP_MESSAGE).contains(&body.len()) {
            return Err(Error::transport(
                "HTTP DNS response has an invalid DNS message length",
            ));
        }
        Ok(body.to_vec())
    }
}

fn same_roots(left: &RootStore, right: &RootStore) -> bool {
    left.len() == right.len()
        && left
            .roots()
            .iter()
            .zip(right.roots())
            .all(|(a, b)| a.der == b.der)
}

fn http_error(
    context: &str,
    error: courierust::courierust_error::Error,
    deadline: super::io::Deadline,
) -> Error {
    let kind = if deadline.remaining().is_err() {
        crate::error::ErrorKind::Timeout
    } else {
        match error.kind {
            courierust::courierust_error::ErrorKind::Timeout
            | courierust::courierust_error::ErrorKind::WouldBlock => {
                crate::error::ErrorKind::Timeout
            }
            courierust::courierust_error::ErrorKind::Io => crate::error::ErrorKind::Io,
            _ => crate::error::ErrorKind::Transport,
        }
    };
    Error::new(kind, format!("{context}: {error}"))
}
