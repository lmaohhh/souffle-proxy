use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

fn next_conn_id() -> u64 {
    NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug)]
pub struct UpstreamSendError {
    pub error: UpstreamError,
    pub conn_id: Option<u64>,
}

use bytes::{Buf, Bytes};
use futures_util::Stream;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

#[derive(Debug)]
pub enum UpstreamError {
    Connect(std::io::Error),
    H2StreamReset { error_code: u32 },
    H2GoAway { error_code: u32 },
    H2Protocol(String),
    H3StreamReset { error_code: u64 },
    H3GoAway { error_code: u64 },
    H3Protocol(String),
    /// The request header block exceeds what the peer accepts. Permanent: the
    /// identical request fails the same way on a fresh connection.
    HeaderTooBig { actual_size: u64, max_size: u64 },
    Timeout,
    Other(String),
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamError::Connect(e) => write!(f, "Connect error: {e}"),
            UpstreamError::H2StreamReset { error_code } => {
                write!(f, "H2StreamReset(error_code={error_code})")
            }
            UpstreamError::H2GoAway { error_code, .. } => {
                write!(f, "H2GoAway(error_code={error_code})")
            }
            UpstreamError::H2Protocol(s) => write!(f, "H2Protocol: {s}"),
            UpstreamError::H3StreamReset { error_code } => {
                write!(f, "H3StreamReset(error_code={error_code:#x})")
            }
            UpstreamError::H3GoAway { error_code } => {
                write!(f, "H3GoAway(error_code={error_code:#x})")
            }
            UpstreamError::H3Protocol(s) => write!(f, "H3Protocol: {s}"),
            UpstreamError::HeaderTooBig {
                actual_size,
                max_size,
            } => write!(
                f,
                "HeaderTooBig: request header block is {actual_size} bytes (peer max {max_size})"
            ),
            UpstreamError::Timeout => write!(f, "Upstream timeout"),
            UpstreamError::Other(s) => write!(f, "Upstream error: {s}"),
        }
    }
}

impl std::error::Error for UpstreamError {}

impl UpstreamError {
    #[allow(dead_code)]
    pub fn is_refused_or_rejected(&self) -> bool {
        matches!(
            self,
            Self::H2StreamReset { error_code: 7 } | Self::H3StreamReset { error_code: 0x010b }
        )
    }

    #[allow(dead_code)]
    pub fn is_cancelled(&self) -> bool {
        matches!(
            self,
            Self::H2StreamReset { error_code: 8 } | Self::H3StreamReset { error_code: 0x010c }
        )
    }

    #[allow(dead_code)]
    pub fn is_goaway_clean(&self) -> bool {
        matches!(
            self,
            Self::H2GoAway { error_code: 0 }
                | Self::H3GoAway { error_code: 0x0100 }
                | Self::H3GoAway { error_code: 0 }
        )
    }

    #[allow(dead_code)]
    pub fn is_enhance_your_calm(&self) -> bool {
        matches!(
            self,
            Self::H2GoAway { error_code: 11 }
                | Self::H3StreamReset { error_code: 0x0107 }
                | Self::H3GoAway { error_code: 0x0107 }
        )
    }

    /// The failure is confined to one request stream; the shared connection is
    /// still usable. Closing the connection for these aborts every other
    /// response multiplexed on it (on H3 that is every concurrent request).
    #[allow(dead_code)]
    pub fn is_stream_scoped(&self) -> bool {
        matches!(
            self,
            Self::H2StreamReset { .. } | Self::H3StreamReset { .. }
        )
    }

    /// The failure means the connection itself is going away (or the request
    /// never left the socket), so a retry must dial a fresh connection.
    /// Everything else — notably `HeaderTooBig` — would fail identically on a
    /// new connection and must be surfaced instead of retried.
    #[allow(dead_code)]
    pub fn is_connection_closing(&self) -> bool {
        match self {
            Self::Connect(_) | Self::Timeout => true,
            Self::H2GoAway { .. } | Self::H3GoAway { .. } => true,
            Self::H2Protocol(_) | Self::H3Protocol(_) => true,
            Self::H2StreamReset { .. } | Self::H3StreamReset { .. } => false,
            Self::HeaderTooBig { .. } => false,
            Self::Other(_) => false,
        }
    }
}

impl From<h2::Error> for UpstreamError {
    fn from(e: h2::Error) -> Self {
        if e.is_reset() {
            let code = e.reason().map(u32::from).unwrap_or(0);
            UpstreamError::H2StreamReset { error_code: code }
        } else if e.is_go_away() {
            let code = e.reason().map(u32::from).unwrap_or(0);
            UpstreamError::H2GoAway { error_code: code }
        } else if let Some(io_err) = e.get_io() {
            UpstreamError::Connect(std::io::Error::new(io_err.kind(), io_err.to_string()))
        } else {
            UpstreamError::H2Protocol(e.to_string())
        }
    }
}

impl From<h3::error::StreamError> for UpstreamError {
    fn from(e: h3::error::StreamError) -> Self {
        match e {
            h3::error::StreamError::RemoteTerminate { code, .. } => {
                UpstreamError::H3StreamReset {
                    error_code: code.value(),
                }
            }
            h3::error::StreamError::StreamError { code, .. } => {
                UpstreamError::H3StreamReset {
                    error_code: code.value(),
                }
            }
            h3::error::StreamError::RemoteClosing => {
                UpstreamError::H3GoAway { error_code: 0x0100 }
            }
            h3::error::StreamError::HeaderTooBig {
                actual_size,
                max_size,
            } => UpstreamError::HeaderTooBig {
                actual_size,
                max_size,
            },
            h3::error::StreamError::ConnectionError(ce) => ce.into(),
            other => UpstreamError::H3Protocol(format!("{other:?}")),
        }
    }
}

impl From<h3::error::ConnectionError> for UpstreamError {
    fn from(ce: h3::error::ConnectionError) -> Self {
        match ce {
            h3::error::ConnectionError::Remote(
                h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code },
            ) => UpstreamError::H3GoAway { error_code },
            h3::error::ConnectionError::Local {
                error: h3::error::LocalError::Application { code, .. },
                ..
            } => UpstreamError::H3GoAway {
                error_code: code.value(),
            },
            h3::error::ConnectionError::Timeout => UpstreamError::Timeout,
            other => UpstreamError::H3Protocol(format!("{other:?}")),
        }
    }
}

/// On Windows, disable WSAECONNRESET (10054) on UDP socket caused by transient ICMP port unreachable
#[cfg(windows)]
pub fn configure_windows_udp_socket(socket: &impl std::os::windows::io::AsRawSocket) -> std::io::Result<()> {
    const SIO_UDP_CONNRESET: u32 = 0x9800000C;
    let handle = socket.as_raw_socket();
    let mut bytes_returned: u32 = 0;
    let enable: u32 = 0; // FALSE: disable WSAECONNRESET on ICMP unreachable

    extern "system" {
        fn WSAIoctl(
            s: usize,
            dwIoControlCode: u32,
            lpvInBuffer: *const std::ffi::c_void,
            cbInBuffer: u32,
            lpvOutBuffer: *mut std::ffi::c_void,
            cbOutBuffer: u32,
            lpcbBytesReturned: *mut u32,
            lpOverlapped: *mut std::ffi::c_void,
            lpCompletionRoutine: *mut std::ffi::c_void,
        ) -> i32;
    }

    let ret = unsafe {
        WSAIoctl(
            handle as usize,
            SIO_UDP_CONNRESET,
            &enable as *const _ as *const std::ffi::c_void,
            std::mem::size_of_val(&enable) as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn configure_windows_udp_socket<T>(_socket: &T) -> std::io::Result<()> {
    Ok(())
}

#[derive(Debug)]
pub struct NoCertificateVerification(Arc<rustls::crypto::CryptoProvider>);

impl NoCertificateVerification {
    pub fn new() -> Self {
        Self(Arc::new(rustls::crypto::ring::default_provider()))
    }
}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

enum BodyStreamInner {
    H2 {
        recv: h2::RecvStream,
        last_goaway: Arc<AtomicI64>,
    },
    H3 {
        stream: Box<h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>>,
        last_goaway: Arc<AtomicI64>,
    },
}

pub struct BodyStream {
    inner: BodyStreamInner,
    conn_id: u64,
}

impl BodyStream {
    pub fn new(recv: h2::RecvStream, last_goaway: Arc<AtomicI64>, conn_id: u64) -> Self {
        Self {
            inner: BodyStreamInner::H2 { recv, last_goaway },
            conn_id,
        }
    }

    pub fn new_h3(
        stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        last_goaway: Arc<AtomicI64>,
        conn_id: u64,
    ) -> Self {
        Self {
            inner: BodyStreamInner::H3 {
                stream: Box::new(stream),
                last_goaway,
            },
            conn_id,
        }
    }

    pub fn conn_id(&self) -> u64 {
        self.conn_id
    }

    /// Read the body but stop once `max` bytes are buffered. Callers that only ever
    /// read a short preview use this so a misbehaving upstream cannot grow the buffer
    /// without bound. Returns what it got; truncation is not an error.
    pub async fn read_full_limited(self, max: usize) -> Result<Bytes, UpstreamError> {
        self.read_full_limited_checked(max).await.map(|(b, _)| b)
    }

    /// Same read, but reports whether the cap was reached while data remained, so a
    /// caller that forwards the body can fail loudly instead of shipping a truncated
    /// payload as a 200. Preview callers keep using `read_full_limited`.
    pub async fn read_full_limited_checked(
        mut self,
        max: usize,
    ) -> Result<(Bytes, bool), UpstreamError> {
        let mut buf = bytes::BytesMut::with_capacity(max.min(8192));
        let mut truncated = false;
        while let Some(chunk_res) = futures_util::StreamExt::next(&mut self).await {
            let chunk = chunk_res?;
            let room = max.saturating_sub(buf.len());
            if room == 0 {
                truncated = true;
                break;
            }
            if chunk.len() > room {
                buf.extend_from_slice(&chunk[..room]);
                truncated = true;
                break;
            }
            buf.extend_from_slice(&chunk);
        }
        Ok((buf.freeze(), truncated))
    }
}

impl Stream for BodyStream {
    type Item = Result<Bytes, UpstreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match &mut self.inner {
            BodyStreamInner::H2 { recv, last_goaway } => {
                match recv.poll_data(cx) {
                    Poll::Ready(Some(Ok(bytes))) => {
                        let _ = recv.flow_control().release_capacity(bytes.len());
                        Poll::Ready(Some(Ok(bytes)))
                    }
                    Poll::Ready(Some(Err(e))) => {
                        let err = UpstreamError::from(e);
                        match err {
                            UpstreamError::Connect(_) | UpstreamError::H2Protocol(_) => {
                                let code = last_goaway.load(Ordering::Acquire);
                                if code >= 0 {
                                    return Poll::Ready(Some(Err(UpstreamError::H2GoAway {
                                        error_code: code as u32,
                                    })));
                                }
                            }
                            _ => {}
                        }
                        Poll::Ready(Some(Err(err)))
                    }
                    Poll::Ready(None) => Poll::Ready(None),
                    Poll::Pending => Poll::Pending,
                }
            }
            BodyStreamInner::H3 { stream, last_goaway } => {
                match stream.poll_recv_data(cx) {
                    Poll::Ready(Ok(Some(mut buf))) => {
                        // In h3-quinn 0.0.10, BidiStream::Buf = bytes::Bytes, so
                        // copy_to_bytes(remaining) calls Bytes::split_to — O(1) zero-copy.
                        let chunk = buf.copy_to_bytes(buf.remaining());
                        Poll::Ready(Some(Ok(chunk)))
                    }
                    Poll::Ready(Ok(None)) => Poll::Ready(None),
                    Poll::Ready(Err(e)) => {
                        let err = UpstreamError::from(e);
                        match err {
                            UpstreamError::Connect(_) | UpstreamError::H3Protocol(_) => {
                                let code = last_goaway.load(Ordering::Acquire);
                                if code >= 0 {
                                    return Poll::Ready(Some(Err(UpstreamError::H3GoAway {
                                        error_code: code as u64,
                                    })));
                                }
                            }
                            _ => {}
                        }
                        Poll::Ready(Some(Err(err)))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}

pub struct UpstreamResponse {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub version: http::Version,
    pub body: BodyStream,
    pub conn_id: u64,
}

pub enum UpstreamStream {
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
    Plain(tokio::net::TcpStream),
}

impl tokio::io::AsyncRead for UpstreamStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            UpstreamStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
            UpstreamStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for UpstreamStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            UpstreamStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
            UpstreamStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            UpstreamStream::Tls(s) => Pin::new(s).poll_flush(cx),
            UpstreamStream::Plain(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            UpstreamStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
            UpstreamStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[derive(Clone)]
struct ActiveConn {
    id: u64,
    handle: h2::client::SendRequest<Bytes>,
    last_goaway: Arc<AtomicI64>,
    /// Set by the connection's keepalive task when a PING went unanswered past
    /// the pong timeout: the connection is WEDGED (socket open, h2 dead) and
    /// poll_ready can still pass, so get_connection checks this flag first and
    /// drops the pooled connection instead of reusing it.
    wedge_flag: Arc<AtomicBool>,
    /// Keepalive PING task for THIS connection; aborted when the connection is
    /// invalidated or replaced.
    keepalive_abort: Option<tokio::task::AbortHandle>,
}

/// One resolved upstream endpoint (one URL from the failover list).
#[derive(Clone, Debug)]
pub struct Target {
    pub base_url: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub chat_uri: http::Uri,
}

impl Target {
    pub fn sni_host(&self) -> &str {
        self.host.trim_start_matches('[').trim_end_matches(']')
    }

    fn parse(upstream_url: &str) -> Result<Self, UpstreamError> {
        let uri: http::Uri = upstream_url
            .parse()
            .map_err(|e: http::uri::InvalidUri| UpstreamError::Other(e.to_string()))?;
        let scheme = uri.scheme_str().unwrap_or("https").to_string();
        let host = uri
            .host()
            .ok_or_else(|| UpstreamError::Other("Missing host in upstream URL".into()))?
            .to_string();
        let port = uri
            .port_u16()
            .unwrap_or(if scheme == "http" { 80 } else { 443 });
        let path_prefix = uri.path().trim_end_matches('/').to_string();
        let chat_uri_str = format!(
            "{}://{}:{}{}/chat/completions",
            scheme, host, port, path_prefix
        );
        let chat_uri: http::Uri = chat_uri_str
            .parse()
            .map_err(|e: http::uri::InvalidUri| UpstreamError::Other(e.to_string()))?;
        Ok(Self {
            base_url: upstream_url.to_string(),
            scheme,
            host,
            port,
            chat_uri,
        })
    }
}

#[derive(Clone)]
pub struct H2Client {
    /// Failover list of upstream endpoints, tried in order. `active_idx` is
    /// sticky: it only advances when a connection to the current target
    /// FAILS TO ESTABLISH (transport fault), so a healthy base is never
    /// abandoned mid-traffic. HTTP 5xx/524 from a base that answered does
    /// NOT rotate (on this provider the bases share an origin, so rotating
    /// on an application error just doubles the toll).
    pub targets: Arc<Vec<Target>>,
    active_idx: Arc<AtomicUsize>,
    pub tls_config: Arc<rustls::ClientConfig>,
    pub connect_timeout: Duration,
    /// Keepalive PING interval for pooled h2 connections.
    keepalive: Duration,
    active_conn: Arc<tokio::sync::Mutex<Option<ActiveConn>>>,
    connect_lock: Arc<tokio::sync::Mutex<()>>,
}

impl H2Client {
    /// Build a client from a comma-separated failover list (or a single URL).
    /// ALL URLs must parse — one bad URL fails the whole constructor. At
    /// least one valid URL is required.
    pub fn new(
        upstream_urls: &str,
        connect_timeout: Duration,
        keepalive: Duration,
        insecure_tls: bool,
    ) -> Result<Self, UpstreamError> {
        let targets: Vec<Target> = upstream_urls
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(Target::parse)
            .collect::<Result<Vec<_>, _>>()?;
        if targets.is_empty() {
            return Err(UpstreamError::Other(
                "No upstream URL configured (SOUFFLE_UPSTREAM_BASE empty)".into(),
            ));
        }

        let tls_config = if insecure_tls {
            let mut config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification::new()))
                .with_no_client_auth();
            config.alpn_protocols = vec![b"h2".to_vec()];
            Arc::new(config)
        } else {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"h2".to_vec()];
            Arc::new(config)
        };

        Ok(Self {
            targets: Arc::new(targets),
            active_idx: Arc::new(AtomicUsize::new(0)),
            tls_config,
            connect_timeout,
            keepalive,
            active_conn: Arc::new(tokio::sync::Mutex::new(None)),
            connect_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// The upstream endpoint currently in use. The dispatch loop reads only
    /// `chat_uri` from here to build the request URI; `scheme`/`host`/`port`
    /// are consumed by `connect_raw` when establishing the connection.
    pub fn current_target(&self) -> &Target {
        let idx = self.active_idx.load(Ordering::Relaxed) % self.targets.len();
        &self.targets[idx]
    }

    /// Advance to the next target in the failover list (wraps). Called only
    /// when the current target fails to establish a connection. Returns the
    /// new active target's base_url for logging.
    fn rotate_target(&self) -> String {
        let n = self.targets.len();
        let next = (self.active_idx.load(Ordering::Relaxed) + 1) % n;
        self.active_idx.store(next, Ordering::Relaxed);
        self.targets[next].base_url.clone()
    }

    pub async fn invalidate_connection(&self) {
        let mut lock = self.active_conn.lock().await;
        if let Some(conn) = lock.take() {
            // Stop the connection's keepalive PING task along with it.
            if let Some(ab) = &conn.keepalive_abort {
                ab.abort();
            }
        }
    }

    pub async fn invalidate_if_same(&self, failed_id: u64) {
        let mut lock = self.active_conn.lock().await;
        if lock.as_ref().is_some_and(|c| c.id == failed_id) {
            if let Some(conn) = lock.take() {
                if let Some(ab) = &conn.keepalive_abort {
                    ab.abort();
                }
            }
        }
    }

    /// Stream-scoped failure (RST_STREAM REFUSED_STREAM / CANCEL): the request
    /// stream is already dead, so the pooled connection is dropped only to get a
    /// clean socket for the retry. Unlike H3 there is no collateral damage --
    /// the h2 driver task keeps in-flight streams alive on its own.
    pub async fn invalidate_stream_if_same(&self, failed_id: u64) {
        self.invalidate_if_same(failed_id).await;
    }

    async fn connect_raw(&self, target: &Target) -> Result<ActiveConn, UpstreamError> {
        // ONE deadline for the whole attempt (TCP + TLS + h2 handshake). Applying
        // connect_timeout to each stage serially let a dead peer hold the
        // connect_lock for up to 3x the configured budget.
        let deadline = tokio::time::Instant::now() + self.connect_timeout;
        let remaining = |deadline: tokio::time::Instant| -> Result<Duration, UpstreamError> {
            deadline
                .checked_duration_since(tokio::time::Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(UpstreamError::Timeout)
        };

        let tcp = tokio::time::timeout(
            remaining(deadline)?,
            tokio::net::TcpStream::connect((target.sni_host(), target.port)),
        )
        .await
        .map_err(|_| UpstreamError::Timeout)?
        .map_err(UpstreamError::Connect)?;

        let _ = configure_tcp_keepalive(&tcp);
        let _ = tcp.set_nodelay(true);

        let stream: UpstreamStream = if target.scheme == "https" {
            let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());
            let server_name = ServerName::try_from(target.sni_host().to_string())
                .map_err(|e| {
                    UpstreamError::Other(format!("Invalid DNS name {}: {:?}", target.host, e))
                })?
                .to_owned();

            let tls =
                tokio::time::timeout(remaining(deadline)?, connector.connect(server_name, tcp))
                    .await
                    .map_err(|_| UpstreamError::Timeout)?
                    .map_err(UpstreamError::Connect)?;

            UpstreamStream::Tls(Box::new(tls))
        } else {
            UpstreamStream::Plain(tcp)
        };

        // Stock h2 settings (spec defaults: 64KB stream + connection windows,
        // 16KB frames) -- deliberately NOT tuned. Proposal 1 expanded these to
        // 2MB/8MB and was only ever validated on loopback with ~5KB payloads
        // (verdict: NEUTRAL, "retained because harmless" -- WAN benefit
        // unproven). In production the proxy died on ~1.1MB WAN streams through
        // the relay (RST_STREAM at ~5min, silent stalls), while the Python twin
        // (httpx, stock h2) ran the same relay overnight without incident.
        // Mimic the working profile: no overrides at all.
        let builder = h2::client::Builder::new();

        let (send_req, connection) =
            tokio::time::timeout(remaining(deadline)?, builder.handshake(stream))
                .await
                .map_err(|_| UpstreamError::Timeout)?
                .map_err(UpstreamError::from)?;

        let last_goaway = Arc::new(AtomicI64::new(-1));
        let last_goaway_conn = last_goaway.clone();
        // Take the PING handle BEFORE the connection is moved into its driver
        // task: ping_pong needs &mut and can only be taken once per connection.
        let mut connection = connection;
        let user_ping = connection.ping_pong();
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                if e.is_go_away() {
                    let code = e.reason().map(u32::from).unwrap_or(0);
                    last_goaway_conn.store(code as i64, Ordering::Release);
                }
            }
        });

        // Keepalive PING task for this connection: keeps NAT/firewall mappings
        // alive over WAN idle periods (Cloudflare's client-facing h2 idle limit
        // is 400s — overnight idle always kills the connection) and detects a
        // wedged connection via the pong timeout instead of at the next request.
        let wedge_flag = Arc::new(AtomicBool::new(false));
        let mut keepalive_abort: Option<tokio::task::AbortHandle> = None;
        // SOUFFLE_KEEPALIVE_EXPIRY=0 disables the keepalive entirely. An
        // interval of 0 would otherwise mean sleep(0) between PINGs — a
        // sustained PING flood, the documented ENHANCE_YOUR_CALM failure mode.
        if self.keepalive.as_secs() > 0 {
            if let Some(pp) = user_ping {
                keepalive_abort = Some(
                    tokio::spawn(keepalive_loop(pp, self.keepalive, wedge_flag.clone()))
                        .abort_handle(),
                );
            }
        }

        Ok(ActiveConn {
            id: next_conn_id(),
            handle: send_req,
            last_goaway,
            wedge_flag,
            keepalive_abort,
        })
    }

    async fn connect_with_failover(&self) -> Result<ActiveConn, UpstreamError> {
        // Try the current target; on a transport failure to ESTABLISH, rotate
        // through the remaining failover targets once each. A single working
        // base short-circuits; if every base fails, surface the last error.
        let n = self.targets.len();
        let mut last_err = None;
        for _ in 0..n {
            let target = self.current_target().clone();
            match self.connect_raw(&target).await {
                Ok(new_conn) => {
                    let mut lock = self.active_conn.lock().await;
                    *lock = Some(new_conn.clone());
                    return Ok(new_conn);
                }
                Err(e) => {
                    last_err = Some(e);
                    if n > 1 {
                        let next = self.rotate_target();
                        eprintln!(
                            "[Souffle-Proxy] Upstream connect failed for {}; failing over to {}",
                            target.base_url, next
                        );
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| UpstreamError::Other("No upstream targets".into())))
    }

    async fn get_connection_inner(&self, probe_ready: bool) -> Result<ActiveConn, UpstreamError> {
        // Fast path: check existing pooled connection under short-lived lock
        let existing = {
            let lock = self.active_conn.lock().await;
            lock.clone()
        };
        if let Some(conn) = existing {
            let wedged = conn.wedge_flag.load(Ordering::Acquire);
            if !wedged {
                if !probe_ready {
                    return Ok(conn);
                }
                let mut test_handle = conn.handle.clone();
                let is_alive = futures_util::future::poll_fn(|cx| test_handle.poll_ready(cx)).await;
                if is_alive.is_ok() {
                    return Ok(conn);
                }
            }
        }

        // Slow path: serialize connection establishment across concurrent tasks
        let _connect_guard = self.connect_lock.lock().await;

        // Double check: another task may have established a connection while we waited
        let double_check = {
            let lock = self.active_conn.lock().await;
            lock.clone()
        };
        if let Some(conn) = double_check {
            let wedged = conn.wedge_flag.load(Ordering::Acquire);
            if !wedged {
                if !probe_ready {
                    return Ok(conn);
                }
                let mut test_handle = conn.handle.clone();
                let is_alive = futures_util::future::poll_fn(|cx| test_handle.poll_ready(cx)).await;
                if is_alive.is_ok() {
                    return Ok(conn);
                }
            }
            // Stale, wedged, or dead connection - clear it under lock
            let mut lock = self.active_conn.lock().await;
            if lock.as_ref().is_some_and(|c| c.id == conn.id) {
                if let Some(mut c) = lock.take() {
                    if let Some(ab) = c.keepalive_abort.take() {
                        ab.abort();
                    }
                }
            }
        }

        // Perform network handshake with active_conn lock UNHELD
        self.connect_with_failover().await
    }

    async fn get_connection(&self) -> Result<ActiveConn, UpstreamError> {
        self.get_connection_inner(true).await
    }

    /// Acquire a pooled H2 connection without running a throwaway `poll_ready`
    /// probe; `send_stream` immediately awaits `conn.handle.ready().await`.
    async fn get_or_connect(&self) -> Result<ActiveConn, UpstreamError> {
        self.get_connection_inner(false).await
    }

    pub async fn send_stream(
        &self,
        req: http::Request<Bytes>,
    ) -> Result<UpstreamResponse, UpstreamSendError> {
        let (parts, body) = req.into_parts();

        let mut conn = self
            .get_or_connect()
            .await
            .map_err(|error| UpstreamSendError {
                error,
                conn_id: None,
            })?;

        // Ensure stream capacity is available on this connection
        let mut ready_handle = match conn.handle.ready().await {
            Ok(h) => h,
            Err(_) => {
                // Connection became invalid while waiting for stream capacity
                self.invalidate_if_same(conn.id).await;
                conn = self
                    .get_or_connect()
                    .await
                    .map_err(|error| UpstreamSendError {
                        error,
                        conn_id: None,
                    })?;
                conn.handle
                    .ready()
                    .await
                    .map_err(|e| UpstreamSendError {
                        error: UpstreamError::from(e),
                        conn_id: Some(conn.id),
                    })?
            }
        };

        let conn_id = conn.id;
        let is_empty = body.is_empty();
        let (resp_fut, mut send_stream) = ready_handle
            .send_request(http::Request::from_parts(parts, ()), is_empty)
            .map_err(|e| UpstreamSendError {
                error: UpstreamError::from(e),
                conn_id: Some(conn_id),
            })?;

        if !is_empty {
            send_stream
                .send_data(body, true)
                .map_err(|e| UpstreamSendError {
                    error: UpstreamError::from(e),
                    conn_id: Some(conn_id),
                })?;
        }

        let resp = match resp_fut.await {
            Ok(r) => r,
            Err(e) => {
                let err = UpstreamError::from(e);
                match err {
                    UpstreamError::Connect(_) | UpstreamError::H2Protocol(_) => {
                        let code = conn.last_goaway.load(Ordering::Acquire);
                        if code >= 0 {
                            return Err(UpstreamSendError {
                                error: UpstreamError::H2GoAway {
                                    error_code: code as u32,
                                },
                                conn_id: Some(conn_id),
                            });
                        }
                    }
                    _ => {}
                }
                return Err(UpstreamSendError {
                    error: err,
                    conn_id: Some(conn_id),
                });
            }
        };
        let (resp_parts, recv_stream) = resp.into_parts();

        Ok(UpstreamResponse {
            status: resp_parts.status,
            headers: resp_parts.headers,
            version: resp_parts.version,
            body: BodyStream::new(recv_stream, conn.last_goaway, conn_id),
            conn_id,
        })
    }

    pub async fn prewarm(&self) -> Result<(), UpstreamError> {
        self.get_connection().await.map(|_| ())
    }
}

#[derive(Clone)]
struct ActiveH3Conn {
    id: u64,
    send_req: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    quinn_conn: quinn::Connection,
    last_goaway: Arc<AtomicI64>,
    driver_abort: Arc<tokio::task::AbortHandle>,
}

fn bind_h3_endpoint(is_ipv6: bool) -> Result<quinn::Endpoint, UpstreamError> {
    let bind_addr = if is_ipv6 { "[::]:0" } else { "0.0.0.0:0" };
    let std_sock = std::net::UdpSocket::bind(bind_addr).map_err(UpstreamError::Connect)?;
    configure_windows_udp_socket(&std_sock).map_err(UpstreamError::Connect)?;
    let sock_ref = socket2::SockRef::from(&std_sock);
    if is_ipv6 {
        // Windows defaults IPV6_V6ONLY=true; clear best-effort for dual-stack compatibility.
        let _ = sock_ref.set_only_v6(false);
    }
    let _ = sock_ref.set_send_buffer_size(1024 * 1024);
    let _ = sock_ref.set_recv_buffer_size(1024 * 1024);

    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        std_sock,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| UpstreamError::Connect(std::io::Error::other(e)))
}

/// Floor for the post-QUIC h3 control handshake. DNS + the QUIC handshake can
/// consume the whole connect budget, which used to leave this handshake with a
/// ~0s timeout and fail a connection whose QUIC handshake had just succeeded.
const H3_HANDSHAKE_FLOOR: Duration = Duration::from_secs(2);

/// Timeout for the h3 control handshake: whatever is left of the connect
/// budget, but never less than a bounded floor (itself capped by
/// `connect_timeout`, so a deliberately tiny budget stays tiny).
fn h3_handshake_budget(remaining: Duration, connect_timeout: Duration) -> Duration {
    remaining.max(connect_timeout.min(H3_HANDSHAKE_FLOOR))
}

#[derive(Clone)]
pub struct H3Client {
    pub targets: Arc<Vec<Target>>,
    active_idx: Arc<AtomicUsize>,
    endpoint: quinn::Endpoint,
    alt_endpoint: Arc<tokio::sync::Mutex<Option<quinn::Endpoint>>>,
    quinn_client_config: quinn::ClientConfig,
    pub connect_timeout: Duration,
    active_conn: Arc<tokio::sync::Mutex<Option<ActiveH3Conn>>>,
    connect_lock: Arc<tokio::sync::Mutex<()>>,
}

impl H3Client {
    pub fn new(
        upstream_urls: &str,
        connect_timeout: Duration,
        insecure_tls: bool,
    ) -> Result<Self, UpstreamError> {
        let targets: Vec<Target> = upstream_urls
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(Target::parse)
            .collect::<Result<Vec<_>, _>>()?;
        if targets.is_empty() {
            return Err(UpstreamError::Other(
                "No upstream URL configured for HTTP/3".into(),
            ));
        }

        let tls_config = if insecure_tls {
            let mut config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification::new()))
                .with_no_client_auth();
            config.alpn_protocols = vec![b"h3".to_vec()];
            Arc::new(config)
        } else {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"h3".to_vec()];
            Arc::new(config)
        };

        let mut transport = quinn::TransportConfig::default();
        // 15s keepalive PING interval prevents NAT/firewall drops during model reasoning stalls
        transport.keep_alive_interval(Some(Duration::from_secs(15)));
        transport.max_idle_timeout(Some(Duration::from_secs(60).try_into().map_err(|e| {
            UpstreamError::Other(format!("Invalid max_idle_timeout: {e}"))
        })?));
        transport.stream_receive_window(quinn::VarInt::from_u32(1024 * 1024));
        transport.receive_window(quinn::VarInt::from_u32(4 * 1024 * 1024));

        let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| UpstreamError::Other(format!("QUIC TLS config error: {e}")))?;
        let mut quinn_client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
        quinn_client_config.transport_config(Arc::new(transport));

        let first_is_ipv6 = targets.first().is_some_and(|t| {
            t.host.starts_with('[') || t.sni_host().parse::<std::net::Ipv6Addr>().is_ok()
        });
        let endpoint = bind_h3_endpoint(first_is_ipv6)?;

        Ok(Self {
            targets: Arc::new(targets),
            active_idx: Arc::new(AtomicUsize::new(0)),
            endpoint,
            alt_endpoint: Arc::new(tokio::sync::Mutex::new(None)),
            quinn_client_config,
            connect_timeout,
            active_conn: Arc::new(tokio::sync::Mutex::new(None)),
            connect_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    async fn endpoint_for_family(&self, want_ipv6: bool) -> Result<quinn::Endpoint, UpstreamError> {
        let primary_is_v6 = self
            .endpoint
            .local_addr()
            .map(|a| a.is_ipv6())
            .unwrap_or(false);
        if want_ipv6 == primary_is_v6 {
            return Ok(self.endpoint.clone());
        }
        let mut guard = self.alt_endpoint.lock().await;
        if let Some(ref ep) = *guard {
            return Ok(ep.clone());
        }
        let ep = bind_h3_endpoint(want_ipv6)?;
        *guard = Some(ep.clone());
        Ok(ep)
    }

    pub fn current_target(&self) -> &Target {
        let idx = self.active_idx.load(Ordering::Relaxed) % self.targets.len();
        &self.targets[idx]
    }

    fn rotate_target(&self) -> String {
        let n = self.targets.len();
        let next = (self.active_idx.load(Ordering::Relaxed) + 1) % n;
        self.active_idx.store(next, Ordering::Relaxed);
        self.targets[next].base_url.clone()
    }

    pub async fn invalidate_connection(&self) {
        let mut lock = self.active_conn.lock().await;
        if let Some(conn) = lock.take() {
            conn.quinn_conn.close(0u32.into(), b"invalidated");
            conn.driver_abort.abort();
        }
    }

    pub async fn invalidate_if_same(&self, failed_id: u64) {
        let mut lock = self.active_conn.lock().await;
        if lock.as_ref().is_some_and(|c| c.id == failed_id) {
            if let Some(conn) = lock.take() {
                conn.quinn_conn.close(0u32.into(), b"invalidated");
                conn.driver_abort.abort();
            }
        }
    }

    /// Stream-scoped failure (H3_REQUEST_REJECTED / H3_REQUEST_CANCELLED /
    /// H3_EXCESSIVE_LOAD, or any first-chunk stream reset): the request stream
    /// is already dead and needs no cleanup, and the pooled QUIC connection is
    /// still healthy for everyone else on it. Tearing the connection down here
    /// would abort every concurrent response multiplexed onto it -- one
    /// request's retryable reset would take out the whole in-flight batch.
    /// Callers must use `invalidate_if_same` only for connection-level faults.
    pub async fn invalidate_stream_if_same(&self, _failed_id: u64) {}

    async fn connect_raw(&self, target: &Target) -> Result<ActiveH3Conn, UpstreamError> {
        let deadline = tokio::time::Instant::now() + self.connect_timeout;
        let resolved: Vec<std::net::SocketAddr> = tokio::time::timeout(
            deadline
                .checked_duration_since(tokio::time::Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(UpstreamError::Timeout)?,
            tokio::net::lookup_host((target.sni_host(), target.port)),
        )
        .await
        .map_err(|_| UpstreamError::Timeout)?
        .map_err(UpstreamError::Connect)?
        .collect();

        if resolved.is_empty() {
            return Err(UpstreamError::Other(format!(
                "No addresses resolved for {}",
                target.host
            )));
        }

        // Prefer primary endpoint's address family first, falling back to the alternate
        // family (via lazy alt_endpoint) if DNS/failover returns IPv6-only or IPv4 fails.
        let primary_is_v4 = self
            .endpoint
            .local_addr()
            .map(|a| a.is_ipv4())
            .unwrap_or(true);
        let mut ordered = Vec::with_capacity(resolved.len());
        ordered.extend(resolved.iter().copied().filter(|a| a.is_ipv4() == primary_is_v4));
        ordered.extend(resolved.iter().copied().filter(|a| a.is_ipv4() != primary_is_v4));

        let mut last_err = None;
        let total_addrs = ordered.len();
        let mut connection_opt = None;
        for (idx, remote_addr) in ordered.into_iter().enumerate() {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                last_err = Some(UpstreamError::Timeout);
                break;
            }
            let remaining = deadline - now;
            let addrs_left = (total_addrs - idx) as u32;
            let attempt_budget = if addrs_left > 1 {
                (remaining / addrs_left)
                    .max(Duration::from_millis(500))
                    .min(remaining)
            } else {
                remaining
            };

            let ep = match self.endpoint_for_family(remote_addr.is_ipv6()).await {
                Ok(ep) => ep,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            let connecting = match ep.connect_with(
                self.quinn_client_config.clone(),
                remote_addr,
                target.sni_host(),
            ) {
                Ok(c) => c,
                Err(e) => {
                    last_err = Some(UpstreamError::Connect(std::io::Error::other(e)));
                    continue;
                }
            };
            match tokio::time::timeout(attempt_budget, connecting).await {
                Ok(Ok(conn)) => {
                    connection_opt = Some(conn);
                    break;
                }
                Ok(Err(e)) => {
                    last_err = Some(UpstreamError::Connect(std::io::Error::other(e)));
                }
                Err(_) => {
                    last_err = Some(UpstreamError::Timeout);
                }
            }
        }

        let connection = connection_opt.ok_or_else(|| {
            last_err.unwrap_or_else(|| UpstreamError::Other("QUIC connect failed".into()))
        })?;

        let quinn_conn_handle = connection.clone();
        let quinn_conn = h3_quinn::Connection::new(connection);
        let mut client_builder = h3::client::builder();
        client_builder.send_grease(false);

        // The h3 control handshake is an extra RTT after the QUIC handshake; give
        // it its own bounded window instead of whatever DNS + QUIC left over.
        let h3_budget = h3_handshake_budget(
            deadline.saturating_duration_since(tokio::time::Instant::now()),
            self.connect_timeout,
        );
        let (mut driver, send_req) =
            tokio::time::timeout(h3_budget, client_builder.build(quinn_conn))
                .await
                .map_err(|_| UpstreamError::Timeout)?
                .map_err(|e| UpstreamError::Other(format!("H3 handshake error: {e}")))?;

        let last_goaway = Arc::new(AtomicI64::new(-1));
        let last_goaway_clone = last_goaway.clone();
        let driver_task = tokio::spawn(async move {
            let e = driver.wait_idle().await;
            match e {
                h3::error::ConnectionError::Remote(
                    h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code },
                ) => {
                    last_goaway_clone.store(error_code as i64, Ordering::Release);
                }
                h3::error::ConnectionError::Local {
                    error: h3::error::LocalError::Application { code, .. },
                    ..
                } => {
                    last_goaway_clone.store(code.value() as i64, Ordering::Release);
                }
                _ => {}
            }
        });

        Ok(ActiveH3Conn {
            id: next_conn_id(),
            send_req,
            quinn_conn: quinn_conn_handle,
            last_goaway,
            driver_abort: Arc::new(driver_task.abort_handle()),
        })
    }

    async fn get_connection(&self) -> Result<ActiveH3Conn, UpstreamError> {
        // Fast path: check existing pooled connection under short-lived lock
        {
            let lock = self.active_conn.lock().await;
            if let Some(ref conn) = *lock {
                let is_finished = conn.driver_abort.is_finished();
                let goaway = conn.last_goaway.load(Ordering::Acquire);
                if !is_finished && goaway < 0 {
                    return Ok(conn.clone());
                }
            }
        }

        // Slow path: serialize connection establishment across concurrent tasks
        let _connect_guard = self.connect_lock.lock().await;

        // Double check: another task may have established a connection while we waited
        {
            let mut lock = self.active_conn.lock().await;
            if let Some(ref conn) = *lock {
                let is_finished = conn.driver_abort.is_finished();
                let goaway = conn.last_goaway.load(Ordering::Acquire);
                if !is_finished && goaway < 0 {
                    return Ok(conn.clone());
                }
                conn.quinn_conn.close(0u32.into(), b"invalidated");
                conn.driver_abort.abort();
                *lock = None;
            }
        }

        // Perform network handshake with active_conn lock UNHELD
        let n = self.targets.len();
        let mut last_err = None;
        for _ in 0..n {
            let target = self.current_target().clone();
            match self.connect_raw(&target).await {
                Ok(new_conn) => {
                    let mut lock = self.active_conn.lock().await;
                    *lock = Some(new_conn.clone());
                    return Ok(new_conn);
                }
                Err(e) => {
                    last_err = Some(e);
                    if n > 1 {
                        let next = self.rotate_target();
                        eprintln!(
                            "[Souffle-Proxy] Upstream H3 connect failed for {}; failing over to {}",
                            target.base_url, next
                        );
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| UpstreamError::Other("No upstream targets".into())))
    }

    pub async fn send_stream(
        &self,
        req: http::Request<Bytes>,
    ) -> Result<UpstreamResponse, UpstreamSendError> {
        let (parts, body) = req.into_parts();
        let mut conn = self
            .get_connection()
            .await
            .map_err(|error| UpstreamSendError {
                error,
                conn_id: None,
            })?;
        let mut send_req = conn.send_req.clone();

        // h3::client::SendRequest::send_request(Request<()>) takes Request by value and
        // has no poll_ready(), so parts.clone() is required to allow retrying on a fresh
        // connection if the pooled QUIC connection died while idle.
        let mut stream = match send_req
            .send_request(http::Request::from_parts(parts.clone(), ()))
            .await
        {
            Ok(s) => s,
            Err(e) => {
                let first_err = UpstreamError::from(e);
                // Only a dying connection is worth a second attempt. A permanent
                // request fault (HeaderTooBig, local protocol violation) would
                // fail identically on a fresh connection and its real error must
                // reach the caller instead of being replaced by the retry's.
                if !first_err.is_connection_closing() {
                    return Err(UpstreamSendError {
                        error: first_err,
                        conn_id: Some(conn.id),
                    });
                }
                self.invalidate_if_same(conn.id).await;
                let fresh = self
                    .get_connection()
                    .await
                    .map_err(|error| UpstreamSendError {
                        error,
                        conn_id: None,
                    })?;
                let mut fresh_send_req = fresh.send_req.clone();
                let s = fresh_send_req
                    .send_request(http::Request::from_parts(parts, ()))
                    .await
                    .map_err(|e| UpstreamSendError {
                        error: UpstreamError::from(e),
                        conn_id: Some(fresh.id),
                    })?;
                conn = fresh;
                s
            }
        };

        let conn_id = conn.id;

        if !body.is_empty() {
            stream
                .send_data(body)
                .await
                .map_err(|e| UpstreamSendError {
                    error: UpstreamError::from(e),
                    conn_id: Some(conn_id),
                })?;
        }
        stream.finish().await.map_err(|e| UpstreamSendError {
            error: UpstreamError::from(e),
            conn_id: Some(conn_id),
        })?;

        let resp = stream
            .recv_response()
            .await
            .map_err(|e| UpstreamSendError {
                error: UpstreamError::from(e),
                conn_id: Some(conn_id),
            })?;
        let (resp_parts, ()) = resp.into_parts();

        Ok(UpstreamResponse {
            status: resp_parts.status,
            headers: resp_parts.headers,
            version: resp_parts.version,
            body: BodyStream::new_h3(stream, conn.last_goaway, conn_id),
            conn_id,
        })
    }

    pub async fn prewarm(&self) -> Result<(), UpstreamError> {
        self.get_connection().await.map(|_| ())
    }
}

#[derive(Clone)]
pub enum UpstreamClient {
    H2(H2Client),
    H3(H3Client),
}

impl UpstreamClient {
    pub fn current_target(&self) -> &Target {
        match self {
            Self::H2(c) => c.current_target(),
            Self::H3(c) => c.current_target(),
        }
    }

    #[allow(dead_code)]
    pub async fn invalidate_connection(&self) {
        match self {
            Self::H2(c) => c.invalidate_connection().await,
            Self::H3(c) => c.invalidate_connection().await,
        }
    }

    pub async fn invalidate_if_same(&self, conn_id: u64) {
        match self {
            Self::H2(c) => c.invalidate_if_same(conn_id).await,
            Self::H3(c) => c.invalidate_if_same(conn_id).await,
        }
    }

    /// Connection-level invalidation is only correct for faults that affect the
    /// whole connection (GOAWAY, protocol error, connect failure, TTFT wedge).
    /// Stream-scoped resets must go through here instead: on H3 they leave the
    /// shared QUIC connection healthy, and tearing it down would abort every
    /// other response multiplexed on it.
    // caller wiring in main.rs's stream-reset arms lands in the dispatch slice
    #[allow(dead_code)]
    pub async fn invalidate_stream_if_same(&self, conn_id: u64) {
        match self {
            Self::H2(c) => c.invalidate_stream_if_same(conn_id).await,
            Self::H3(c) => c.invalidate_stream_if_same(conn_id).await,
        }
    }

    pub async fn send_stream(
        &self,
        req: http::Request<Bytes>,
    ) -> Result<UpstreamResponse, UpstreamSendError> {
        match self {
            Self::H2(c) => c.send_stream(req).await,
            Self::H3(c) => c.send_stream(req).await,
        }
    }

    pub async fn prewarm(&self) -> Result<(), UpstreamError> {
        match self {
            Self::H2(c) => c.prewarm().await,
            Self::H3(c) => c.prewarm().await,
        }
    }

    #[allow(dead_code)]
    pub fn is_h3(&self) -> bool {
        matches!(self, Self::H3(_))
    }

    pub fn transport_name(&self) -> &'static str {
        match self {
            Self::H2(_) => "HTTP/2",
            Self::H3(_) => "HTTP/3",
        }
    }
}

/// Keepalive PING loop for one pooled h2 connection: sends an opaque PING every
/// `interval`, waits up to PONG_TIMEOUT for the ACK.
///
/// - Healthy: no log (noise).
/// - Connection closed: stop silently — get_connection's poll_ready check
///   already reconnects lazily on the next request.
/// - PONG timeout (socket open, h2 wedged): set `wedge_flag` so get_connection
///   drops the pooled connection on the next request instead of reusing it.
async fn keepalive_loop(mut ping: h2::PingPong, interval: Duration, wedge_flag: Arc<AtomicBool>) {
    // PING frames carry exactly 8 bytes (h2 frame::ping::Payload = [u8; 8]) and
    // the peer's ACK echoes them; `Ping::opaque()` uses h2's fixed user payload.
    // A healthy relay answers within an RTT, so 15s is generous headroom.
    const PONG_TIMEOUT: Duration = Duration::from_secs(15);
    loop {
        tokio::time::sleep(interval).await;
        match tokio::time::timeout(PONG_TIMEOUT, ping.ping(h2::Ping::opaque())).await {
            Ok(Ok(_pong)) => {}
            Ok(Err(_e)) => break, // connection closed; poll_ready owns the reconnect
            Err(_) => {
                wedge_flag.store(true, Ordering::Release);
                crate::log(
                    "Upstream h2 keepalive: PING unanswered (connection wedged). Pool invalidated; next request reconnects.",
                    None,
                );
                break;
            }
        }
    }
}

/// Configure TCP keepalive on an upstream socket to preserve stateful NAT/firewall mappings
/// during extended model reasoning pauses (15s idle, 5s interval).
pub fn configure_tcp_keepalive(stream: &tokio::net::TcpStream) -> std::io::Result<()> {
    socket2::SockRef::from(stream).set_tcp_keepalive(
        &socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(15))
            .with_interval(Duration::from_secs(5))
            .with_retries(4),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_configure_tcp_keepalive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_fut = tokio::net::TcpStream::connect(addr);
        let server_fut = listener.accept();

        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        let client_stream = client_res.unwrap();
        let (server_stream, _) = server_res.unwrap();

        assert!(configure_tcp_keepalive(&client_stream).is_ok());
        assert!(configure_tcp_keepalive(&server_stream).is_ok());
    }

    #[test]
    fn test_configure_windows_udp_socket() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(configure_windows_udp_socket(&sock).is_ok());
    }

    #[test]
    fn test_h3_error_mapping_refused_vs_cancelled() {
        let err_rejected = UpstreamError::H3StreamReset { error_code: 0x010b };
        assert!(err_rejected.is_refused_or_rejected());
        assert!(!err_rejected.is_cancelled());

        let err_cancelled = UpstreamError::H3StreamReset { error_code: 0x010c };
        assert!(err_cancelled.is_cancelled());
        assert!(!err_cancelled.is_refused_or_rejected());

        let err_h2_refused = UpstreamError::H2StreamReset { error_code: 7 };
        assert!(err_h2_refused.is_refused_or_rejected());

        let err_h2_cancel = UpstreamError::H2StreamReset { error_code: 8 };
        assert!(err_h2_cancel.is_cancelled());
    }

    #[test]
    fn test_h3_error_mapping_excessive_load() {
        let err_load_reset = UpstreamError::H3StreamReset { error_code: 0x0107 };
        assert!(err_load_reset.is_enhance_your_calm());

        let err_load_goaway = UpstreamError::H3GoAway { error_code: 0x0107 };
        assert!(err_load_goaway.is_enhance_your_calm());

        let err_h2_calm = UpstreamError::H2GoAway { error_code: 11 };
        assert!(err_h2_calm.is_enhance_your_calm());
    }

    #[test]
    fn test_h3_error_mapping_goaway_clean() {
        let err_clean = UpstreamError::H3GoAway { error_code: 0x0100 };
        assert!(err_clean.is_goaway_clean());

        let err_zero = UpstreamError::H3GoAway { error_code: 0 };
        assert!(err_zero.is_goaway_clean());

        let err_h2_clean = UpstreamError::H2GoAway { error_code: 0 };
        assert!(err_h2_clean.is_goaway_clean());

        let err_other = UpstreamError::H3GoAway { error_code: 0x0102 };
        assert!(!err_other.is_goaway_clean());
    }

    #[tokio::test]
    async fn test_h3_client_new_and_target_rotation() {
        let client = H3Client::new("https://127.0.0.1:19000/v1,https://127.0.0.1:19001/v1", Duration::from_secs(5), true).unwrap();
        assert_eq!(client.current_target().port, 19000);
        let next = client.rotate_target();
        assert!(next.contains("19001"));
        assert_eq!(client.current_target().port, 19001);
    }

    #[test]
    fn test_h3_address_family_matching_logic() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
        let addrs = [
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
        ];

        let is_ipv4 = true;
        let matched = addrs.iter().find(|a| if is_ipv4 { a.is_ipv4() } else { a.is_ipv6() });
        assert!(matched.unwrap().is_ipv4());

        let is_ipv4 = false;
        let matched_v6 = addrs.iter().find(|a| if is_ipv4 { a.is_ipv4() } else { a.is_ipv6() });
        assert!(matched_v6.unwrap().is_ipv6());
    }

    #[test]
    fn test_upstream_error_display_formatting() {
        let h3_reset = UpstreamError::H3StreamReset { error_code: 0x010b };
        assert_eq!(format!("{h3_reset}"), "H3StreamReset(error_code=0x10b)");

        let h3_goaway = UpstreamError::H3GoAway { error_code: 0x0100 };
        assert_eq!(format!("{h3_goaway}"), "H3GoAway(error_code=0x100)");

        let h3_proto = UpstreamError::H3Protocol("malformed header".into());
        assert_eq!(format!("{h3_proto}"), "H3Protocol: malformed header");
    }

    #[test]
    fn test_udp_socket_buffer_tuning() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let sock_ref = socket2::SockRef::from(&sock);
        assert!(sock_ref.set_send_buffer_size(1024 * 1024).is_ok());
        assert!(sock_ref.set_recv_buffer_size(1024 * 1024).is_ok());
    }

    #[tokio::test]
    async fn test_h3_client_ipv6_bind_selection() {
        let client_v6 = H3Client::new("https://[::1]:19000/v1", Duration::from_secs(5), true).unwrap();
        assert_eq!(client_v6.current_target().port, 19000);
        let local = client_v6.endpoint.local_addr().unwrap();
        assert!(local.is_ipv6());
        assert_eq!(client_v6.current_target().sni_host(), "::1");
        assert_eq!(client_v6.current_target().host, "[::1]");
        let addr = std::net::SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 19000);
        let res = client_v6.endpoint.connect_with(
            client_v6.quinn_client_config.clone(),
            addr,
            client_v6.current_target().sni_host(),
        );
        assert!(res.is_ok(), "connect_with failed: {:?}", res.err());
    }

    const TEST_CERT_DER: &[u8] = &[
        48, 130, 1, 27, 48, 129, 206, 160, 3, 2, 1, 2, 2, 20, 116, 98, 92, 9, 104, 190, 98, 219,
        60, 55, 199, 208, 38, 114, 71, 150, 183, 246, 7, 190, 48, 5, 6, 3, 43, 101, 112, 48, 20,
        49, 18, 48, 16, 6, 3, 85, 4, 3, 12, 9, 108, 111, 99, 97, 108, 104, 111, 115, 116, 48, 32,
        23, 13, 50, 54, 49, 49, 49, 49, 49, 48, 50, 54, 51, 53, 90, 24, 15, 50, 49, 50, 54, 49, 48,
        49, 57, 49, 48, 50, 54, 51, 53, 90, 48, 20, 49, 18, 48, 16, 6, 3, 85, 4, 3, 12, 9, 108,
        111, 99, 97, 108, 104, 111, 115, 116, 48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, 113,
        236, 20, 105, 137, 92, 31, 111, 121, 211, 82, 20, 101, 35, 216, 26, 136, 98, 110, 105, 183,
        145, 68, 227, 15, 37, 55, 112, 1, 27, 14, 135, 163, 48, 48, 46, 48, 44, 6, 3, 85, 29, 17,
        4, 37, 48, 35, 130, 9, 108, 111, 99, 97, 108, 104, 111, 115, 116, 135, 4, 127, 0, 0, 1,
        135, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 48, 5, 6, 3, 43, 101, 112, 3, 65,
        0, 7, 179, 194, 83, 15, 41, 104, 55, 2, 81, 117, 63, 18, 39, 218, 120, 48, 208, 48, 154,
        100, 231, 90, 52, 213, 9, 115, 134, 72, 132, 16, 88, 48, 105, 117, 114, 67, 122, 253, 45,
        7, 112, 137, 254, 239, 112, 203, 107, 2, 222, 25, 169, 190, 147, 85, 152, 241, 168, 37,
        145, 14, 98, 107, 7,
    ];

    const TEST_KEY_DER: &[u8] = &[
        48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 199, 101, 224, 93, 108, 5, 185,
        254, 180, 105, 224, 249, 78, 56, 223, 200, 134, 175, 79, 0, 120, 140, 129, 89, 51, 160,
        221, 13, 6, 206, 226, 23,
    ];

    async fn spawn_mock_h3_server(
        bind_addr: std::net::SocketAddr,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let cert = rustls::pki_types::CertificateDer::from(TEST_CERT_DER);
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(TEST_KEY_DER.into());
        let mut tls_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        tls_cfg.alpn_protocols = vec![b"h3".to_vec()];
        let quic_srv_cfg = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_cfg).unwrap(),
        ));
        let endpoint = quinn::Endpoint::server(quic_srv_cfg, bind_addr).unwrap();
        let local_addr = endpoint.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    let mut h3_conn =
                        match h3::server::Connection::new(h3_quinn::Connection::new(conn)).await {
                            Ok(c) => c,
                            Err(_) => return,
                        };
                    while let Ok(Some(resolver)) = h3_conn.accept().await {
                        tokio::spawn(async move {
                            if let Ok((_req, mut stream)) = resolver.resolve_request().await {
                                while let Ok(Some(_)) = stream.recv_data().await {}
                                let resp = http::Response::builder()
                                    .status(200)
                                    .body(())
                                    .unwrap();
                                if stream.send_response(resp).await.is_ok() {
                                    let _ = stream.send_data(Bytes::from_static(b"h3-ok")).await;
                                    let _ = stream.finish().await;
                                }
                            }
                        });
                    }
                });
            }
        });
        (local_addr, handle)
    }

    #[test]
    fn test_error_classification_stream_scoped_vs_connection_closing() {
        // Stream resets are confined to their own request stream: H3_REQUEST_REJECTED,
        // H3_REQUEST_CANCELLED and H3_EXCESSIVE_LOAD all keep the QUIC connection pooled.
        for code in [0x010b_u64, 0x010c, 0x0107] {
            let e = UpstreamError::H3StreamReset { error_code: code };
            assert!(e.is_stream_scoped(), "H3 reset {code:#x} must be stream-scoped");
            assert!(
                !e.is_connection_closing(),
                "H3 reset {code:#x} must not force a reconnect"
            );
        }
        for code in [7_u32, 8, 2] {
            let e = UpstreamError::H2StreamReset { error_code: code };
            assert!(e.is_stream_scoped());
            assert!(!e.is_connection_closing());
        }

        // Genuine connection-level faults still tear the pool down.
        let conn_errors = [
            UpstreamError::Connect(std::io::Error::other("boom")),
            UpstreamError::Timeout,
            UpstreamError::H2Protocol("bad frame".into()),
            UpstreamError::H3Protocol("bad frame".into()),
            UpstreamError::H2GoAway { error_code: 0 },
            UpstreamError::H3GoAway { error_code: 0x0100 },
            UpstreamError::H3GoAway { error_code: 0x0107 },
        ];
        for e in conn_errors {
            assert!(e.is_connection_closing(), "{e} must force a reconnect");
            assert!(!e.is_stream_scoped(), "{e} must not take the stream path");
        }

        // HeaderTooBig is permanent: never retried, never mistaken for a dead conn.
        let too_big = UpstreamError::HeaderTooBig {
            actual_size: 100_000,
            max_size: 16_384,
        };
        assert!(!too_big.is_connection_closing());
        assert!(!too_big.is_stream_scoped());
        let msg = too_big.to_string();
        assert!(msg.contains("100000") && msg.contains("16384"), "{msg}");
    }

    #[test]
    fn test_h3_handshake_budget_has_floor_and_stays_bounded() {
        // DNS + QUIC ate the whole budget: the h3 control handshake still gets a window.
        assert_eq!(
            h3_handshake_budget(Duration::ZERO, Duration::from_secs(30)),
            H3_HANDSHAKE_FLOOR
        );
        // Leftover above the floor is used as-is (no artificial extension).
        assert_eq!(
            h3_handshake_budget(Duration::from_secs(10), Duration::from_secs(30)),
            Duration::from_secs(10)
        );
        // A deliberately tiny connect_timeout is not inflated past itself.
        assert_eq!(
            h3_handshake_budget(Duration::ZERO, Duration::from_millis(800)),
            Duration::from_millis(800)
        );
    }

    /// Mock h3 server that sends the response head + a first data chunk, then
    /// holds the tail until a permit is released. Used to prove that a
    /// stream-scoped invalidation does not kill a response already in flight.
    async fn spawn_mock_h3_holding_server(
        bind_addr: std::net::SocketAddr,
        gate: Arc<tokio::sync::Semaphore>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let cert = rustls::pki_types::CertificateDer::from(TEST_CERT_DER);
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(TEST_KEY_DER.into());
        let mut tls_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        tls_cfg.alpn_protocols = vec![b"h3".to_vec()];
        let quic_srv_cfg = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_cfg).unwrap(),
        ));
        let endpoint = quinn::Endpoint::server(quic_srv_cfg, bind_addr).unwrap();
        let local_addr = endpoint.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let gate = gate.clone();
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    let mut h3_conn =
                        match h3::server::Connection::new(h3_quinn::Connection::new(conn)).await {
                            Ok(c) => c,
                            Err(_) => return,
                        };
                    while let Ok(Some(resolver)) = h3_conn.accept().await {
                        let gate = gate.clone();
                        tokio::spawn(async move {
                            if let Ok((_req, mut stream)) = resolver.resolve_request().await {
                                while let Ok(Some(_)) = stream.recv_data().await {}
                                let resp =
                                    http::Response::builder().status(200).body(()).unwrap();
                                if stream.send_response(resp).await.is_ok() {
                                    let _ = stream.send_data(Bytes::from_static(b"h3-part1")).await;
                                    let _ = gate.acquire().await;
                                    let _ = stream.send_data(Bytes::from_static(b"h3-part2")).await;
                                    let _ = stream.finish().await;
                                }
                            }
                        });
                    }
                });
            }
        });
        (local_addr, handle)
    }

    #[tokio::test]
    async fn test_h3_stream_invalidation_preserves_concurrent_response() {
        use futures_util::StreamExt;

        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let (addr, srv) =
            spawn_mock_h3_holding_server("127.0.0.1:0".parse().unwrap(), gate.clone()).await;
        let client = H3Client::new(
            &format!("https://127.0.0.1:{}/v1", addr.port()),
            Duration::from_secs(5),
            true,
        )
        .unwrap();
        let mk_req = || {
            http::Request::builder()
                .method(http::Method::POST)
                .uri(format!(
                    "https://127.0.0.1:{}/v1/chat/completions",
                    addr.port()
                ))
                .body(Bytes::from_static(b"{}"))
                .unwrap()
        };

        let mut held = client.send_stream(mk_req()).await.unwrap();
        let conn_id = held.conn_id;
        let first = held.body.next().await.unwrap().unwrap();
        assert_eq!(first.as_ref(), b"h3-part1");

        // A stream-scoped failure (H3_REQUEST_REJECTED etc.) for this very
        // connection must leave the pooled QUIC connection alone: the response
        // already in flight on it has to survive.
        client.invalidate_stream_if_same(conn_id).await;
        gate.add_permits(1);

        let mut rest = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_secs(5), held.body.next()).await {
                Ok(Some(Ok(chunk))) => rest.extend_from_slice(&chunk),
                Ok(Some(Err(e))) => panic!("in-flight response destroyed by stream invalidation: {e}"),
                Ok(None) => break,
                Err(_) => panic!("in-flight response stalled: the QUIC connection was closed"),
            }
        }
        assert_eq!(rest.as_slice(), b"h3-part2");

        // The connection is still pooled and reused, not redialed.
        let follow = client.send_stream(mk_req()).await.unwrap();
        assert_eq!(follow.conn_id, conn_id, "stream invalidation must not evict the pool");
        srv.abort();

        // Control: the connection-level path (kept for genuine connection
        // faults) really does tear the pool down and kill in-flight responses,
        // which is exactly why stream resets must not use it.
        let gate2 = Arc::new(tokio::sync::Semaphore::new(0));
        let (addr2, srv2) =
            spawn_mock_h3_holding_server("127.0.0.1:0".parse().unwrap(), gate2.clone()).await;
        let client2 = H3Client::new(
            &format!("https://127.0.0.1:{}/v1", addr2.port()),
            Duration::from_secs(5),
            true,
        )
        .unwrap();
        let mut held2 = client2
            .send_stream(
                http::Request::builder()
                    .method(http::Method::POST)
                    .uri(format!(
                        "https://127.0.0.1:{}/v1/chat/completions",
                        addr2.port()
                    ))
                    .body(Bytes::from_static(b"{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let id2 = held2.conn_id;
        let _ = held2.body.next().await.unwrap().unwrap();
        client2.invalidate_if_same(id2).await;
        gate2.add_permits(1);
        let mut dead = false;
        loop {
            match tokio::time::timeout(Duration::from_secs(5), held2.body.next()).await {
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(_))) | Err(_) => {
                    dead = true;
                    break;
                }
                Ok(None) => break,
            }
        }
        assert!(dead, "connection-level invalidation must abort the in-flight stream");
        srv2.abort();
    }

    #[tokio::test]
    async fn test_h2_invalidate_if_same_preserves_newer_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv_task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut conn = match h2::server::handshake(tcp).await {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    while let Some(Ok((req, mut respond))) = conn.accept().await {
                        let mut body = req.into_body();
                        while let Some(Ok(frame)) = body.data().await {
                            let _ = body.flow_control().release_capacity(frame.len());
                        }
                        let resp = http::Response::builder().status(200).body(()).unwrap();
                        if let Ok(mut send) = respond.send_response(resp, false) {
                            let _ = send.send_data(Bytes::from_static(b"h2-ok"), true);
                        }
                    }
                });
            }
        });

        let client = H2Client::new(
            &format!("http://{addr}/v1"),
            Duration::from_secs(5),
            Duration::from_secs(0),
            true,
        )
        .unwrap();

        let mk_req = || {
            http::Request::builder()
                .method(http::Method::POST)
                .uri(format!("http://{addr}/v1/chat/completions"))
                .body(Bytes::from_static(b"{}"))
                .unwrap()
        };

        let r1 = client.send_stream(mk_req()).await.unwrap();
        let id1 = r1.conn_id;
        assert_eq!(r1.body.read_full_limited(1024).await.unwrap().as_ref(), b"h2-ok");

        // Stale/wrong id must NOT evict active connection
        client.invalidate_if_same(id1 + 999).await;
        let r2 = client.send_stream(mk_req()).await.unwrap();
        assert_eq!(r2.conn_id, id1);
        let _ = r2.body.read_full_limited(1024).await.unwrap();

        // Exact id evicts -> next request opens new connection
        client.invalidate_if_same(id1).await;
        let r3 = client.send_stream(mk_req()).await.unwrap();
        let id2 = r3.conn_id;
        assert!(id2 > id1);
        let _ = r3.body.read_full_limited(1024).await.unwrap();

        // Stale id1 must NOT evict id2
        client.invalidate_if_same(id1).await;
        let r4 = client.send_stream(mk_req()).await.unwrap();
        assert_eq!(r4.conn_id, id2);
        let _ = r4.body.read_full_limited(1024).await.unwrap();

        srv_task.abort();
    }

    #[tokio::test]
    async fn test_h3_real_loopback_ipv4_ipv6_localhost_and_invalidate_if_same() {
        // 1. Real IPv4 loopback + invalidate_if_same
        let (v4_addr, v4_srv) = spawn_mock_h3_server("127.0.0.1:0".parse().unwrap()).await;
        let client_v4 = H3Client::new(
            &format!("https://127.0.0.1:{}/v1", v4_addr.port()),
            Duration::from_secs(5),
            true,
        )
        .unwrap();
        let mk_req_v4 = || {
            http::Request::builder()
                .method(http::Method::POST)
                .uri(format!(
                    "https://127.0.0.1:{}/v1/chat/completions",
                    v4_addr.port()
                ))
                .body(Bytes::from_static(b"{}"))
                .unwrap()
        };
        let r1 = client_v4.send_stream(mk_req_v4()).await.unwrap();
        let id1 = r1.conn_id;
        assert_eq!(r1.body.read_full_limited(1024).await.unwrap().as_ref(), b"h3-ok");

        client_v4.invalidate_if_same(id1 + 999).await;
        let r2 = client_v4.send_stream(mk_req_v4()).await.unwrap();
        assert_eq!(r2.conn_id, id1);
        let _ = r2.body.read_full_limited(1024).await.unwrap();

        client_v4.invalidate_if_same(id1).await;
        let r3 = client_v4.send_stream(mk_req_v4()).await.unwrap();
        assert!(r3.conn_id > id1);
        assert_eq!(r3.body.read_full_limited(1024).await.unwrap().as_ref(), b"h3-ok");
        v4_srv.abort();

        // 2. Real IPv6 loopback
        let (v6_addr, v6_srv) = spawn_mock_h3_server("[::1]:0".parse().unwrap()).await;
        let client_v6 = H3Client::new(
            &format!("https://[::1]:{}/v1", v6_addr.port()),
            Duration::from_secs(5),
            true,
        )
        .unwrap();
        let req_v6 = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "https://[::1]:{}/v1/chat/completions",
                v6_addr.port()
            ))
            .body(Bytes::from_static(b"{}"))
            .unwrap();
        let r_v6 = client_v6.send_stream(req_v6).await.unwrap();
        assert_eq!(r_v6.body.read_full_limited(1024).await.unwrap().as_ref(), b"h3-ok");
        v6_srv.abort();

        // 3. Hostname "localhost" against IPv4 server
        let (lh_addr, lh_srv) = spawn_mock_h3_server("127.0.0.1:0".parse().unwrap()).await;
        let client_lh = H3Client::new(
            &format!("https://localhost:{}/v1", lh_addr.port()),
            Duration::from_secs(5),
            true,
        )
        .unwrap();
        let req_lh = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "https://localhost:{}/v1/chat/completions",
                lh_addr.port()
            ))
            .body(Bytes::from_static(b"{}"))
            .unwrap();
        let r_lh = client_lh.send_stream(req_lh).await.unwrap();
        assert_eq!(r_lh.body.read_full_limited(1024).await.unwrap().as_ref(), b"h3-ok");
        lh_srv.abort();

        // 4. Hostname "localhost" against IPv6-only server (exercises alt_endpoint family fallback)
        let (lh6_addr, lh6_srv) = spawn_mock_h3_server("[::1]:0".parse().unwrap()).await;
        let client_lh6 = H3Client::new(
            &format!("https://localhost:{}/v1", lh6_addr.port()),
            Duration::from_millis(800),
            true,
        )
        .unwrap();
        let req_lh6 = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "https://localhost:{}/v1/chat/completions",
                lh6_addr.port()
            ))
            .body(Bytes::from_static(b"{}"))
            .unwrap();
        let r_lh6 = client_lh6.send_stream(req_lh6).await.unwrap();
        assert_eq!(r_lh6.body.read_full_limited(1024).await.unwrap().as_ref(), b"h3-ok");
        lh6_srv.abort();
    }
}



