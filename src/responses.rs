//! Native stateless Responses. Wire items stay opaque; this module only applies
//! endpoint policy and observes lifecycle/usage without rebuilding response bytes.
use super::*;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ApiMode {
    #[default]
    ChatCompletions,
    Responses,
}

impl ApiMode {
    pub(crate) fn parse(value: Option<&Value>) -> Result<Self, &'static str> {
        match value {
            None => Ok(Self::ChatCompletions),
            Some(Value::String(s)) if s == "chat_completions" => Ok(Self::ChatCompletions),
            Some(Value::String(s)) if s == "responses" => Ok(Self::Responses),
            _ => Err("'api_mode' must be 'chat_completions' or 'responses'"),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ChatCompletions => "chat_completions",
            Self::Responses => "responses",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Operation {
    #[default]
    Chat,
    Create,
    Compact,
    InputTokens,
}

impl Operation {
    pub(crate) fn from_path(path: &str) -> Self {
        match path {
            "/v1/responses" | "/responses" => Self::Create,
            "/v1/responses/compact" | "/responses/compact" => Self::Compact,
            "/v1/responses/input_tokens" | "/responses/input_tokens" => Self::InputTokens,
            _ => Self::Chat,
        }
    }

    pub(crate) fn native(self) -> bool {
        self != Self::Chat
    }

    fn uri(self, target: &upstream::Target) -> http::Uri {
        match self {
            Self::Chat => target.chat_uri.clone(),
            Self::Create => target.responses_uri.clone(),
            Self::Compact => target.compact_uri.clone(),
            Self::InputTokens => target.input_tokens_uri.clone(),
        }
    }
}

#[derive(Default)]
pub(crate) struct RequestOptions {
    pub(crate) operation: Operation,
    query: Option<String>,
    pub(crate) headers: HeaderMap,
}

impl RequestOptions {
    pub(crate) fn capture(request: &Request) -> Self {
        let operation = Operation::from_path(request.uri().path());
        if !operation.native() {
            return Self::default();
        }
        let nominated: HashSet<String> = request
            .headers()
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(|v| v.trim().to_ascii_lowercase())
            .collect();
        let mut headers = HeaderMap::new();
        for (name, value) in request.headers() {
            if !matches!(
                name.as_str(),
                "host"
                    | "authorization"
                    | "proxy-authorization"
                    | "proxy-authenticate"
                    | "x-api-key"
                    | "api-key"
                    | "cookie"
                    | "content-length"
                    | "content-type"
                    | "content-encoding"
                    | "accept"
                    | "accept-encoding"
                    | "connection"
                    | "transfer-encoding"
                    | "keep-alive"
                    | "te"
                    | "trailer"
                    | "upgrade"
            ) && !nominated.contains(name.as_str())
            {
                headers.append(name.clone(), value.clone());
            }
        }
        Self {
            operation,
            query: request.uri().query().map(str::to_owned),
            headers,
        }
    }

    pub(crate) fn uri(&self, target: &upstream::Target) -> Result<http::Uri, String> {
        let uri = self.operation.uri(target);
        let Some(query) = &self.query else {
            return Ok(uri);
        };
        let mut parts = uri.clone().into_parts();
        parts.path_and_query = Some(
            format!("{}?{}", uri.path(), query)
                .parse()
                .map_err(|e: http::uri::InvalidUri| e.to_string())?,
        );
        http::Uri::from_parts(parts).map_err(|e| e.to_string())
    }
}

fn raw(value: Value) -> Box<RawValue> {
    RawValue::from_string(value.to_string()).expect("serialized JSON is valid")
}

fn local_error(state: &AppState, status: StatusCode, message: &str) -> Response {
    state.stats.error_count.fetch_add(1, Ordering::Relaxed);
    make_error_response(status, message)
}

fn object_field(
    map: &BTreeMap<String, Box<RawValue>>,
    key: &str,
) -> Result<serde_json::Map<String, Value>, String> {
    match map.get(key) {
        None => Ok(serde_json::Map::new()),
        Some(v) if v.get().trim() == "null" => Ok(serde_json::Map::new()),
        Some(v) => serde_json::from_str::<serde_json::Map<String, Value>>(v.get())
            .map_err(|_| format!("'{key}' must be a JSON object")),
    }
}

fn reject_stored_context(map: &BTreeMap<String, Box<RawValue>>) -> Result<(), String> {
    for key in ["previous_response_id", "conversation"] {
        if map.get(key).is_some_and(|v| v.get().trim() != "null") {
            return Err(format!("Stateless Responses does not support '{key}'; replay the complete input history instead"));
        }
    }
    if map
        .get("background")
        .is_some_and(|v| v.get().trim() != "false" && v.get().trim() != "null")
    {
        return Err("Stateless Responses does not support background execution".into());
    }
    if let Some(input) = map.get("input") {
        if input.get().trim_start().starts_with('[') {
            let items: Vec<&RawValue> =
                serde_json::from_str(input.get()).map_err(|e| format!("Invalid input: {e}"))?;
            for item in items {
                if let Ok(fields) = serde_json::from_str::<BTreeMap<String, &RawValue>>(item.get())
                {
                    let explicit_reference = fields
                        .get("type")
                        .and_then(|v| serde_json::from_str::<String>(v.get()).ok())
                        .as_deref()
                        == Some("item_reference");
                    // ItemReference.type is optional. A complete implicit
                    // message may also have an id, so retain role/content items.
                    let implicit_reference = fields.contains_key("id")
                        && fields.get("type").is_none_or(|v| v.get().trim() == "null")
                        && !(fields.contains_key("role") && fields.contains_key("content"));
                    if explicit_reference || implicit_reference {
                        return Err("Stateless Responses cannot resolve item_reference; send the complete item".into());
                    }
                }
            }
        }
    }
    Ok(())
}

fn prepare_payload(
    mut map: BTreeMap<String, Box<RawValue>>,
    config: &Config,
    operation: Operation,
) -> Result<(UpstreamPayload, bool), String> {
    let stream = map.get("stream").is_some_and(|v| v.get().trim() == "true");
    if operation != Operation::Create && stream {
        return Err("This Responses operation does not support streaming".into());
    }
    // Validate the caller before injection as well: never erase an unsupported
    // ID continuation and accidentally generate without its promised context.
    reject_stored_context(&map)?;
    let mut reasoning = if operation == Operation::Create {
        object_field(&map, "reasoning")?
    } else {
        serde_json::Map::new()
    };
    let mut include = Vec::new();
    if operation == Operation::Create {
        for source in [map.get("include"), config.inject_raw.get("include")]
            .into_iter()
            .flatten()
        {
            if source.get().trim() == "null" {
                continue;
            }
            let values: Vec<String> = serde_json::from_str(source.get())
                .map_err(|_| "'include' must be an array of strings")?;
            for value in values {
                if !include.contains(&value) {
                    include.push(value);
                }
            }
        }
        if let Some(injected) = config
            .inject
            .get("reasoning")
            .filter(|value| !value.is_null())
        {
            let fields = injected
                .as_object()
                .ok_or("Injected 'reasoning' must be a JSON object")?;
            reasoning.extend(fields.clone());
        }
    }
    // Auxiliary endpoints have different schemas. Their requests are already
    // native and do not inherit generation-only preset parameters.
    if operation == Operation::Create {
        for (key, value) in &config.inject_raw {
            if !matches!(
                key.as_str(),
                "input" | "model" | "stream" | "store" | "include" | "reasoning"
            ) {
                map.insert(key.clone(), value.clone());
            }
        }
        reasoning.insert("summary".into(), json!("detailed"));
        include.push("reasoning.encrypted_content".into());
        let mut seen = HashSet::new();
        include.retain(|value| seen.insert(value.clone()));
        map.insert("reasoning".into(), raw(Value::Object(reasoning)));
        map.insert("include".into(), raw(json!(include)));
        map.insert("store".into(), raw(json!(false)));
    }
    reject_stored_context(&map)?;
    map.insert("model".into(), config.models_raw[0].clone());
    Ok((
        UpstreamPayload {
            map,
            spliced_messages: None,
        },
        stream,
    ))
}

pub(crate) async fn raw_path(
    state: Arc<AppState>,
    bytes: Bytes,
    req_id: String,
    t_start: Instant,
    active_guard: ActiveRequestGuard,
    options: RequestOptions,
) -> Response {
    let raw_len = bytes.len();
    let map: BTreeMap<String, Box<RawValue>> = match serde_json::from_slice(&bytes) {
        Ok(map) => map,
        Err(e) => {
            return local_error(
                &state,
                StatusCode::BAD_REQUEST,
                &format!("Request body must be a JSON object: {e}"),
            )
        }
    };
    drop(bytes);
    let model = map
        .get("model")
        .and_then(|v| serde_json::from_str::<String>(v.get()).ok())
        .unwrap_or_default();
    let preset = state.slots[select_slot_index(&model, state.slots.len())].clone();
    if preset.config.api_mode != ApiMode::Responses {
        return local_error(&state, StatusCode::BAD_REQUEST, "Selected preset uses chat_completions; configure api_mode: responses for native Responses requests");
    }
    let (payload, stream) = match prepare_payload(map, &preset.config, options.operation) {
        Ok(result) => result,
        Err(message) => return local_error(&state, StatusCode::BAD_REQUEST, &message),
    };
    let permit = match state.semaphore.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return local_error(&state, StatusCode::SERVICE_UNAVAILABLE, &e.to_string()),
    };
    log(
        &format!(
            "POST native Responses {:?} size={:.1}KB stream={stream}",
            options.operation,
            raw_len as f64 / 1024.0
        ),
        Some(&req_id),
    );
    dispatch_upstream(
        state,
        preset,
        payload,
        raw_len,
        stream,
        req_id,
        t_start,
        permit,
        active_guard,
        options,
    )
    .await
}

pub(crate) fn stored_operation(path: &str, method: &Method) -> bool {
    let path = path
        .strip_prefix("/v1/responses/")
        .or_else(|| path.strip_prefix("/responses/"));
    let Some(path) = path else {
        return false;
    };
    let parts: Vec<_> = path.split('/').collect();
    (parts.len() == 1 && (*method == Method::GET || *method == Method::DELETE))
        || (parts.len() == 2
            && ((parts[1] == "input_items" && *method == Method::GET)
                || (parts[1] == "cancel" && *method == Method::POST)))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Terminal {
    #[default]
    Pending = 0,
    Completed = 1,
    Failed = 2,
}

#[derive(Default, serde::Deserialize)]
struct TokenDetails {
    cached_tokens: Option<u64>,
    reasoning_tokens: Option<u64>,
}

#[derive(serde::Deserialize)]
struct NativeUsage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    #[serde(default)]
    input_tokens_details: Option<TokenDetails>,
    #[serde(default)]
    output_tokens_details: Option<TokenDetails>,
}

// Only observe metadata. In particular, deserialization skips the potentially
// multi-megabyte opaque output/encrypted-content fields without allocating them.
#[derive(serde::Deserialize)]
struct Metadata {
    #[serde(rename = "type")]
    kind: Option<String>,
    status: Option<String>,
    usage: Option<NativeUsage>,
    response: Option<Box<Metadata>>,
}

#[derive(Default)]
struct Observation {
    terminal: Terminal,
    usage: Option<UsageStats>,
    cached: u64,
    buffer: BytesMut,
    data: Vec<u8>,
    malformed: bool,
    skip_lf: bool,
}

impl Observation {
    fn value(&mut self, value: &Metadata, event: bool) {
        let body = if event {
            value.response.as_deref().unwrap_or(value)
        } else {
            value
        };
        let terminal = if event {
            value.kind.as_deref()
        } else {
            body.status.as_deref()
        };
        match terminal {
            Some("response.completed" | "completed") => self.terminal = Terminal::Completed,
            Some(
                "response.failed"
                | "response.incomplete"
                | "response.cancelled"
                | "error"
                | "failed"
                | "incomplete"
                | "cancelled",
            ) => self.terminal = Terminal::Failed,
            _ => {}
        }
        if let Some(usage) = &body.usage {
            self.usage = Some(UsageStats {
                prompt_tokens: usage.input_tokens,
                completion_tokens: usage.output_tokens,
                reasoning_tokens: usage
                    .output_tokens_details
                    .as_ref()
                    .and_then(|v| v.reasoning_tokens),
                completion_tokens_details: None,
            });
            self.cached = usage
                .input_tokens_details
                .as_ref()
                .and_then(|v| v.cached_tokens)
                .unwrap_or(0);
        }
    }

    fn feed(&mut self, mut chunk: &[u8], limit: usize) {
        if self.malformed {
            return;
        }
        while !chunk.is_empty() {
            // Bound unfinished lines and event data, not transport chunks:
            // one H2/H3 read can contain arbitrarily many complete events.
            let end = memchr::memchr2(b'\n', b'\r', chunk);
            let len = end.map_or(chunk.len(), |end| end + 1);
            if self.buffer.len().saturating_add(len) > limit {
                self.malformed = true;
                self.buffer.clear();
                self.data.clear();
                return;
            }
            self.buffer.extend_from_slice(&chunk[..len]);
            chunk = &chunk[len..];
            if end.is_none() {
                return;
            }
            let line = self.buffer.split_to(self.buffer.len());
            let terminator = line[line.len() - 1];
            let line = &line[..line.len() - 1];
            if self.skip_lf && line.is_empty() && terminator == b'\n' {
                self.skip_lf = false;
                continue;
            }
            self.skip_lf = terminator == b'\r';
            if line.is_empty() {
                if !self.data.is_empty() {
                    let data = std::mem::take(&mut self.data);
                    if let Ok(value) = serde_json::from_slice::<Metadata>(&data) {
                        self.value(&value, true);
                    }
                }
            } else if let Some(data) = line.strip_prefix(b"data:") {
                let data = data.strip_prefix(b" ").unwrap_or(data);
                if self.data.len().saturating_add(data.len()).saturating_add(1) > limit {
                    self.malformed = true;
                    self.data.clear();
                    return;
                }
                if !self.data.is_empty() {
                    self.data.push(b'\n');
                }
                self.data.extend_from_slice(data);
            }
        }
    }
}

struct NativeStreamGuard {
    state: Arc<AppState>,
    metrics: Arc<StreamMetrics>,
    terminal: Arc<AtomicU8>,
    req_id: String,
    ttft: f64,
    start: Instant,
    cached: Arc<AtomicU64>,
}

impl Drop for NativeStreamGuard {
    fn drop(&mut self) {
        let stats = &self.state.stats;
        let terminal = self.terminal.load(Ordering::Relaxed);
        if terminal == 1 {
            stats.success_count.fetch_add(1, Ordering::Relaxed);
        }
        if terminal == 2 {
            stats.error_count.fetch_add(1, Ordering::Relaxed);
        }
        stats.total_chunks.fetch_add(
            self.metrics.chunks.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        stats.total_bytes.fetch_add(
            self.metrics.bytes.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        let usage = UsageStats {
            prompt_tokens: Some(self.metrics.prompt_tokens.load(Ordering::Relaxed)),
            completion_tokens: Some(self.metrics.completion_tokens.load(Ordering::Relaxed)),
            reasoning_tokens: Some(self.metrics.reasoning_tokens.load(Ordering::Relaxed)),
            completion_tokens_details: None,
        };
        apply_usage_stats(stats, &usage, self.start.elapsed().as_secs_f64(), self.ttft);
        stats
            .total_tokens_cached
            .fetch_add(self.cached.load(Ordering::Relaxed), Ordering::Relaxed);
        log(
            &format!(
                "Responses stream end terminal={terminal} bytes={}",
                self.metrics.bytes.load(Ordering::Relaxed)
            ),
            Some(&self.req_id),
        );
    }
}

fn response_headers(headers: &HeaderMap, state: &AppState) -> HeaderMap {
    let mut result = HeaderMap::new();
    let nominated: HashSet<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|v| v.trim().to_ascii_lowercase())
        .collect();
    for (name, value) in headers {
        if (!state.stripped_headers.contains(name) || name == header::CONTENT_ENCODING)
            && !matches!(
                name.as_str(),
                "connection"
                    | "keep-alive"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailer"
                    | "upgrade"
                    | "transfer-encoding"
            )
            && !nominated.contains(name.as_str())
        {
            result.append(name.clone(), value.clone());
        }
    }
    apply_nocache_headers(&mut result);
    result
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn forward(
    status: StatusCode,
    headers: HeaderMap,
    mut upstream: BodyStream,
    state: Arc<AppState>,
    preset: Arc<PresetRuntime>,
    operation: Operation,
    stream: bool,
    req_id: String,
    ttft: f64,
    start: Instant,
    permit: OwnedSemaphorePermit,
    active_guard: ActiveRequestGuard,
) -> Response {
    if !status.is_success() {
        let _permit = permit;
        let _active_guard = active_guard;
        state.stats.error_count.fetch_add(1, Ordering::Relaxed);
        let body = match tokio::time::timeout(
            ERROR_BODY_TIMEOUT,
            upstream.read_full_limited_checked(ERROR_BODY_CAP),
        )
        .await
        {
            Ok(Ok((body, false))) => body,
            _ => {
                return make_error_response(
                    StatusCode::BAD_GATEWAY,
                    "Could not read bounded Responses upstream error body",
                )
            }
        };
        let mut response = Response::new(Body::from(body));
        *response.status_mut() = status;
        *response.headers_mut() = response_headers(&headers, &state);
        return response;
    }
    // Transport does not decompress. Negotiate identity explicitly and reject an
    // upstream that violates it, rather than mislabeling compressed bytes as SSE.
    if headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|v| v.as_bytes() != b"identity")
    {
        state.stats.error_count.fetch_add(1, Ordering::Relaxed);
        return make_error_response(StatusCode::BAD_GATEWAY, "Responses upstream returned an unsupported Content-Encoding despite Accept-Encoding: identity");
    }
    let response_headers = response_headers(&headers, &state);
    if !stream {
        let _permit = permit;
        let _active_guard = active_guard;
        let body = match tokio::time::timeout(
            preset.config.read_timeout,
            upstream.read_full_limited_checked(preset.config.max_body_bytes),
        )
        .await
        {
            Ok(Ok((body, false))) => body,
            Ok(Ok((_, true))) => {
                return local_error(
                    &state,
                    StatusCode::BAD_GATEWAY,
                    "Responses upstream body exceeded max_body_bytes",
                )
            }
            Ok(Err(e)) => {
                return local_error(
                    &state,
                    StatusCode::BAD_GATEWAY,
                    &format!("Responses body read failed: {e}"),
                )
            }
            Err(_) => {
                return local_error(
                    &state,
                    StatusCode::GATEWAY_TIMEOUT,
                    "Responses body read timed out",
                )
            }
        };
        let mut observation = Observation::default();
        if let Ok(value) = serde_json::from_slice::<Metadata>(&body) {
            observation.value(&value, false);
        }
        if operation == Operation::Create && observation.terminal == Terminal::Pending {
            state.stats.error_count.fetch_add(1, Ordering::Relaxed);
            return make_error_response(
                StatusCode::BAD_GATEWAY,
                "Responses upstream did not return a terminal response object",
            );
        }
        if observation.terminal == Terminal::Failed {
            state.stats.error_count.fetch_add(1, Ordering::Relaxed);
        } else {
            state.stats.success_count.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(usage) = &observation.usage {
            apply_usage_stats(&state.stats, usage, start.elapsed().as_secs_f64(), ttft);
        }
        state
            .stats
            .total_tokens_cached
            .fetch_add(observation.cached, Ordering::Relaxed);
        state
            .stats
            .total_bytes
            .fetch_add(body.len() as u64, Ordering::Relaxed);
        let mut response = Response::new(Body::from(body));
        *response.status_mut() = status;
        *response.headers_mut() = response_headers;
        return response;
    }
    let metrics = Arc::new(StreamMetrics::default());
    let terminal = Arc::new(AtomicU8::new(0));
    let cached = Arc::new(AtomicU64::new(0));
    let guard = NativeStreamGuard {
        state: state.clone(),
        metrics: metrics.clone(),
        terminal: terminal.clone(),
        cached: cached.clone(),
        req_id: req_id.clone(),
        ttft,
        start,
    };
    let body = stream! {
        let _permit = permit; let _active_guard = active_guard; let _guard = guard;
        let mut observation = Observation::default();
        loop {
            let chunk = match tokio::time::timeout(preset.config.read_timeout, upstream.next()).await {
                Ok(Some(Ok(chunk))) => chunk,
                Ok(None) => {
                    if observation.terminal == Terminal::Pending {
                        terminal.store(2, Ordering::Relaxed);
                        yield Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Responses stream ended before a terminal event"));
                    }
                    break;
                }
                Ok(Some(Err(e))) => {
                    let conn_id = upstream.conn_id();
                    if e.is_stream_scoped() { preset.client.invalidate_stream_if_same(conn_id).await; }
                    else { preset.client.invalidate_if_same(conn_id).await; }
                    terminal.store(2, Ordering::Relaxed);
                    yield Err(std::io::Error::other(format!("Responses stream failed: {e}"))); break;
                }
                Err(_) => { terminal.store(2, Ordering::Relaxed); yield Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Responses stream idle timeout")); break; }
            };
            observation.feed(&chunk, preset.config.max_body_bytes);
            if observation.malformed { terminal.store(2, Ordering::Relaxed); yield Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Responses SSE event exceeded max_body_bytes")); break; }
            metrics.chunks.fetch_add(1, Ordering::Relaxed); metrics.bytes.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            if let Some(usage) = &observation.usage { publish_sse_usage(usage, &metrics); }
            cached.store(observation.cached, Ordering::Relaxed);
            terminal.store(observation.terminal as u8, Ordering::Relaxed);
            yield Ok::<Bytes, std::io::Error>(chunk);
            if observation.terminal != Terminal::Pending { break; }
        }
    };
    let mut response = Response::new(Body::from_stream(body));
    *response.status_mut() = status;
    *response.headers_mut() = response_headers;
    response
}

#[cfg(test)]
mod acceptance;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Clone)]
    pub(super) struct Reply {
        pub(super) status: u16,
        pub(super) headers: Vec<(&'static str, &'static str)>,
        pub(super) chunks: Vec<Bytes>,
    }

    pub(super) struct Captured {
        pub(super) path: String,
        pub(super) headers: HeaderMap,
        pub(super) body: Vec<u8>,
    }

    pub(super) async fn server(reply: Reply) -> (std::net::SocketAddr, Arc<Mutex<Vec<Captured>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let records = captured.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let records = records.clone();
                let reply = reply.clone();
                tokio::spawn(async move {
                    let mut connection = h2::server::handshake(tcp).await.unwrap();
                    while let Some(Ok((request, mut respond))) = connection.accept().await {
                        let (parts, mut body) = request.into_parts();
                        let mut bytes = Vec::new();
                        while let Some(Ok(chunk)) = body.data().await {
                            body.flow_control().release_capacity(chunk.len()).unwrap();
                            bytes.extend_from_slice(&chunk);
                        }
                        records.lock().unwrap().push(Captured {
                            path: parts.uri.path_and_query().unwrap().to_string(),
                            headers: parts.headers,
                            body: bytes,
                        });
                        if reply.status == 0 {
                            connection.abrupt_shutdown(h2::Reason::PROTOCOL_ERROR);
                            return;
                        }
                        let mut response = http::Response::builder().status(reply.status);
                        for (key, value) in &reply.headers {
                            response = response.header(*key, *value);
                        }
                        let mut send = respond
                            .send_response(response.body(()).unwrap(), reply.chunks.is_empty())
                            .unwrap();
                        for (i, chunk) in reply.chunks.iter().enumerate() {
                            if send
                                .send_data(chunk.clone(), i + 1 == reply.chunks.len())
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                });
            }
        });
        (addr, captured)
    }

    pub(super) fn native_state(base: &str) -> Arc<AppState> {
        let mut state = crate::tests::make_test_app_state(base, true, 15);
        let slot = Arc::get_mut(&mut Arc::get_mut(&mut state).unwrap().slots[0]).unwrap();
        let config = Arc::get_mut(&mut slot.config).unwrap();
        config.api_mode = ApiMode::Responses;
        config.souffle_pout = true;
        config.prepend_raw = Some(r#"{"role":"system","content":"must not be injected"}"#.into());
        state
    }

    pub(super) fn request(path: &str, body: &str) -> Request {
        Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::USER_AGENT, "Hermes-local-verification")
            .header("openai-project", "project-local-fixture")
            .header(header::AUTHORIZATION, "Bearer caller-must-not-leak")
            .header(header::CONNECTION, "x-hop-fixture")
            .header("x-hop-fixture", "must-not-leak")
            .body(Body::from(body.to_owned()))
            .unwrap()
    }

    pub(super) fn completed() -> &'static str {
        "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":10,\"output_tokens\":4,\"input_tokens_details\":{\"cached_tokens\":6},\"output_tokens_details\":{\"reasoning_tokens\":3}}}}\n\n"
    }

    #[tokio::test]
    async fn native_create_policy_preserves_raw_items_and_merges_small_fields() {
        let state = native_state("http://127.0.0.1:1/v1");
        let config = &state.slots[0].config;
        let source = r#"{"input":[ {"type":"reasoning","encrypted_content":"OPAQUE\\\u0041","summary":[]}, {"role":"user","content":"hello"} ],"reasoning":{"effort":"high","context":"all_turns","summary":"auto"},"include":["message.output_text.logprobs","reasoning.encrypted_content"],"store":true,"stream":true,"custom":{"a":1}}"#;
        let map: BTreeMap<String, Box<RawValue>> = serde_json::from_str(source).unwrap();
        let original_input = map["input"].get().to_owned();
        let (prepared, stream) = prepare_payload(map, config, Operation::Create).unwrap();
        assert!(stream);
        assert_eq!(prepared.map["input"].get(), original_input);
        assert_eq!(prepared.map["custom"].get(), r#"{"a":1}"#);
        assert_eq!(prepared.map["store"].get(), "false");
        let reasoning: Value = serde_json::from_str(prepared.map["reasoning"].get()).unwrap();
        assert_eq!(
            reasoning,
            json!({"effort":"high","context":"all_turns","summary":"detailed"})
        );
        let include: Value = serde_json::from_str(prepared.map["include"].get()).unwrap();
        assert_eq!(
            include,
            json!([
                "message.output_text.logprobs",
                "reasoning.encrypted_content"
            ])
        );
        assert!(prepared.spliced_messages.is_none());
        assert!(!prepared.map.contains_key("messages"));
    }

    #[tokio::test]
    async fn auxiliary_operations_do_not_inherit_create_policy_or_preset_injection() {
        let mut state = native_state("http://127.0.0.1:1/v1");
        let cfg = Arc::get_mut(
            &mut Arc::get_mut(&mut Arc::get_mut(&mut state).unwrap().slots[0])
                .unwrap()
                .config,
        )
        .unwrap();
        cfg.inject = json!({"reasoning":{"effort":"max"},"include":["reasoning.encrypted_content"],"store":true}).as_object().unwrap().clone();
        cfg.inject_raw = inject_to_raw(&cfg.inject).unwrap();
        for operation in [Operation::Compact, Operation::InputTokens] {
            let map = serde_json::from_str(r#"{"input":"hello","instructions":"rules"}"#).unwrap();
            let (prepared, stream) = prepare_payload(map, cfg, operation).unwrap();
            assert!(!stream);
            for key in ["reasoning", "store", "include"] {
                assert!(!prepared.map.contains_key(key));
            }
            assert_eq!(prepared.map["instructions"].get(), "\"rules\"");
        }
    }

    #[tokio::test]
    async fn stored_context_and_id_only_items_are_rejected_not_erased() {
        let state = native_state("http://127.0.0.1:1/v1");
        for body in [
            r#"{"previous_response_id":"resp_old"}"#,
            r#"{"conversation":"conv_old"}"#,
            r#"{"background":true}"#,
            r#"{"input":[{"type":"item_reference","id":"rs_old"}]}"#,
        ] {
            assert!(prepare_payload(
                serde_json::from_str(body).unwrap(),
                &state.slots[0].config,
                Operation::Create
            )
            .is_err());
        }
        assert!(prepare_payload(
            serde_json::from_str(r#"{"previous_response_id":null,"input":"full history"}"#)
                .unwrap(),
            &state.slots[0].config,
            Operation::Create
        )
        .is_ok());
    }

    #[test]
    fn responses_preset_requires_explicit_stable_affinity() {
        let base = json!({"model":"gpt-fixture","key_env":"FIXTURE_KEY","upstream_bases":["https://example.test/v1"],"api_mode":"responses"});
        assert_eq!(
            Preset::from_value("native", &base).unwrap().api_mode,
            ApiMode::Responses
        );
        for (field, value) in [
            ("model", json!(["gpt-one", "gpt-two"])),
            ("key_env", json!(["KEY_ONE", "KEY_TWO"])),
            (
                "upstream_bases",
                json!(["https://one.test/v1", "https://two.test/v1"]),
            ),
        ] {
            let mut changed = base.clone();
            changed[field] = value;
            assert!(Preset::from_value("native", &changed)
                .unwrap_err()
                .contains("exactly one"));
        }
        let mut default = base;
        default.as_object_mut().unwrap().remove("api_mode");
        assert_eq!(
            Preset::from_value("chat", &default).unwrap().api_mode,
            ApiMode::ChatCompletions
        );
    }

    #[tokio::test]
    async fn native_endpoint_prefixes_and_queries_are_shared_by_h2_and_h3() {
        let base = "https://example.test/custom/v1/";
        let clients = [
            UpstreamClient::H2(
                H2Client::new(base, Duration::from_secs(1), Duration::ZERO, true).unwrap(),
            ),
            UpstreamClient::H3(H3Client::new(base, Duration::from_secs(1), true).unwrap()),
        ];
        for client in clients {
            for (incoming, expected) in [
                ("/v1/responses", "/custom/v1/responses"),
                ("/v1/responses/compact", "/custom/v1/responses/compact"),
                (
                    "/v1/responses/input_tokens",
                    "/custom/v1/responses/input_tokens",
                ),
            ] {
                let source = request(&format!("{incoming}?fixture=1"), "{}");
                let options = RequestOptions::capture(&source);
                let uri = options.uri(client.current_target()).unwrap();
                assert_eq!(uri.path(), expected);
                assert_eq!(uri.query(), Some("fixture=1"));
                assert_eq!(uri.host(), Some("example.test"));
            }
        }
    }

    #[test]
    fn native_sse_event_limit_is_independent_of_transport_chunks() {
        for ending in ["\n", "\r\n", "\r"] {
            let first = format!("data: {{\"type\":\"future.event\",{ending}data: \"text\":\"opaque\"}}{ending}{ending}");
            let last = format!("data: {{\"type\":\"response.completed\"}}{ending}{ending}");
            let source = format!("{first}{last}");
            let limit = first.len().max(last.len());
            for size in 1..=source.len() {
                let mut observation = Observation::default();
                for chunk in source.as_bytes().chunks(size) {
                    observation.feed(chunk, limit);
                }
                assert!(!observation.malformed, "ending {ending:?}, chunk size {size}");
                assert_eq!(observation.terminal, Terminal::Completed);
            }
            for size in 1..=source.len() {
                let mut observation = Observation::default();
                for chunk in source.as_bytes().chunks(size) {
                    observation.feed(chunk, 16);
                }
                assert!(observation.malformed);
            }
        }
    }

    #[tokio::test]
    async fn native_oversized_sse_chunk_is_rejected_before_forwarding() {
        let wire = format!(
            "data: {{\"type\":\"future.event\",\"text\":\"{}\"}}\n\n",
            "x".repeat(256)
        );
        let (addr, _) = server(Reply {
            status: 200,
            headers: vec![("content-type", "text/event-stream")],
            chunks: vec![Bytes::from(wire)],
        })
        .await;
        let mut state = native_state(&format!("http://{addr}/v1"));
        Arc::get_mut(
            &mut Arc::get_mut(&mut Arc::get_mut(&mut state).unwrap().slots[0])
                .unwrap()
                .config,
        )
        .unwrap()
        .max_body_bytes = 64;
        let response = handle_chat_completions(
            State(state.clone()),
            request("/v1/responses", r#"{"input":"hello","stream":true}"#),
        )
        .await;
        let mut body = response.into_body().into_data_stream();
        assert!(matches!(body.next().await, Some(Err(_))));
        drop(body);
        assert_eq!(state.stats.total_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(state.stats.error_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.stats.active_requests.load(Ordering::Relaxed), 0);
        assert_eq!(state.semaphore.available_permits(), 20);
    }

    #[tokio::test]
    async fn native_nullable_usage_details_preserve_terminal_and_wire_bytes() {
        let body = r#"{"status":"completed","output":[],"usage":{"input_tokens":10,"output_tokens":4,"input_tokens_details":null,"output_tokens_details":null}}"#;
        for stream in [false, true] {
            let wire = if stream {
                format!("data: {{\"type\":\"response.completed\",\"response\":{body}}}\n\n")
            } else {
                body.to_owned()
            };
            let (addr, _) = server(Reply {
                status: 200,
                headers: vec![(
                    "content-type",
                    if stream {
                        "text/event-stream"
                    } else {
                        "application/json"
                    },
                )],
                chunks: vec![Bytes::from(wire.clone())],
            })
            .await;
            let state = native_state(&format!("http://{addr}/v1"));
            let response = handle_chat_completions(
                State(state.clone()),
                request(
                    "/v1/responses",
                    &format!(r#"{{"input":"hello","stream":{stream}}}"#),
                ),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap(),
                wire
            );
            assert_eq!(state.stats.success_count.load(Ordering::Relaxed), 1);
            assert_eq!(state.stats.error_count.load(Ordering::Relaxed), 0);
            assert_eq!(state.stats.total_tokens_prompt.load(Ordering::Relaxed), 10);
            assert_eq!(
                state.stats.total_tokens_completion.load(Ordering::Relaxed),
                4
            );
        }
    }

    #[tokio::test]
    async fn native_implicit_item_references_are_rejected_before_dispatch() {
        let (addr, captured) = server(Reply {
            status: 200,
            headers: vec![("content-type", "application/json")],
            chunks: vec![Bytes::from_static(br#"{"status":"completed"}"#)],
        })
        .await;
        let state = native_state(&format!("http://{addr}/v1"));
        for body in [
            r#"{"input":[{"id":"msg_old"}]}"#,
            r#"{"input":[{"id":"rs_old","type":null}]}"#,
        ] {
            let response =
                handle_chat_completions(State(state.clone()), request("/v1/responses", body)).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
        }
        assert!(captured.lock().unwrap().is_empty());
        let source = r#"{"input":[ {"id":"msg_full","role":"assistant","content":"hello"}, {"id":"rs_full","type":"reasoning","encrypted_content":"OPAQUE","summary":[]} ]}"#;
        let map: BTreeMap<String, Box<RawValue>> = serde_json::from_str(source).unwrap();
        let original = map["input"].get().to_owned();
        let (payload, _) = prepare_payload(map, &state.slots[0].config, Operation::Create).unwrap();
        assert_eq!(payload.map["input"].get(), original);
    }

    #[test]
    fn native_sse_observer_handles_fragmentation_crlf_multiline_and_unknown_events() {
        for ending in ["\n", "\r\n", "\r"] {
            let source = format!("event: unknown{ending}data: {{\"type\":\"new.future.event\",\"text\":\"response.completed [DONE]\"}}{ending}{ending}event: response.completed{ending}data: {{\"type\":\"response.completed\",{ending}data: \"response\":{{\"status\":\"completed\",\"usage\":{{\"input_tokens\":9,\"output_tokens\":2}}}}}}{ending}{ending}");
            let mut observation = Observation::default();
            for byte in source.bytes() {
                observation.feed(&[byte], 4096);
            }
            assert_eq!(observation.terminal, Terminal::Completed);
            assert_eq!(observation.usage.unwrap().prompt_tokens, Some(9));
            assert!(!observation.malformed);
        }
        let mut observation = Observation::default();
        observation.feed(
            b"data: {\"type\":\"future\",\"text\":\"response.completed\"}\n\n",
            1024,
        );
        assert_eq!(observation.terminal, Terminal::Pending);
        observation.feed(&[b'x'; 1025], 1024);
        assert!(observation.malformed);
    }

    #[tokio::test]
    async fn native_errors_preserve_envelope_status_headers_and_are_never_retried() {
        for (status, code) in [
            (400, "invalid_encrypted_content"),
            (429, "rate_limit_exceeded"),
        ] {
            let body = format!(
                r#"{{"error":{{"message":"provider detail","type":"invalid_request_error","code":"{code}","param":"input[0].encrypted_content"}}}}"#
            );
            let (addr, captured) = server(Reply {
                status,
                headers: vec![
                    ("content-type", "application/json"),
                    ("retry-after", "17"),
                    ("x-request-id", "req-native-fixture"),
                ],
                chunks: vec![Bytes::from(body.clone())],
            })
            .await;
            let state = native_state(&format!("http://{addr}/v1"));
            let response = handle_chat_completions(
                State(state.clone()),
                request("/v1/responses", r#"{"input":"hello","stream":true}"#),
            )
            .await;
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(response.headers()["retry-after"], "17");
            assert_eq!(response.headers()["x-request-id"], "req-native-fixture");
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap(),
                body
            );
            assert_eq!(captured.lock().unwrap().len(), 1);
            assert_eq!(state.stats.success_count.load(Ordering::Relaxed), 0);
            assert_eq!(state.stats.error_count.load(Ordering::Relaxed), 1);
        }
    }

    #[tokio::test]
    async fn native_tool_only_stream_is_verbatim_and_does_not_run_chat_guards() {
        let unknown="event: future.event\ndata: {\"type\":\"future.event\",\"encrypted_content\":\"OPAQUE-consoleconsoleconsole\"}\n\n";
        let call = r#"{"id":"fc_fixture","type":"function_call","call_id":"call_fixture","name":"read_file","arguments":"{}","status":"completed"}"#;
        let tool_event = format!("event: response.output_item.done\ndata: {{\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{call}}}\n\n");
        let final_event = completed().replace("\"output\":[]", &format!("\"output\":[{call}]"));
        let wire = format!("{unknown}{tool_event}{final_event}");
        let chunks = wire
            .as_bytes()
            .chunks(7)
            .map(Bytes::copy_from_slice)
            .collect();
        let (addr, captured) = server(Reply {
            status: 200,
            headers: vec![
                ("content-type", "text/event-stream"),
                ("x-request-id", "req-native-fixture"),
            ],
            chunks,
        })
        .await;
        let state = native_state(&format!("http://{addr}/v1"));
        let response=handle_chat_completions(State(state.clone()),request("/v1/responses?fixture=1",r#"{"input":[ {"type":"reasoning","encrypted_content":"OPAQUE\\\u0041","summary":[]}, {"type":"function_call","call_id":"call_prior","name":"read_file","arguments":"{}"}, {"type":"function_call_output","call_id":"call_prior","output":"fixture result"} ],"stream":true}"#)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap(),
            wire
        );
        let records = captured.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].path, "/v1/responses?fixture=1");
        assert_eq!(
            records[0].headers[header::USER_AGENT],
            "Hermes-local-verification"
        );
        assert_eq!(
            records[0].headers["openai-project"],
            "project-local-fixture"
        );
        assert_eq!(records[0].headers[header::AUTHORIZATION], "Bearer sk-test");
        assert_eq!(records[0].headers[header::ACCEPT_ENCODING], "identity");
        assert!(!records[0].headers.contains_key("x-hop-fixture"));
        let body: Value = serde_json::from_slice(&records[0].body).unwrap();
        assert!(body.get("messages").is_none());
        assert_eq!(body["input"][0]["encrypted_content"], "OPAQUE\\A");
        assert_eq!(body["input"][1]["call_id"], "call_prior");
        assert_eq!(
            body["input"][2],
            json!({"type":"function_call_output","call_id":"call_prior","output":"fixture result"})
        );
        assert_eq!(body["store"], false);
        assert_eq!(state.stats.success_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.stats.error_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.stats.active_requests.load(Ordering::Relaxed), 0);
        assert_eq!(state.stats.total_tokens_prompt.load(Ordering::Relaxed), 10);
        assert_eq!(
            state.stats.total_tokens_completion.load(Ordering::Relaxed),
            4
        );
        assert_eq!(
            state.stats.total_tokens_reasoning.load(Ordering::Relaxed),
            3
        );
        assert_eq!(state.stats.total_tokens_cached.load(Ordering::Relaxed), 6);
    }

    #[tokio::test]
    async fn native_failed_incomplete_and_error_terminals_are_forwarded_but_not_successes() {
        for kind in ["response.failed", "response.incomplete", "error"] {
            let wire=format!("event: {kind}\ndata: {{\"type\":\"{kind}\",\"response\":{{\"status\":\"failed\"}}}}\n\n");
            let (addr, _) = server(Reply {
                status: 200,
                headers: vec![("content-type", "text/event-stream")],
                chunks: vec![Bytes::from(wire.clone())],
            })
            .await;
            let state = native_state(&format!("http://{addr}/v1"));
            let response = handle_chat_completions(
                State(state.clone()),
                request("/v1/responses", r#"{"input":"hello","stream":true}"#),
            )
            .await;
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap(),
                wire
            );
            assert_eq!(state.stats.success_count.load(Ordering::Relaxed), 0);
            assert_eq!(state.stats.error_count.load(Ordering::Relaxed), 1);
        }
    }

    #[tokio::test]
    async fn native_eof_without_a_complete_terminal_event_breaks_transfer() {
        for wire in [
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n",
            "data: {\"type\":\"response.completed\"}",
        ] {
            let (addr, _) = server(Reply {
                status: 200,
                headers: vec![("content-type", "text/event-stream")],
                chunks: vec![Bytes::copy_from_slice(wire.as_bytes())],
            })
            .await;
            let state = native_state(&format!("http://{addr}/v1"));
            let response = handle_chat_completions(
                State(state.clone()),
                request("/v1/responses", r#"{"input":"hello","stream":true}"#),
            )
            .await;
            assert!(axum::body::to_bytes(response.into_body(), 4096)
                .await
                .is_err());
            assert_eq!(state.stats.success_count.load(Ordering::Relaxed), 0);
            assert_eq!(state.stats.error_count.load(Ordering::Relaxed), 1);
            assert_eq!(state.stats.active_requests.load(Ordering::Relaxed), 0);
        }
    }

    #[tokio::test]
    async fn native_buffered_response_and_auxiliary_bodies_stay_opaque() {
        for (path, body) in [
            (
                "/responses",
                r#"{"status":"completed","output":[{"type":"reasoning","encrypted_content":"OPAQUE"}],"unknown":{"x":1}}"#,
            ),
            (
                "/responses/compact",
                r#"{"object":"response.compaction","output":[{"type":"compaction","encrypted_content":"OPAQUE"}]}"#,
            ),
            (
                "/responses/input_tokens",
                r#"{"object":"response.input_tokens","input_tokens":123}"#,
            ),
        ] {
            let (addr, captured) = server(Reply {
                status: 200,
                headers: vec![("content-type", "application/json")],
                chunks: vec![Bytes::from_static(body.as_bytes())],
            })
            .await;
            let state = native_state(&format!("http://{addr}/v1"));
            let response = handle_chat_completions(
                State(state.clone()),
                request(path, r#"{"input":"hello"}"#),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap(),
                body
            );
            let records = captured.lock().unwrap();
            assert_eq!(records[0].path, format!("/v1{path}"));
            let payload: Value = serde_json::from_slice(&records[0].body).unwrap();
            if path != "/responses" {
                assert!(payload.get("store").is_none());
                assert!(payload.get("include").is_none());
            }
        }
    }

    #[tokio::test]
    async fn native_mode_mismatch_and_stored_operations_are_explicit() {
        let chat = crate::tests::make_test_app_state("http://127.0.0.1:1/v1", false, 1);
        assert_eq!(
            handle_chat_completions(
                State(chat.clone()),
                request("/v1/responses", r#"{"input":"hello"}"#)
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let native = native_state("http://127.0.0.1:1/v1");
        assert_eq!(
            handle_chat_completions(
                State(native.clone()),
                request("/v1/chat/completions", r#"{"messages":[]}"#)
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(chat.stats.error_count.load(Ordering::Relaxed), 1);
        assert_eq!(native.stats.error_count.load(Ordering::Relaxed), 1);
        assert_eq!(chat.stats.active_requests.load(Ordering::Relaxed), 0);
        assert_eq!(native.stats.active_requests.load(Ordering::Relaxed), 0);
        let stored = Request::builder()
            .uri("/v1/responses/resp_old")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            handle_fallback(stored).await.status(),
            StatusCode::BAD_REQUEST
        );
        let unknown = Request::builder()
            .method(Method::POST)
            .uri("/v1/responses/typo")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            handle_fallback(unknown).await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn native_unpolled_body_drop_releases_permit_and_active_guard() {
        let (addr, _) = server(Reply {
            status: 200,
            headers: vec![("content-type", "text/event-stream")],
            chunks: vec![Bytes::from_static(completed().as_bytes())],
        })
        .await;
        let state = native_state(&format!("http://{addr}/v1"));
        let response = handle_chat_completions(
            State(state.clone()),
            request("/v1/responses", r#"{"input":"hello","stream":true}"#),
        )
        .await;
        assert_eq!(state.stats.active_requests.load(Ordering::Relaxed), 1);
        assert_eq!(state.semaphore.available_permits(), 19);
        drop(response);
        assert_eq!(state.stats.active_requests.load(Ordering::Relaxed), 0);
        assert_eq!(state.semaphore.available_permits(), 20);
        assert_eq!(state.stats.success_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn native_local_failures_count_once_and_response_headers_strip_hops() {
        for body in ["[]", r#"{"previous_response_id":"resp_old"}"#] {
            let state = native_state("http://127.0.0.1:1/v1");
            let response =
                handle_chat_completions(State(state.clone()), request("/v1/responses", body)).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(state.stats.error_count.load(Ordering::Relaxed), 1);
            assert_eq!(state.stats.active_requests.load(Ordering::Relaxed), 0);
        }
        let state = native_state("http://127.0.0.1:1/v1");
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, HeaderValue::from_static("x-hidden-hop"));
        headers.insert("x-hidden-hop", HeaderValue::from_static("remove"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=1"));
        headers.insert("trailer", HeaderValue::from_static("foo"));
        headers.insert("x-request-id", HeaderValue::from_static("keep"));
        headers.insert("retry-after", HeaderValue::from_static("12"));
        let filtered = response_headers(&headers, &state);
        for name in ["connection", "x-hidden-hop", "keep-alive", "trailer"] {
            assert!(!filtered.contains_key(name));
        }
        assert_eq!(filtered["x-request-id"], "keep");
        assert_eq!(filtered["retry-after"], "12");
    }

    #[tokio::test]
    async fn native_accepted_transport_failure_is_not_resubmitted() {
        let (addr, captured) = server(Reply {
            status: 0,
            headers: vec![],
            chunks: vec![],
        })
        .await;
        let state = native_state(&format!("http://{addr}/v1"));
        let response = handle_chat_completions(
            State(state.clone()),
            request("/v1/responses", r#"{"input":"hello","stream":true}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(captured.lock().unwrap().len(), 1);
        assert_eq!(state.stats.error_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.stats.active_requests.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn native_buffered_truncation_counts_one_failure() {
        let body = format!(
            r#"{{"status":"completed","output":[{{"type":"message","text":"{}"}}]}}"#,
            "x".repeat(256)
        );
        let (addr, _) = server(Reply {
            status: 200,
            headers: vec![("content-type", "application/json")],
            chunks: vec![Bytes::from(body)],
        })
        .await;
        let mut state = native_state(&format!("http://{addr}/v1"));
        Arc::get_mut(
            &mut Arc::get_mut(&mut Arc::get_mut(&mut state).unwrap().slots[0])
                .unwrap()
                .config,
        )
        .unwrap()
        .max_body_bytes = 64;
        let response = handle_chat_completions(
            State(state.clone()),
            request("/v1/responses", r#"{"input":"hello"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(state.stats.error_count.load(Ordering::Relaxed), 1);
        assert_eq!(state.stats.success_count.load(Ordering::Relaxed), 0);
        assert_eq!(state.stats.active_requests.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn native_nullable_reasoning_and_include_get_defaults_without_losing_input() {
        let state = native_state("http://127.0.0.1:1/v1");
        let source = r#"{"input":[ {"type":"reasoning","encrypted_content":"OPAQUE\\\u0041","summary":[]} ],"reasoning":null,"include":null}"#;
        let map: BTreeMap<String, Box<RawValue>> = serde_json::from_str(source).unwrap();
        let input = map["input"].get().to_owned();
        let (prepared, _) =
            prepare_payload(map, &state.slots[0].config, Operation::Create).unwrap();
        assert_eq!(prepared.map["input"].get(), input);
        assert_eq!(
            serde_json::from_str::<Value>(prepared.map["reasoning"].get()).unwrap(),
            json!({"summary":"detailed"})
        );
        assert_eq!(
            serde_json::from_str::<Value>(prepared.map["include"].get()).unwrap(),
            json!(["reasoning.encrypted_content"])
        );
        for invalid in [
            r#"{"input":"hello","reasoning":7}"#,
            r#"{"input":"hello","include":[7]}"#,
        ] {
            assert!(prepare_payload(
                serde_json::from_str(invalid).unwrap(),
                &state.slots[0].config,
                Operation::Create
            )
            .is_err());
        }
    }
}
