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

    pub(crate) fn native(self) -> bool { self != Self::Chat }

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
        if !operation.native() { return Self::default(); }
        let nominated: HashSet<String> = request.headers().get_all(header::CONNECTION).iter()
            .filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(','))
            .map(|v| v.trim().to_ascii_lowercase()).collect();
        let mut headers = HeaderMap::new();
        for (name, value) in request.headers() {
            if !matches!(name.as_str(), "host" | "authorization" | "proxy-authorization" |
                "proxy-authenticate" | "x-api-key" | "api-key" | "cookie" | "content-length" |
                "content-type" | "content-encoding" | "accept" | "accept-encoding" |
                "connection" | "transfer-encoding" | "keep-alive" | "te" | "trailer" | "upgrade")
                && !nominated.contains(name.as_str())
            { headers.append(name.clone(), value.clone()); }
        }
        Self { operation, query: request.uri().query().map(str::to_owned), headers }
    }

    pub(crate) fn uri(&self, target: &upstream::Target) -> Result<http::Uri, String> {
        let uri = self.operation.uri(target);
        let Some(query) = &self.query else { return Ok(uri); };
        let mut parts = uri.clone().into_parts();
        parts.path_and_query = Some(format!("{}?{}", uri.path(), query).parse()
            .map_err(|e: http::uri::InvalidUri| e.to_string())?);
        http::Uri::from_parts(parts).map_err(|e| e.to_string())
    }
}

fn raw(value: Value) -> Box<RawValue> {
    RawValue::from_string(value.to_string()).expect("serialized JSON is valid")
}

fn object_field(map: &BTreeMap<String, Box<RawValue>>, key: &str) -> Result<serde_json::Map<String, Value>, String> {
    match map.get(key) {
        None => Ok(serde_json::Map::new()),
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
    if map.get("background").is_some_and(|v| v.get().trim() != "false" && v.get().trim() != "null") {
        return Err("Stateless Responses does not support background execution".into());
    }
    if let Some(input) = map.get("input") {
        if input.get().trim_start().starts_with('[') {
            let items: Vec<&RawValue> = serde_json::from_str(input.get()).map_err(|e| format!("Invalid input: {e}"))?;
            for item in items {
                if let Ok(fields) = serde_json::from_str::<BTreeMap<String, &RawValue>>(item.get()) {
                    if fields.get("type").and_then(|v| serde_json::from_str::<String>(v.get()).ok()).as_deref() == Some("item_reference") {
                        return Err("Stateless Responses cannot resolve item_reference; send the complete item".into());
                    }
                }
            }
        }
    }
    Ok(())
}

fn prepare_payload(
    mut map: BTreeMap<String, Box<RawValue>>, config: &Config, operation: Operation,
) -> Result<(UpstreamPayload, bool), String> {
    let stream = map.get("stream").is_some_and(|v| v.get().trim() == "true");
    if operation != Operation::Create && stream {
        return Err("This Responses operation does not support streaming".into());
    }
    // Validate the caller before injection as well: never erase an unsupported
    // ID continuation and accidentally generate without its promised context.
    reject_stored_context(&map)?;
    let mut reasoning = if operation == Operation::Create { object_field(&map, "reasoning")? } else { serde_json::Map::new() };
    let mut include = Vec::new();
    if operation == Operation::Create {
        for source in [map.get("include"), config.inject_raw.get("include")] {
            if let Some(source) = source {
                let values: Vec<String> = serde_json::from_str(source.get()).map_err(|_| "'include' must be an array of strings")?;
                for value in values { if !include.contains(&value) { include.push(value); } }
            }
        }
        if let Some(injected) = config.inject.get("reasoning") {
            let fields = injected.as_object().ok_or("Injected 'reasoning' must be a JSON object")?;
            reasoning.extend(fields.clone());
        }
    }
    // Auxiliary endpoints have different schemas. Their requests are already
    // native and do not inherit generation-only preset parameters.
    if operation == Operation::Create {
        for (key, value) in &config.inject_raw {
            if !matches!(key.as_str(), "input" | "model" | "stream" | "store" | "include" | "reasoning") {
                map.insert(key.clone(), value.clone());
            }
        }
        reasoning.insert("summary".into(), json!("detailed"));
        include.push("reasoning.encrypted_content".into());
        include.dedup();
        let mut seen = HashSet::new();
        include.retain(|value| seen.insert(value.clone()));
        map.insert("reasoning".into(), raw(Value::Object(reasoning)));
        map.insert("include".into(), raw(json!(include)));
        map.insert("store".into(), raw(json!(false)));
    }
    reject_stored_context(&map)?;
    map.insert("model".into(), config.models_raw[0].clone());
    Ok((UpstreamPayload { map, spliced_messages: None }, stream))
}

pub(crate) async fn raw_path(
    state: Arc<AppState>, bytes: Bytes, req_id: String, t_start: Instant,
    active_guard: ActiveRequestGuard, options: RequestOptions,
) -> Response {
    let raw_len = bytes.len();
    let map: BTreeMap<String, Box<RawValue>> = match serde_json::from_slice(&bytes) {
        Ok(map) => map,
        Err(e) => return make_error_response(StatusCode::BAD_REQUEST, &format!("Request body must be a JSON object: {e}")),
    };
    drop(bytes);
    let model = map.get("model").and_then(|v| serde_json::from_str::<String>(v.get()).ok()).unwrap_or_default();
    let preset = state.slots[select_slot_index(&model, state.slots.len())].clone();
    if preset.config.api_mode != ApiMode::Responses {
        return make_error_response(StatusCode::BAD_REQUEST, "Selected preset uses chat_completions; configure api_mode: responses for native Responses requests");
    }
    let (payload, stream) = match prepare_payload(map, &preset.config, options.operation) {
        Ok(result) => result,
        Err(message) => return make_error_response(StatusCode::BAD_REQUEST, &message),
    };
    let permit = match state.semaphore.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return make_error_response(StatusCode::SERVICE_UNAVAILABLE, &e.to_string()),
    };
    log(&format!("POST native Responses {:?} size={:.1}KB stream={stream}", options.operation, raw_len as f64 / 1024.0), Some(&req_id));
    dispatch_upstream(state, preset, payload, raw_len, stream, req_id, t_start, permit, active_guard, options).await
}

pub(crate) fn stored_operation(path: &str, method: &Method) -> bool {
    let path = path.strip_prefix("/v1/responses/").or_else(|| path.strip_prefix("/responses/"));
    let Some(path) = path else { return false; };
    let parts: Vec<_> = path.split('/').collect();
    (parts.len() == 1 && (*method == Method::GET || *method == Method::DELETE))
        || (parts.len() == 2 && ((parts[1] == "input_items" && *method == Method::GET)
            || (parts[1] == "cancel" && *method == Method::POST)))
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Terminal { #[default] Pending = 0, Completed = 1, Failed = 2 }

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
    input_tokens_details: TokenDetails,
    #[serde(default)]
    output_tokens_details: TokenDetails,
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
}

impl Observation {
    fn value(&mut self, value: &Metadata, event: bool) {
        let body = if event { value.response.as_deref().unwrap_or(value) } else { value };
        let terminal = if event { value.kind.as_deref() } else { body.status.as_deref() };
        match terminal {
            Some("response.completed" | "completed") => self.terminal = Terminal::Completed,
            Some("response.failed" | "response.incomplete" | "response.cancelled" | "error" | "failed" | "incomplete" | "cancelled") => self.terminal = Terminal::Failed,
            _ => {}
        }
        if let Some(usage) = &body.usage {
            self.usage = Some(UsageStats {
                prompt_tokens: usage.input_tokens,
                completion_tokens: usage.output_tokens,
                reasoning_tokens: usage.output_tokens_details.reasoning_tokens,
                completion_tokens_details: None,
            });
            self.cached = usage.input_tokens_details.cached_tokens.unwrap_or(0);
        }
    }

    fn feed(&mut self, chunk: &[u8], limit: usize) {
        if self.malformed { return; }
        if self.buffer.len().saturating_add(chunk.len()) > limit {
            self.malformed = true; self.buffer.clear(); self.data.clear(); return;
        }
        self.buffer.extend_from_slice(chunk);
        while let Some(end) = memchr::memchr(b'\n', &self.buffer) {
            let line = self.buffer.split_to(end + 1);
            let line = line[..end].strip_suffix(b"\r").unwrap_or(&line[..end]);
            if line.is_empty() {
                if !self.data.is_empty() {
                    let data = std::mem::take(&mut self.data);
                    if let Ok(value) = serde_json::from_slice::<Metadata>(&data) { self.value(&value, true); }
                }
            } else if let Some(data) = line.strip_prefix(b"data:") {
                let data = data.strip_prefix(b" ").unwrap_or(data);
                if self.data.len().saturating_add(data.len()).saturating_add(1) > limit {
                    self.malformed = true; self.data.clear(); return;
                }
                if !self.data.is_empty() { self.data.push(b'\n'); }
                self.data.extend_from_slice(data);
            }
        }
    }
}

struct NativeStreamGuard {
    state: Arc<AppState>, metrics: Arc<StreamMetrics>, terminal: Arc<AtomicU8>,
    req_id: String, ttft: f64, start: Instant, cached: Arc<AtomicU64>,
}

impl Drop for NativeStreamGuard {
    fn drop(&mut self) {
        let stats = &self.state.stats;
        let terminal = self.terminal.load(Ordering::Relaxed);
        if terminal == 1 { stats.success_count.fetch_add(1, Ordering::Relaxed); }
        if terminal == 2 { stats.error_count.fetch_add(1, Ordering::Relaxed); }
        stats.total_chunks.fetch_add(self.metrics.chunks.load(Ordering::Relaxed), Ordering::Relaxed);
        stats.total_bytes.fetch_add(self.metrics.bytes.load(Ordering::Relaxed), Ordering::Relaxed);
        let usage = UsageStats { prompt_tokens: Some(self.metrics.prompt_tokens.load(Ordering::Relaxed)), completion_tokens: Some(self.metrics.completion_tokens.load(Ordering::Relaxed)), reasoning_tokens: Some(self.metrics.reasoning_tokens.load(Ordering::Relaxed)), completion_tokens_details: None };
        apply_usage_stats(stats, &usage, self.start.elapsed().as_secs_f64(), self.ttft);
        stats.total_tokens_cached.fetch_add(self.cached.load(Ordering::Relaxed), Ordering::Relaxed);
        log(&format!("Responses stream end terminal={terminal} bytes={}", self.metrics.bytes.load(Ordering::Relaxed)), Some(&self.req_id));
    }
}

fn response_headers(headers: &HeaderMap, state: &AppState) -> HeaderMap {
    let mut result = HeaderMap::new();
    for (name, value) in headers {
        if !state.stripped_headers.contains(name) || name == header::CONTENT_ENCODING { result.append(name.clone(), value.clone()); }
    }
    apply_nocache_headers(&mut result);
    result
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn forward(
    status: StatusCode, headers: HeaderMap, mut upstream: BodyStream,
    state: Arc<AppState>, preset: Arc<PresetRuntime>, operation: Operation,
    stream: bool, req_id: String, ttft: f64, start: Instant,
    permit: OwnedSemaphorePermit, active_guard: ActiveRequestGuard,
) -> Response {
    if !status.is_success() {
        let _permit = permit; let _active_guard = active_guard;
        state.stats.error_count.fetch_add(1, Ordering::Relaxed);
        let body = match tokio::time::timeout(ERROR_BODY_TIMEOUT, upstream.read_full_limited_checked(ERROR_BODY_CAP)).await {
            Ok(Ok((body, false))) => body,
            _ => return make_error_response(StatusCode::BAD_GATEWAY, "Could not read bounded Responses upstream error body"),
        };
        let mut response = Response::new(Body::from(body));
        *response.status_mut() = status;
        *response.headers_mut() = response_headers(&headers, &state);
        return response;
    }
    // Transport does not decompress. Negotiate identity explicitly and reject an
    // upstream that violates it, rather than mislabeling compressed bytes as SSE.
    if headers.get(header::CONTENT_ENCODING).is_some_and(|v| v.as_bytes() != b"identity") {
        state.stats.error_count.fetch_add(1, Ordering::Relaxed);
        return make_error_response(StatusCode::BAD_GATEWAY, "Responses upstream returned an unsupported Content-Encoding despite Accept-Encoding: identity");
    }
    let response_headers = response_headers(&headers, &state);
    if !stream {
        let _permit = permit; let _active_guard = active_guard;
        let body = match tokio::time::timeout(preset.config.read_timeout, upstream.read_full_limited_checked(preset.config.max_body_bytes)).await {
            Ok(Ok((body, false))) => body,
            Ok(Ok((_, true))) => return make_error_response(StatusCode::BAD_GATEWAY, "Responses upstream body exceeded max_body_bytes"),
            Ok(Err(e)) => return make_error_response(StatusCode::BAD_GATEWAY, &format!("Responses body read failed: {e}")),
            Err(_) => return make_error_response(StatusCode::GATEWAY_TIMEOUT, "Responses body read timed out"),
        };
        let mut observation = Observation::default();
        if let Ok(value) = serde_json::from_slice::<Metadata>(&body) { observation.value(&value, false); }
        if operation == Operation::Create && observation.terminal == Terminal::Pending {
            state.stats.error_count.fetch_add(1, Ordering::Relaxed);
            return make_error_response(StatusCode::BAD_GATEWAY, "Responses upstream did not return a terminal response object");
        }
        if observation.terminal == Terminal::Failed { state.stats.error_count.fetch_add(1, Ordering::Relaxed); }
        else { state.stats.success_count.fetch_add(1, Ordering::Relaxed); }
        if let Some(usage) = &observation.usage { apply_usage_stats(&state.stats, usage, start.elapsed().as_secs_f64(), ttft); }
        state.stats.total_tokens_cached.fetch_add(observation.cached, Ordering::Relaxed);
        state.stats.total_bytes.fetch_add(body.len() as u64, Ordering::Relaxed);
        let mut response = Response::new(Body::from(body)); *response.status_mut() = status; *response.headers_mut() = response_headers; return response;
    }
    let metrics = Arc::new(StreamMetrics::default());
    let terminal = Arc::new(AtomicU8::new(0));
    let cached = Arc::new(AtomicU64::new(0));
    let guard = NativeStreamGuard { state: state.clone(), metrics: metrics.clone(), terminal: terminal.clone(), cached: cached.clone(), req_id: req_id.clone(), ttft, start };
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
            metrics.chunks.fetch_add(1, Ordering::Relaxed); metrics.bytes.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            observation.feed(&chunk, preset.config.max_body_bytes);
            if let Some(usage) = &observation.usage { publish_sse_usage(usage, &metrics); }
            cached.store(observation.cached, Ordering::Relaxed);
            terminal.store(observation.terminal as u8, Ordering::Relaxed);
            yield Ok::<Bytes, std::io::Error>(chunk);
            if observation.malformed { terminal.store(2, Ordering::Relaxed); yield Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Responses SSE event exceeded max_body_bytes")); break; }
            if observation.terminal != Terminal::Pending { break; }
        }
    };
    let mut response = Response::new(Body::from_stream(body)); *response.status_mut() = status; *response.headers_mut() = response_headers; response
}
