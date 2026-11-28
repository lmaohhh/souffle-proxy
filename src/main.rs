//! Soufflé Proxy — Rust Edition
//! =====================================
//! High-performance native reverse proxy with:
//!   - Upstream Engine: HTTP/2 via hyper/h2 direct with ALPN
//!   - Local Server: Axum on http://127.0.0.1:8799
//!   - Model rewrite and parameter injection
//!   - Preserved Thinking mode injection (clear_thinking: false)
//!   - reasoning_content pass-through (upstream returns it natively)
//!   - Empty response peek guard (catches 0-token stop responses)
//!   - Degenerate-output guard (mid-stream & buffered verbatim repetition loop detector)
//!   - Exponential backoff with jitter (1s → 2s → 4s → 8s → 16s)
//!   - HTTP/2 stream reset & protocol error handling
//!   - Request UUID correlation logging & runtime statistics (/stats)
//!   - Concurrency semaphore & graceful shutdown

use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use async_stream::stream;
use axum::serve::ListenerExt;
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use serde_json::{json, value::RawValue, Value};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

mod responses;
mod upstream;
use upstream::{BodyStream, H2Client, H3Client, UpstreamClient, UpstreamError};

// ---------------------------------------------------------------------------
// Preset header metadata. Values are parsed once at startup and deliberately
// redacted from Debug output; only safe, non-framing metadata reaches dispatch.
// ---------------------------------------------------------------------------
#[derive(Clone, Default)]
struct HeaderOverrides {
    entries: Vec<(HeaderName, HeaderValue)>,
}

impl std::fmt::Debug for HeaderOverrides {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HeaderOverrides")
            .field("names", &self.entries.iter().map(|(name, _)| name).collect::<Vec<_>>())
            .field("count", &self.entries.len())
            .finish()
    }
}

impl HeaderOverrides {
    fn parse(preset_name: &str, value: &Value) -> Result<Self, String> {
        let object = value.as_object().ok_or_else(|| {
            format!("preset '{preset_name}' field 'extra_headers' must be a JSON object")
        })?;
        let mut entries = Vec::with_capacity(object.len());
        let mut seen = HashSet::with_capacity(object.len());
        for (configured_name, configured_value) in object {
            let name = HeaderName::from_bytes(configured_name.as_bytes()).map_err(|error| {
                format!(
                    "preset '{preset_name}' field 'extra_headers' has invalid HTTP name '{configured_name}': {error}"
                )
            })?;
            let normalized = name.as_str().to_ascii_lowercase();
            if !seen.insert(normalized) {
                return Err(format!(
                    "preset '{preset_name}' field 'extra_headers' has case-colliding header name '{configured_name}'"
                ));
            }
            if is_protected_extra_header(&name) {
                return Err(format!(
                    "preset '{preset_name}' field 'extra_headers' header '{configured_name}' is protected"
                ));
            }
            let configured_value = configured_value.as_str().ok_or_else(|| {
                format!(
                    "preset '{preset_name}' field 'extra_headers' value for '{configured_name}' must be a string"
                )
            })?;
            let value = HeaderValue::from_str(configured_value).map_err(|error| {
                format!(
                    "preset '{preset_name}' field 'extra_headers' value for '{configured_name}' is not a valid HTTP value: {error}"
                )
            })?;
            entries.push((name, value));
        }
        Ok(Self { entries })
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn apply(&self, headers: &mut HeaderMap) {
        for (name, value) in &self.entries {
            headers.insert(name.clone(), value.clone());
        }
    }
}

fn is_protected_extra_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "host"
            | "authorization"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "www-authenticate"
            | "x-api-key"
            | "api-key"
            | "cookie"
            | "set-cookie"
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
            | "cache-control"
            | "pragma"
            | "expires"
            | "cdn-cache-control"
            | "cloudflare-cdn-cache-control"
            | "x-accel-buffering"
    )
}

// ---------------------------------------------------------------------------
// Preset system: config.json beside the exe holds named presets. A preset is
// RAW PARAMS — the proxy is a dumb merger that splices `inject` verbatim into
// each request body (it knows no model families). Local docs/PRESETS.md is deliberately gitignored; see README.md.
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
struct Preset {
    name: String,
    api_mode: responses::ApiMode,
    /// One or more upstream model ids. When multiple are given, the proxy
    /// round-robins across them per request (e.g. ["deepseek-sol", "souffle-pro"]).
    /// In config.json the field is called `model` (or `models`) and accepts
    /// either a single string (`"deepseek-sol"`) or an array (`["deepseek-sol", "souffle-pro"]`).
    /// Optional alias fields (`alias`, `aliases`, `model_alias`, `model_aliases`)
    /// are also recognized and appended.
    models: Vec<String>,
    /// One or more env var names whose values are API keys.  When multiple are
    /// given the proxy round-robins across them per request.  In config.json the
    /// field is always called `key_env` and accepts either a single string
    /// (`"KEY"`) or an array (`["KEY_A", "KEY_B"]`).
    key_envs: Vec<String>,
    upstream_bases: Vec<String>,
    inject: serde_json::Map<String, Value>,
    /// `inject` pre-serialized to canonical raw JSON, one `Box<RawValue>` per key.
    inject_raw: BTreeMap<String, Box<RawValue>>,
    /// Each model id pre-serialized to a canonical raw JSON string literal,
    /// matching `models` element-for-element.
    models_raw: Vec<Box<RawValue>>,
    append_messages: Vec<Value>,
    append_raw: Option<String>,
    prepend_messages: Vec<Value>,
    prepend_raw: Option<String>,
    /// Opt-in verbatim repetition-loop guard (glued/spaced word or short-phrase
    /// runaways across reasoning_content and content). Absent or false = off.
    degen_repeat: bool,
    /// Whole-feature brotli opt-in, preset field (config.json `brotli`,
    /// owner ruling 2026-10-08 late night): true = compress outbound request
    /// bodies (`Content-Encoding: br`) with the automatic size-escalating
    /// quality curve; absent/false = NO compression at all (raw passthrough,
    /// the pre-brotli behavior). Deliberately a single yes/no line — the
    /// relay's upload throttle (13-14 KB/s owner-measured) is a property of
    /// throttled upstream deployments, not of the proxy in general.
    brotli: Option<bool>,
    /// Opt-in HTTP/3 (QUIC / RFC 9114) transport engine:
    /// true = use HTTP/3 client; false/absent = use HTTP/2 client (the default).
    pub http3: Option<bool>,
    /// In-Content CoT folding (`souffle_pout`): folds assistant reasoning_content
    /// into <think> tags in content. Absent/false = off; true = on.
    pub souffle_pout: bool,
    /// Safe, per-preset metadata overrides applied after all request headers are assembled.
    extra_headers: HeaderOverrides,
}

impl Preset {
    /// Parse one preset object. `name` is the map key (authoritative).
    fn from_value(name: &str, v: &Value) -> Result<Self, String> {
        let obj = v
            .as_object()
            .ok_or_else(|| format!("preset '{name}' is not a JSON object"))?;
        let api_mode = responses::ApiMode::parse(obj.get("api_mode"))
            .map_err(|message| format!("preset '{name}' {message}"))?;
        // model: accept a single string or an array of strings, plus optional alias(es).
        let mut models: Vec<String> = match obj.get("models").or_else(|| obj.get("model")) {
            Some(Value::String(s)) => {
                let s = s.trim().to_string();
                if s.is_empty() {
                    return Err(format!("preset '{name}' field 'model' is empty"));
                }
                vec![s]
            }
            Some(Value::Array(arr)) => {
                let v: Vec<String> = arr
                    .iter()
                    .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
                    .filter(|s| !s.is_empty())
                    .collect();
                if v.is_empty() {
                    return Err(format!(
                        "preset '{name}' field 'model' array has no valid strings"
                    ));
                }
                v
            }
            None => {
                return Err(format!(
                    "preset '{name}' missing string or array field 'model'"
                ))
            }
            Some(_) => {
                return Err(format!(
                    "preset '{name}' field 'model' must be a string or array of strings"
                ))
            }
        };

        // Also check optional alias / aliases / model_alias / model_aliases
        let alias_vals: Option<&Value> = obj
            .get("alias")
            .or_else(|| obj.get("aliases"))
            .or_else(|| obj.get("model_alias"))
            .or_else(|| obj.get("model_aliases"));

        if let Some(alias_val) = alias_vals {
            match alias_val {
                Value::String(s) => {
                    let s = s.trim().to_string();
                    if !s.is_empty() && !models.contains(&s) {
                        models.push(s);
                    }
                }
                Value::Array(arr) => {
                    for item in arr {
                        if let Some(s) = item.as_str().map(|s| s.trim().to_string()) {
                            if !s.is_empty() && !models.contains(&s) {
                                models.push(s);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        // key_env: accept a single string or an array of strings.
        let key_envs: Vec<String> = match obj.get("key_env") {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(arr)) => {
                let v: Vec<String> = arr
                    .iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect();
                if v.is_empty() {
                    return Err(format!("preset '{name}' field 'key_env' array is empty"));
                }
                v
            }
            None => vec!["SOUFFLE_API_KEY".to_string()],
            Some(_) => {
                return Err(format!(
                    "preset '{name}' field 'key_env' must be a string or array of strings"
                ))
            }
        };
        let upstream_bases: Vec<String> = match obj.get("upstream_bases") {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect(),
            Some(Value::String(s)) => vec![s.clone()],
            _ => Vec::new(),
        };
        if upstream_bases.is_empty() {
            return Err(format!("preset '{name}' has empty 'upstream_bases'"));
        }
        let inject = match obj.get("inject") {
            Some(Value::Object(m)) => m.clone(),
            None => serde_json::Map::new(),
            Some(_) => {
                return Err(format!(
                    "preset '{name}' field 'inject' must be a JSON object"
                ))
            }
        };
        let append_messages = match obj.get("append_messages") {
            Some(Value::Array(arr)) => arr.clone(),
            Some(_) => {
                return Err(format!(
                    "preset '{name}' field 'append_messages' must be a JSON array"
                ))
            }
            None => Vec::new(),
        };
        let prepend_messages = match obj.get("prepend_messages") {
            Some(Value::Array(arr)) => arr.clone(),
            Some(_) => {
                return Err(format!(
                    "preset '{name}' field 'prepend_messages' must be a JSON array"
                ))
            }
            None => Vec::new(),
        };
        // Repetition-loop guard opt-in: absent = false, boolean otherwise (no env override).
        let degen_repeat = match obj.get("degen_repeat") {
            Some(Value::Bool(b)) => *b,
            Some(_) => {
                return Err(format!(
                    "preset '{name}' field 'degen_repeat' must be a boolean"
                ))
            }
            None => false,
        };
        // Whole-feature brotli opt-in: absent = off (None), boolean otherwise.
        let brotli = match obj.get("brotli") {
            Some(Value::Bool(b)) => Some(*b),
            Some(_) => return Err(format!("preset '{name}' field 'brotli' must be a boolean")),
            None => None,
        };
        // In-Content CoT folding opt-in: absent = false, boolean otherwise.
        let souffle_pout = match obj.get("souffle_pout") {
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(format!("preset '{name}' field 'souffle_pout' must be a boolean")),
            None => false,
        };
        // Opt-in HTTP/3 (QUIC / RFC 9114) transport engine: absent = None, boolean otherwise.
        let http3 = match obj.get("http3") {
            Some(Value::Bool(b)) => Some(*b),
            Some(_) => return Err(format!("preset '{name}' field 'http3' must be a boolean")),
            None => None,
        };
        let extra_headers = match obj.get("extra_headers") {
            Some(value) => HeaderOverrides::parse(name, value)?,
            None => HeaderOverrides::default(),
        };
        let inject_raw = inject_to_raw(&inject)?;
        let models_raw = models_to_raw(&models)?;
        let prepend_raw = messages_to_raw_fragment(&prepend_messages)?;
        let append_raw = messages_to_raw_fragment(&append_messages)?;

        if api_mode == responses::ApiMode::Responses
            && (models.len() != 1 || key_envs.len() != 1 || upstream_bases.len() != 1)
        {
            return Err(format!("preset '{name}' api_mode responses requires exactly one model, key_env and upstream base to preserve encrypted-reasoning affinity"));
        }

        Ok(Preset {
            name: name.to_string(),
            api_mode,
            models,
            models_raw,
            key_envs,
            upstream_bases,
            inject,
            inject_raw,
            append_messages,
            append_raw,
            prepend_messages,
            prepend_raw,
            degen_repeat,
            brotli,
            http3,
            souffle_pout,
            extra_headers,
        })
    }
}

/// Pre-serialize an inject block to canonical raw JSON (owned-RawValue chat path).
/// Preserves key order (BTreeMap alphabetizes, matching serde_json::Map).
fn inject_to_raw(
    inject: &serde_json::Map<String, Value>,
) -> Result<BTreeMap<String, Box<RawValue>>, String> {
    let mut out = BTreeMap::new();
    for (k, v) in inject {
        let rv = RawValue::from_string(v.to_string())
            .map_err(|e| format!("pre-serialize inject key '{}': {}", k, e))?;
        out.insert(k.clone(), rv);
    }
    Ok(out)
}

/// Pre-serialize each model id to a canonical raw JSON string literal (owned-RawValue
/// chat path). Matches `models` element-for-element.
fn models_to_raw(models: &[String]) -> Result<Vec<Box<RawValue>>, String> {
    let mut out = Vec::with_capacity(models.len());
    for m in models {
        let rv = RawValue::from_string(serde_json::to_string(m).unwrap())
            .map_err(|e| format!("pre-serialize model '{}': {}", m, e))?;
        out.push(rv);
    }
    Ok(out)
}

/// Pre-serialize a list of message objects into a comma-delimited raw JSON fragment
/// (e.g. `{"role":"system",...},{"role":"system",...}`) without outer brackets.
fn messages_to_raw_fragment(messages: &[Value]) -> Result<Option<String>, String> {
    if messages.is_empty() {
        return Ok(None);
    }
    let mut parts = Vec::with_capacity(messages.len());
    for (idx, item) in messages.iter().enumerate() {
        let s = serde_json::to_string(item)
            .map_err(|e| format!("pre-serialize message [{}]: {}", idx, e))?;
        parts.push(s);
    }
    Ok(Some(parts.join(",")))
}

fn config_json_path() -> PathBuf {
    // Beside the exe; fall back to CWD if exe path is unavailable.
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("config.json")
}

/// (default preset name, all parsed presets) from config.json.
type ConfigData = (Option<String>, Vec<Preset>);

/// Load config.json. Ok(None) = file absent (first run); Err = present but broken
/// (fatal — never silently overwrite a user's config).
fn load_config_file() -> Result<Option<ConfigData>, String> {
    let path = config_json_path();
    if !path.is_file() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("read config.json: {e}"))?;
    let root: Value = serde_json::from_str(&text).map_err(|e| format!("parse config.json: {e}"))?;
    let default = root
        .get("default")
        .and_then(|d| d.as_str())
        .map(String::from);
    let presets_obj = root
        .get("presets")
        .and_then(|p| p.as_object())
        .ok_or_else(|| "config.json missing 'presets' object".to_string())?;
    let mut presets = Vec::new();
    for (k, v) in presets_obj {
        presets.push(Preset::from_value(k, v)?);
    }
    if presets.is_empty() {
        return Err("config.json 'presets' is empty".to_string());
    }
    Ok(Some((default, presets)))
}

/// Resolve the API secret from the process env first, then a .env beside the exe.
fn load_secret(key_env: &str) -> Option<String> {
    if let Ok(v) = env::var(key_env) {
        let t = v.trim().trim_matches('"').trim_matches('\'').to_string();
        if !t.is_empty() {
            return Some(t);
        }
    }
    let env_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(".env")))?;
    let file = File::open(&env_path).ok()?;
    let prefix = format!("{key_env}=");
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix(&prefix) {
            let val = val.trim().trim_matches('"').trim_matches('\'').to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

/// Static virtual models exposed via GET /v1/models and GET /models.
/// Hermes client profiles (e.g. `@miao`, `@default`) use virtual alias model names
/// (`deepseek-souffle`, `deepseek-sol`) for catalog discovery, validation, and CLI binding.
/// The proxy serves these stable virtual IDs here so client model discovery succeeds without
/// coupling to dynamic upstream model IDs. When the client sends chat completion requests,
/// upstream dispatch always forces the active preset's model (or round-robin model rotation),
/// overriding whatever model ID the client passed.
fn exposed_models() -> Value {
    json!([
        {"id": "deepseek-souffle", "object": "model", "owned_by": "soufflotheque"},
        {"id": "deepseek-sol", "object": "model", "owned_by": "soufflethecutest"},
    ])
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
struct Config {
    api_mode: responses::ApiMode,
    host: String,
    port: u16,
    // Comma-joined failover list fed to H2Client (sticky-failover on connect fail).
    upstream_bases: String,
    max_concurrency: usize,
    connect_timeout: Duration,
    read_timeout: Duration,
    /// Keepalive PING interval for the pooled h2 upstream connection
    /// (SOUFFLE_KEEPALIVE_EXPIRY, default 60s, 0 = keepalive disabled).
    /// Cloudflare's client-facing h2 idle limit is 400s, so overnight idle
    /// always kills the connection; a PING every interval keeps NAT/firewall
    /// mappings alive and lets a wedged connection be detected without waiting
    /// for the next request.
    keepalive_expiry: Duration,
    max_retry: usize,
    /// Opt-in verbatim repetition-loop guard (glued/spaced word or short-phrase
    /// runaways across reasoning_content and content). Preset opt-in only.
    degen_repeat: bool,
    /// Cap on any single buffered body: the client request body, and upstream
    /// error/diagnostic bodies. A 1M-token chat request is ~4 MB of JSON, so the
    /// 64 MB default is generous headroom; the point is that it is FINITE.
    max_body_bytes: usize,
    /// Brotli compression of the OUTBOUND request body (upload-throttle
    /// mitigation, 2026-10-08). The box->relay uplink is the bottleneck
    /// (~4.7 KB/s measured: a 200KB body uploads ~43s, and with generation
    /// time on top the relay's Cloudflare edge hits its 100s proxy window ->
    /// 524). Verified against the live upstream with a direct probe: the relay
    /// decodes Content-Encoding: br request bodies correctly (HTTP 200,
    /// authentic conversation probe: 224376B -> 63507B wire, 28.3% at q9).
    brotli_enabled: bool,
    /// Encoder quality 0..=10 (SOUFFLE_BROTLI_LEVEL, default 9; <256KB is base, >=256KB escalates to q10 max;
    /// the encode runs on spawn_blocking so tokio workers never stall).
    brotli_level: i32,
    /// Bodies below this stay uncompressed (SOUFFLE_BROTLI_MIN, default 1KB).
    brotli_min_bytes: usize,
    /// Round-robin key pool.  Always contains at least one entry.
    api_keys: Vec<String>,
    auth_headers: Vec<HeaderValue>,
    // From the resolved preset:
    preset_name: String,
    models: Vec<String>,
    models_raw: Vec<Box<RawValue>>,
    inject: serde_json::Map<String, Value>,
    inject_raw: BTreeMap<String, Box<RawValue>>,
    append_messages: Vec<Value>,
    append_raw: Option<String>,
    prepend_messages: Vec<Value>,
    prepend_raw: Option<String>,
    /// In-Content CoT folding (`souffle_pout`): folds assistant reasoning_content
    /// into <think> tags in content. Absent/false = off; true = on.
    pub souffle_pout: bool,
    /// Opt-in HTTP/3 (QUIC / RFC 9114) transport engine:
    /// true = use HTTP/3 client; false = use HTTP/2 client.
    pub http3_enabled: bool,
    /// Safe, per-preset metadata overrides applied at the single late dispatch point.
    extra_headers: HeaderOverrides,
}

/// Timeout from an env var parsed as f64 seconds. Negative, non-finite, or
/// over-range values ("inf", "NaN", "-1", "1e999", "1e300" all parse as f64
/// but cannot convert to a Duration) would panic via from_secs_f64 — a
/// process kill under panic=abort, before the listener even exists — so they
/// exit with a fatal message naming the variable instead. Unset or unparseable
/// values keep the documented default.
fn env_timeout(name: &str, default_secs: f64) -> Duration {
    match env::var(name).ok().and_then(|t| t.parse::<f64>().ok()) {
        Some(v) if v.is_finite() && v >= 0.0 => {
            Duration::try_from_secs_f64(v).unwrap_or_else(|_| {
                eprintln!(
                    "[FATAL] {} is too large to represent as a Duration (got {})",
                    name, v
                );
                std::process::exit(1);
            })
        }
        Some(v) => {
            eprintln!(
                "[FATAL] {} must be a finite, non-negative number of seconds (got {})",
                name, v
            );
            std::process::exit(1);
        }
        None => Duration::from_secs_f64(default_secs),
    }
}

impl Config {
    /// Build the runtime config from a resolved preset. Host/port/timeouts stay
    /// env-tunable; model/inject/upstream/key come from the preset. Exits fatally
    /// if the preset's key_env secret cannot be resolved.
    fn from_preset(preset: &Preset) -> Self {
        let host = env::var("SOUFFLE_PROXY_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port = env::var("SOUFFLE_PROXY_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8799);
        let max_concurrency = env::var("SOUFFLE_MAX_CONCURRENCY")
            .ok()
            .and_then(|c| c.parse().ok())
            .filter(|&n| n >= 1)
            .unwrap_or(20);
        let connect_timeout = env_timeout("SOUFFLE_CONNECT_TIMEOUT", 30.0);
        if env::var("SOUFFLE_WRITE_TIMEOUT").is_ok() {
            log(
                "WARNING: SOUFFLE_WRITE_TIMEOUT is deprecated and ignored; upstream response/read timeouts use SOUFFLE_READ_TIMEOUT.",
                None,
            );
        }
        let read_timeout = env_timeout("SOUFFLE_READ_TIMEOUT", 600.0);
        let keepalive_expiry = env_timeout("SOUFFLE_KEEPALIVE_EXPIRY", 60.0);
        // Retry generosity: 15 attempts (1s->16s backoff), tunable via SOUFFLE_MAX_RETRY.
        let max_retry = env::var("SOUFFLE_MAX_RETRY")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&n| n >= 1)
            .unwrap_or(15);
        let max_body_bytes = env::var("SOUFFLE_MAX_BODY_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(64 * 1024 * 1024);
        // Outbound brotli (upload-throttle mitigation). OPT-IN per preset:
        // config.json `"brotli": true` on the preset (owner ruling 2026-10-08
        // late night — the throttle is a deployment property of throttled
        // upstream relays, not of the proxy in general). SOUFFLE_BROTLI=0
        // force-disables and =1 force-enables as an env override; unset =
        // the preset's choice.
        let brotli_enabled = match env::var("SOUFFLE_BROTLI").as_deref() {
            Ok("0") => false,
            Ok("1") => true,
            _ => preset.brotli.unwrap_or(false),
        };
        // In-Content CoT folding: SOUFFLE_POUT=1/true or 0/false env override;
        // unset = preset's choice.
        let souffle_pout = match env::var("SOUFFLE_POUT").as_deref() {
            Ok(v) if v == "1" || v.eq_ignore_ascii_case("true") => true,
            Ok(v) if v == "0" || v.eq_ignore_ascii_case("false") => false,
            _ => preset.souffle_pout,
        };
        // Opt-in HTTP/3 (QUIC / RFC 9114) transport engine:
        // SOUFFLE_HTTP3=1/true or 0/false env override; unset = preset's choice (default false).
        let http3_enabled = match env::var("SOUFFLE_HTTP3").as_deref() {
            Ok(v) if v == "1" || v.eq_ignore_ascii_case("true") => true,
            Ok(v) if v == "0" || v.eq_ignore_ascii_case("false") => false,
            _ => preset.http3.unwrap_or(false),
        };
        // Base quality 9. Powered by `mbrotli` with `fearless_simd` (AVX-512),
        // q9 encodes in ~20ms, q10 encodes 3MB in ~200ms (clamped to max q10),
        // delivering optimal compression ratio without upload stall.
        let brotli_level = env::var("SOUFFLE_BROTLI_LEVEL")
            .ok()
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(9)
            .clamp(0, 10);
        let brotli_min_bytes = env::var("SOUFFLE_BROTLI_MIN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024);
        // Repetition-loop guard: preset opt-in only (no env override).
        let degen_repeat = preset.degen_repeat;

        // Resolve every key_env; fatal if any is missing.
        let api_keys: Vec<String> = preset
            .key_envs
            .iter()
            .map(|env_name| {
                load_secret(env_name).unwrap_or_else(|| {
                    eprintln!(
                        "[FATAL] Secret env var '{}' (from preset '{}') not found in environment or .env beside the exe",
                        env_name, preset.name
                    );
                    std::process::exit(1);
                })
            })
            .collect();

        let auth_headers: Vec<HeaderValue> = api_keys
            .iter()
            .zip(&preset.key_envs)
            .map(|(k, env_name)| {
                HeaderValue::from_str(&format!("Bearer {k}")).unwrap_or_else(|e| {
                    eprintln!(
                        "[FATAL] Secret env var '{}' (from preset '{}') contains a character that is invalid in an HTTP header value: {}",
                        env_name, preset.name, e
                    );
                    std::process::exit(1);
                })
            })
            .collect();

        Config {
            api_mode: preset.api_mode,
            host,
            port,
            upstream_bases: preset.upstream_bases.join(","),
            max_concurrency,
            connect_timeout,
            read_timeout,
            keepalive_expiry,
            max_retry,
            max_body_bytes,
            brotli_enabled,
            brotli_level,
            brotli_min_bytes,
            degen_repeat,
            api_keys,
            auth_headers,
            preset_name: preset.name.clone(),
            models: preset.models.clone(),
            models_raw: preset.models_raw.clone(),
            inject: preset.inject.clone(),
            inject_raw: preset.inject_raw.clone(),
            append_messages: preset.append_messages.clone(),
            append_raw: preset.append_raw.clone(),
            prepend_messages: preset.prepend_messages.clone(),
            prepend_raw: preset.prepend_raw.clone(),
            souffle_pout,
            http3_enabled,
            extra_headers: preset.extra_headers.clone(),
        }
    }
}

/// Per-request log verbosity (owner request 2026-10-09: less console noise).
/// Normal mode (default) condenses the steady-state per-request lines: the
/// model rewrite folds into the POST line and the attempt-1 dispatch line is
/// suppressed. `SOUFFLE_LOG_LEVEL=verbose` restores the full line set.
/// Faults, retries (attempt >= 2), prepend/append notices and errors always
/// log regardless of mode.
fn log_verbose() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        env::var("SOUFFLE_LOG_LEVEL")
            .map(|v| v.eq_ignore_ascii_case("verbose"))
            .unwrap_or(false)
    })
}

/// Upstream statuses worth retrying. `retry-400` is a build-time opt-in for relays
/// that answer 400 on transient conditions; the default build treats 400 as final.
fn is_retryable_upstream_status(status: u16) -> bool {
    let base = status == 429
        || (500..=504).contains(&status)
        || status == 522
        || status == 524
        || status == 529;
    if cfg!(feature = "retry-400") {
        base || status == 400
    } else {
        base
    }
}

fn retry_delay(attempt: usize) -> Duration {
    let base = 1.0f64 * 2.0f64.powi(attempt as i32);
    let delay = base.min(16.0);
    let jitter_factor = 0.25 * (2.0 * fastrand::f64() - 1.0);
    let final_delay = (delay + delay * jitter_factor).max(0.05);
    Duration::from_secs_f64(final_delay)
}

// ---------------------------------------------------------------------------
// Logging — async stdout writer (SOTA hardening 2026-10-07).
//
// The old log() did chrono::Local::now + println! + flush INLINE on the tokio
// worker threads: a blocking console write on a worker stalls that worker's
// whole task set (3 workers = a third of the reactor), and Windows console
// writes cost ~95.6 µs/line (measured, rust-forum) vs ~6 s/GB via pipes
// (refterm FAQ). The per-request CPU-time profiling (GetProcessTimes) could
// never see this hazard: blocking wait is wall-clock, not CPU.
//
// Design: a dedicated OS writer thread owns stdout; workers only do a bounded
// try_send (lossy on overload — the documented tracing_appender shape). The
// timestamp formatting (chrono's per-call timezone lookup) happens on the
// writer thread. This preserves the stdout-only/no-disk invariant: it is a
// logging-architecture change, not a file sink.
// ---------------------------------------------------------------------------
static LOG_TX: OnceLock<tokio::sync::mpsc::Sender<String>> = OnceLock::new();
/// Bounded channel: 4096 lines is orders of magnitude beyond what a
/// human-rate proxy produces even under retries (no per-chunk logging).
const LOG_CHANNEL_CAPACITY: usize = 4096;

/// Spawn the dedicated log-writer thread. Called FIRST in main, before any log().
fn init_log_writer() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(LOG_CHANNEL_CAPACITY);
    let _ = LOG_TX.set(tx);
    std::thread::Builder::new()
        .name("log-writer".into())
        .spawn(move || {
            while let Some(body) = rx.blocking_recv() {
                write_log_line(&body);
            }
        })
        .expect("failed to spawn log writer thread");
}

static SYSTEM_TZ: OnceLock<jiff::tz::TimeZone> = OnceLock::new();

/// One timestamped line to stdout. writeln! (not println!) so a closed console
/// cannot panic the writer thread — with panic="abort" a thread panic would
/// kill the whole process mid-traffic.
fn write_log_line(body: &str) {
    let tz = SYSTEM_TZ.get_or_init(jiff::tz::TimeZone::system);
    let dt = jiff::Timestamp::now().to_zoned(tz.clone()).datetime();
    let mut out = std::io::stdout().lock();
    let _ = writeln!(
        out,
        "[{:04}-{:02}-{:02} {:02}:{:02}:{:02}] {body}",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    );
    let _ = out.flush();
}

fn log(msg: &str, req_id: Option<&str>) {
    let body = match req_id {
        Some(id) => format!("[Souffle-Proxy] [req={}] {msg}", &id[..8.min(id.len())]),
        None => format!("[Souffle-Proxy] {msg}"),
    };

    match LOG_TX.get() {
        Some(tx) => {
            // Bounded + lossy: on overload the line is dropped (the documented
            // tracing_appender::non_blocking shape); the writer drains orders of
            // magnitude faster than this proxy produces lines.
            let _ = tx.try_send(body);
        }
        None => write_log_line(&body),
    }
}

// ---------------------------------------------------------------------------
// Runtime Statistics
// ---------------------------------------------------------------------------
struct ProxyStats {
    start_time: Instant,
    total_requests: AtomicU64,
    active_requests: AtomicI64,
    success_count: AtomicU64,
    error_count: AtomicU64,
    total_ttft_us: AtomicU64,
    ttft_samples: AtomicU64,
    total_chunks: AtomicU64,
    total_bytes: AtomicU64,
    total_tokens_prompt: AtomicU64,
    total_tokens_completion: AtomicU64,
    total_tokens_reasoning: AtomicU64,
    total_tokens_cached: AtomicU64,
    pub last_request_time: AtomicI64,
}

impl ProxyStats {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_requests: AtomicU64::new(0),
            active_requests: AtomicI64::new(0),
            success_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            total_ttft_us: AtomicU64::new(0),
            ttft_samples: AtomicU64::new(0),
            total_chunks: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            total_tokens_prompt: AtomicU64::new(0),
            total_tokens_completion: AtomicU64::new(0),
            total_tokens_reasoning: AtomicU64::new(0),
            total_tokens_cached: AtomicU64::new(0),
            last_request_time: AtomicI64::new(jiff::Timestamp::now().as_second()),
        }
    }

    async fn snapshot(&self) -> Value {
        let samples = self.ttft_samples.load(Ordering::Relaxed);
        let avg_ttft = if samples > 0 {
            let total_ttft = self.total_ttft_us.load(Ordering::Relaxed) as f64 / 1_000_000.0;
            (total_ttft / samples as f64 * 1000.0).round() / 1000.0
        } else {
            0.0
        };

        let uptime = (self.start_time.elapsed().as_secs_f64() * 10.0).round() / 10.0;

        json!({
            "uptime_seconds": uptime,
            "total_requests": self.total_requests.load(Ordering::Relaxed),
            "active_requests": self.active_requests.load(Ordering::Relaxed),
            "success_count": self.success_count.load(Ordering::Relaxed),
            "error_count": self.error_count.load(Ordering::Relaxed),
            "avg_ttft_seconds": avg_ttft,
            "ttft_samples": samples,
            "total_chunks": self.total_chunks.load(Ordering::Relaxed),
            "total_bytes": self.total_bytes.load(Ordering::Relaxed),
            "total_tokens": {
                "prompt": self.total_tokens_prompt.load(Ordering::Relaxed),
                "completion": self.total_tokens_completion.load(Ordering::Relaxed),
                "reasoning": self.total_tokens_reasoning.load(Ordering::Relaxed),
                "cached": self.total_tokens_cached.load(Ordering::Relaxed),
            }
        })
    }
}

struct FirstTokenTiming {
    request_started: Instant,
    first_token_us: AtomicU64,
    committed: AtomicBool,
}

impl FirstTokenTiming {
    const UNRECORDED: u64 = u64::MAX;

    fn new(request_started: Instant) -> Self {
        Self {
            request_started,
            first_token_us: AtomicU64::new(Self::UNRECORDED),
            committed: AtomicBool::new(false),
        }
    }

    fn record_at(&self, observed_at: Instant) -> Option<f64> {
        let elapsed_us = observed_at
            .saturating_duration_since(self.request_started)
            .as_micros()
            .min((u64::MAX - 1) as u128) as u64;
        self.first_token_us
            .compare_exchange(
                Self::UNRECORDED,
                elapsed_us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .ok()?;
        Some(elapsed_us as f64 / 1_000_000.0)
    }

    fn commit(&self, stats: &ProxyStats) {
        let elapsed_us = self.first_token_us.load(Ordering::Relaxed);
        if elapsed_us == Self::UNRECORDED
            || self
                .committed
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        stats.total_ttft_us.fetch_add(elapsed_us, Ordering::Relaxed);
        stats.ttft_samples.fetch_add(1, Ordering::Relaxed);
    }

    fn recorded(&self) -> bool {
        self.first_token_us.load(Ordering::Relaxed) != Self::UNRECORDED
    }

    fn seconds(&self) -> f64 {
        let elapsed_us = self.first_token_us.load(Ordering::Relaxed);
        if elapsed_us == Self::UNRECORDED {
            0.0
        } else {
            elapsed_us as f64 / 1_000_000.0
        }
    }
}

#[derive(serde::Deserialize)]
struct ChatTokenProbe {
    choices: Option<Vec<ChatTokenChoice>>,
}

#[derive(serde::Deserialize)]
struct ChatTokenChoice {
    delta: Option<ChatTokenDelta>,
}

#[derive(serde::Deserialize)]
struct ChatTokenDelta {
    content: Option<Value>,
    reasoning_content: Option<Value>,
    reasoning: Option<Value>,
    refusal: Option<Value>,
    audio: Option<Value>,
    tool_calls: Option<Vec<ChatTokenCall>>,
    function_call: Option<ChatTokenFunctionCall>,
}

#[derive(serde::Deserialize)]
struct ChatTokenCall {
    function: Option<ChatTokenFunctionCall>,
}

#[derive(serde::Deserialize)]
struct ChatTokenFunctionCall {
    name: Option<Value>,
    arguments: Option<Value>,
}

fn has_nonempty_text(value: &Value) -> bool {
    match value {
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => items.iter().any(has_nonempty_text),
        Value::Object(fields) => fields.get("text").is_some_and(has_nonempty_text),
        _ => false,
    }
}

fn chat_sse_line_has_generated_delta(line: &[u8]) -> bool {
    let Some(data) = line
        .trim_ascii()
        .strip_prefix(b"data:")
        .map(|data| data.trim_ascii())
    else {
        return false;
    };
    if !data.windows(7).any(|window| window == b"\"delta\"") {
        return false;
    }
    let Ok(event) = serde_json::from_slice::<ChatTokenProbe>(data) else {
        return false;
    };
    event.choices.into_iter().flatten().any(|choice| {
        let Some(delta) = choice.delta else {
            return false;
        };
        [
            delta.content.as_ref(),
            delta.reasoning_content.as_ref(),
            delta.reasoning.as_ref(),
            delta.refusal.as_ref(),
            delta.audio.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(has_nonempty_text)
            || delta.tool_calls.into_iter().flatten().any(|call| {
                call.function.is_some_and(|function| {
                    function.name.as_ref().is_some_and(has_nonempty_text)
                        || function.arguments.as_ref().is_some_and(has_nonempty_text)
                })
            })
            || delta.function_call.is_some_and(|function| {
                function.name.as_ref().is_some_and(has_nonempty_text)
                    || function.arguments.as_ref().is_some_and(has_nonempty_text)
            })
    })
}

fn chat_sse_line_has_error(line: &[u8]) -> bool {
    let line = line.trim_ascii();
    if line.strip_prefix(b"event:").is_some_and(|kind| kind.trim_ascii() == b"error") {
        return true;
    }
    let Some(data) = line.strip_prefix(b"data:") else {
        return false;
    };
    if !data.windows(7).any(|part| part == b"\"error\"") {
        return false;
    }
    #[derive(serde::Deserialize)]
    struct ErrorProbe {
        error: Option<serde::de::IgnoredAny>,
    }
    serde_json::from_slice::<ErrorProbe>(data).is_ok_and(|event| event.error.is_some())
}

// ---------------------------------------------------------------------------
// Helpers for Headers & SSE
// ---------------------------------------------------------------------------
fn apply_nocache_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store, must-revalidate, max-age=0"),
    );
    headers.insert(
        HeaderName::from_static("cdn-cache-control"),
        HeaderValue::from_static("no-store"),
    );
    headers.insert(
        HeaderName::from_static("cloudflare-cdn-cache-control"),
        HeaderValue::from_static("no-store"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
    headers.insert(
        HeaderName::from_static("x-accel-buffering"),
        HeaderValue::from_static("no"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
}

static FINDER_USAGE: LazyLock<memchr::memmem::Finder<'static>> =
    LazyLock::new(|| memchr::memmem::Finder::new(b"\"usage\""));
static FINDER_CONTENT: LazyLock<memchr::memmem::Finder<'static>> =
    LazyLock::new(|| memchr::memmem::Finder::new(b"\"content\""));
static FINDER_REASONING: LazyLock<memchr::memmem::Finder<'static>> =
    LazyLock::new(|| memchr::memmem::Finder::new(b"\"reasoning"));

#[inline]
fn is_sse_done_line(line: &[u8]) -> bool {
    let trimmed = line.trim_ascii();
    trimmed
        .strip_prefix(b"data:")
        .is_some_and(|d| d.trim_ascii() == b"[DONE]")
}

fn is_empty_sse_response(data: &[u8]) -> bool {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut saw_stop = false;
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("data:") else {
            continue;
        };
        let data_str = rest.trim();
        if data_str.is_empty() || data_str == "[DONE]" {
            continue;
        }
        if let Ok(obj) = serde_json::from_str::<Value>(data_str) {
            if let Some(choices) = obj.get("choices").and_then(|c| c.as_array()) {
                for c in choices {
                    let delta = c.get("delta").and_then(|d| d.as_object());
                    let message = c.get("message").and_then(|m| m.as_object());
                    for holder in [delta, message].into_iter().flatten() {
                        let content = holder.get("content").and_then(|s| s.as_str()).unwrap_or("");
                        let reasoning_content = holder
                            .get("reasoning_content")
                            .and_then(|s| s.as_str())
                            .unwrap_or("");
                        let reasoning =
                            holder.get("reasoning").and_then(|s| s.as_str()).unwrap_or("");
                        let has_tools = holder
                            .get("tool_calls")
                            .and_then(|t| t.as_array())
                            .is_some_and(|a| !a.is_empty());
                        if !content.is_empty()
                            || !reasoning_content.is_empty()
                            || !reasoning.is_empty()
                            || has_tools
                        {
                            return false;
                        }
                    }
                    if c.get("finish_reason").and_then(|r| r.as_str()) == Some("stop")
                        && (delta.is_some() || message.is_some())
                    {
                        saw_stop = true;
                    }
                }
            }
        }
    }
    saw_stop
}

// Architectural Decision (Phase 3): Retain serde_json, skip simd-json.
// The SSE streaming hot-path relies on zero-copy SIMD memchr + slice windows.
// Full JSON parsing is only evaluated on cold/infrequent paths: the peeked first-chunk (<300B)
// and the terminal usage chunk (<200B, once per stream). simd-json requires mutable &mut [u8]
// buffers with scratch padding, which would force copying immutable BytesMut slices into heap
// Vec<u8> buffers, regressing throughput on sub-kilobyte lines compared to scalar serde_json.
// ---------------------------------------------------------------------------
// Degenerate-output guard (verbatim repetition-loop detector).
// ---------------------------------------------------------------------------
// Catches exact verbatim glued/spaced word or short-phrase repetition loops
// (e.g. "consoleconsole...", "i need i need...") inside either `reasoning`
// (`reasoning_content` / `reasoning`) or `content`, starting at any position.
//
// Zero-heap inline `[u8; 1024]` tail per channel (~2 KB/stream total), checked
// once every 64 bytes via SIMD `memchr::memrchr` + contiguous `[u8]::eq`
// (lowers to AVX-512 `vpcmpeqb` under `-C target-cpu=native`, zero `unsafe`).
const REPEAT_BUF_CAP: usize = 1024;
const REPEAT_SHIFT_KEEP: usize = 512;
const REPEAT_CHECK_STRIDE: usize = 64;
const REPEAT_MIN_PERIOD: usize = 2;
const REPEAT_MAX_PERIOD: usize = 64;
const REPEAT_MIN_SPAN_BYTES: usize = 256;
const REPEAT_MIN_REPEATS: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RepeatChannel {
    Reasoning,
    Content,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RepeatMatch {
    channel: RepeatChannel,
    period: usize,
    span: usize,
}

fn detect_periodic_suffix(tail: &[u8]) -> Option<(usize, usize)> {
    let n = tail.len();
    if n < REPEAT_MIN_SPAN_BYTES {
        return None;
    }
    let last = tail[n - 1];
    let search_start = n.saturating_sub(1 + REPEAT_MAX_PERIOD);
    let mut search_end = n - 1;
    while let Some(rel) = memchr::memrchr(last, &tail[search_start..search_end]) {
        let pos = search_start + rel;
        let p = (n - 1) - pos;
        search_end = pos;
        if p < REPEAT_MIN_PERIOD {
            continue;
        }
        let span = REPEAT_MIN_SPAN_BYTES.max(p * REPEAT_MIN_REPEATS);
        if span > n {
            continue;
        }
        let suffix_start = n - span;
        if tail[suffix_start..n - p] == tail[suffix_start + p..n] {
            let motif = &tail[n - p..n];
            let has_word_byte = motif.iter().any(|&b| b.is_ascii_alphabetic() || b >= 0x80);
            let has_distinct_byte = motif.iter().any(|&b| b != last);
            if has_word_byte && has_distinct_byte {
                return Some((p, span));
            }
        }
    }
    None
}

struct ChannelWatch {
    buf: [u8; REPEAT_BUF_CAP],
    len: usize,
    since_check: usize,
}

impl Default for ChannelWatch {
    fn default() -> Self {
        Self {
            buf: [0u8; REPEAT_BUF_CAP],
            len: 0,
            since_check: 0,
        }
    }
}

impl ChannelWatch {
    fn feed(&mut self, bytes: &[u8]) -> Option<(usize, usize)> {
        if bytes.is_empty() {
            return None;
        }
        for chunk in bytes.chunks(REPEAT_CHECK_STRIDE) {
            if self.len + chunk.len() > REPEAT_BUF_CAP {
                let keep = self.len.min(REPEAT_SHIFT_KEEP);
                let drop_n = self.len - keep;
                self.buf.copy_within(drop_n..self.len, 0);
                self.len = keep;
            }
            self.buf[self.len..self.len + chunk.len()].copy_from_slice(chunk);
            self.len += chunk.len();
            self.since_check += chunk.len();
            if self.since_check >= REPEAT_CHECK_STRIDE {
                self.since_check = 0;
                if let Some(hit) = detect_periodic_suffix(&self.buf[..self.len]) {
                    return Some(hit);
                }
            }
        }
        None
    }

    fn finish(&self) -> Option<(usize, usize)> {
        if self.since_check == 0 {
            return None;
        }
        let trimmed = self.buf[..self.len].trim_ascii_end();
        detect_periodic_suffix(trimmed)
    }
}

#[derive(Default)]
struct RepeatWatch {
    reasoning: ChannelWatch,
    content: ChannelWatch,
}

impl RepeatWatch {
    fn new() -> Self {
        Self::default()
    }

    fn feed_text(&mut self, channel: RepeatChannel, text: &str) -> Option<RepeatMatch> {
        let ch = match channel {
            RepeatChannel::Reasoning => &mut self.reasoning,
            RepeatChannel::Content => &mut self.content,
        };
        ch.feed(text.as_bytes()).map(|(period, span)| RepeatMatch {
            channel,
            period,
            span,
        })
    }

    fn finish_channel(&self, channel: RepeatChannel) -> Option<RepeatMatch> {
        let ch = match channel {
            RepeatChannel::Reasoning => &self.reasoning,
            RepeatChannel::Content => &self.content,
        };
        ch.finish().map(|(period, span)| RepeatMatch {
            channel,
            period,
            span,
        })
    }

    fn feed_sse_line(&mut self, raw_line: &[u8]) -> Option<RepeatMatch> {
        let trimmed = raw_line.trim_ascii();
        let data = trimmed.strip_prefix(b"data:")?.trim_ascii();
        if data.is_empty() || data == b"[DONE]" {
            return None;
        }
        if FINDER_CONTENT.find(data).is_none() && FINDER_REASONING.find(data).is_none() {
            return None;
        }
        scan_sse_json_into_watch(self, data)
    }
}

#[derive(serde::Deserialize)]
struct SseRepeatDelta<'a> {
    #[serde(borrow, default)]
    content: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow, default)]
    reasoning_content: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow, default)]
    reasoning: Option<std::borrow::Cow<'a, str>>,
}

#[derive(serde::Deserialize)]
struct SseRepeatChoice<'a> {
    #[serde(borrow, default)]
    delta: Option<SseRepeatDelta<'a>>,
    #[serde(borrow, default)]
    message: Option<SseRepeatDelta<'a>>,
}

fn scan_sse_json_into_watch(watch: &mut RepeatWatch, data: &[u8]) -> Option<RepeatMatch> {
    struct ChoicesSeed<'w>(&'w mut RepeatWatch, &'w mut Option<RepeatMatch>);
    impl<'de, 'w> serde::de::DeserializeSeed<'de> for ChoicesSeed<'w> {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<(), D::Error> {
            struct SeqVis<'w>(&'w mut RepeatWatch, &'w mut Option<RepeatMatch>);
            impl<'de, 'w> serde::de::Visitor<'de> for SeqVis<'w> {
                type Value = ();
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("choices array")
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> Result<(), A::Error> {
                    while let Some(c) = seq.next_element::<SseRepeatChoice<'de>>()? {
                        for holder in [c.delta, c.message].into_iter().flatten() {
                            if let Some(rc) = holder.reasoning_content.as_deref() {
                                if let Some(m) =
                                    self.0.feed_text(RepeatChannel::Reasoning, rc)
                                {
                                    *self.1 = Some(m);
                                    return Ok(());
                                }
                            }
                            if let Some(r) = holder.reasoning.as_deref() {
                                if let Some(m) =
                                    self.0.feed_text(RepeatChannel::Reasoning, r)
                                {
                                    *self.1 = Some(m);
                                    return Ok(());
                                }
                            }
                            if let Some(ct) = holder.content.as_deref() {
                                if let Some(m) = self.0.feed_text(RepeatChannel::Content, ct) {
                                    *self.1 = Some(m);
                                    return Ok(());
                                }
                            }
                        }
                    }
                    Ok(())
                }
            }
            deserializer.deserialize_seq(SeqVis(self.0, self.1))
        }
    }

    struct RootSeed<'w>(&'w mut RepeatWatch, &'w mut Option<RepeatMatch>);
    impl<'de, 'w> serde::de::DeserializeSeed<'de> for RootSeed<'w> {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<(), D::Error> {
            struct MapVis<'w>(&'w mut RepeatWatch, &'w mut Option<RepeatMatch>);
            impl<'de, 'w> serde::de::Visitor<'de> for MapVis<'w> {
                type Value = ();
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("SSE chunk object")
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<(), A::Error> {
                    while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                        if key == "choices" {
                            map.next_value_seed(ChoicesSeed(self.0, self.1))?;
                            if self.1.is_some() {
                                return Ok(());
                            }
                        } else {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                    Ok(())
                }
            }
            deserializer.deserialize_map(MapVis(self.0, self.1))
        }
    }

    let mut hit = None;
    let mut de = serde_json::Deserializer::from_slice(data);
    let _ = serde::de::DeserializeSeed::deserialize(RootSeed(watch, &mut hit), &mut de);
    hit
}

#[derive(Default)]
struct StreamMetrics {
    chunks: AtomicU64,
    bytes: AtomicU64,
    seen_done: std::sync::atomic::AtomicBool,
    seen_error: AtomicBool,
    prompt_tokens: AtomicU64,
    completion_tokens: AtomicU64,
    reasoning_tokens: AtomicU64,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct CompletionTokensDetails {
    #[serde(default)]
    reasoning_tokens: Option<u64>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct UsageStats {
    #[serde(default)]
    prompt_tokens: Option<u64>,
    #[serde(default)]
    completion_tokens: Option<u64>,
    #[serde(default)]
    reasoning_tokens: Option<u64>,
    #[serde(default)]
    completion_tokens_details: Option<CompletionTokensDetails>,
}

impl UsageStats {
    fn reasoning_tokens(&self) -> u64 {
        self.reasoning_tokens
            .or_else(|| self.completion_tokens_details.as_ref().and_then(|d| d.reasoning_tokens))
            .unwrap_or(0)
    }
}

#[derive(serde::Deserialize)]
struct SseUsageChunk {
    #[serde(default)]
    usage: Option<UsageStats>,
}

#[derive(serde::Deserialize)]
struct BufferedContentPart<'a> {
    #[serde(borrow, default)]
    text: Option<std::borrow::Cow<'a, str>>,
}

fn feed_buffered_raw_field(
    watch: &mut RepeatWatch,
    channel: RepeatChannel,
    raw: &RawValue,
) -> Option<RepeatMatch> {
    let s = raw.get().trim();
    if s.starts_with('"') {
        if let Ok(cow) = serde_json::from_str::<std::borrow::Cow<str>>(s) {
            return watch.feed_text(channel, &cow);
        }
    } else if s.starts_with('[') {
        if let Ok(parts) = serde_json::from_str::<Vec<BufferedContentPart>>(s) {
            for part in parts {
                if let Some(txt) = part.text.as_deref() {
                    if let Some(hit) = watch.feed_text(channel, txt) {
                        return Some(hit);
                    }
                }
            }
        }
    }
    None
}

#[derive(serde::Deserialize)]
struct BufferedChoiceMessage<'a> {
    #[serde(borrow, default)]
    content: Option<&'a RawValue>,
    #[serde(borrow, default)]
    reasoning_content: Option<&'a RawValue>,
    #[serde(borrow, default)]
    reasoning: Option<&'a RawValue>,
}

#[derive(serde::Deserialize)]
struct BufferedChoice<'a> {
    #[serde(borrow, default)]
    message: Option<BufferedChoiceMessage<'a>>,
    #[serde(borrow, default)]
    text: Option<&'a RawValue>,
}

#[derive(serde::Deserialize)]
struct BufferedResponse<'a> {
    #[serde(borrow, default)]
    choices: Option<Vec<BufferedChoice<'a>>>,
    #[serde(default)]
    usage: Option<UsageStats>,
}

impl<'a> BufferedResponse<'a> {
    fn detect_repetition(&self) -> Option<RepeatMatch> {
        let mut watch = RepeatWatch::new();
        if let Some(choices) = &self.choices {
            for c in choices {
                if let Some(msg) = &c.message {
                    if let Some(raw) = msg.reasoning_content {
                        if let Some(hit) =
                            feed_buffered_raw_field(&mut watch, RepeatChannel::Reasoning, raw)
                        {
                            return Some(hit);
                        }
                    }
                    if let Some(raw) = msg.reasoning {
                        if let Some(hit) =
                            feed_buffered_raw_field(&mut watch, RepeatChannel::Reasoning, raw)
                        {
                            return Some(hit);
                        }
                    }
                    if let Some(raw) = msg.content {
                        if let Some(hit) =
                            feed_buffered_raw_field(&mut watch, RepeatChannel::Content, raw)
                        {
                            return Some(hit);
                        }
                    }
                }
                if let Some(raw) = c.text {
                    if let Some(hit) =
                        feed_buffered_raw_field(&mut watch, RepeatChannel::Content, raw)
                    {
                        return Some(hit);
                    }
                }
            }
        }
        watch
            .finish_channel(RepeatChannel::Reasoning)
            .or_else(|| watch.finish_channel(RepeatChannel::Content))
    }

    fn extract_usage(self) -> Option<UsageStats> {
        self.usage
    }
}

/// Extract the trailing `usage` object of a buffered completion without parsing the
/// whole document. Falls back to `None` on any unexpected shape, so the caller can
/// still do a full parse; the point is that the common case never pays for one.
fn extract_usage_from_body_tail(body: &[u8]) -> Option<UsageStats> {
    const TAIL: usize = 8192;
    let window = &body[body.len().saturating_sub(TAIL)..];
    let mut i = memchr::memmem::rfind(window, b"\"usage\"")? + b"\"usage\"".len();
    while i < window.len() && window[i].is_ascii_whitespace() {
        i += 1;
    }
    if window.get(i) != Some(&b':') {
        return None;
    }
    i += 1;
    while i < window.len() && window[i].is_ascii_whitespace() {
        i += 1;
    }
    if window.get(i) != Some(&b'{') {
        return None;
    }
    let obj_start = i;
    let mut depth = 0usize;
    let mut in_str = false;
    let mut escaped = false;
    while i < window.len() {
        let c = window[i];
        if in_str {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_str = false;
            }
        } else {
            match c {
                b'"' => in_str = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return serde_json::from_slice::<UsageStats>(&window[obj_start..=i]).ok();
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

fn extract_usage_from_sse_line(line: &str) -> Option<UsageStats> {
    let data_str = line.trim().strip_prefix("data:")?.trim();
    if data_str.is_empty() || data_str == "[DONE]" {
        return None;
    }
    serde_json::from_str::<SseUsageChunk>(data_str)
        .ok()
        .and_then(|obj| obj.usage)
}

/// Publish prompt/completion/reasoning counters from an SSE usage payload to the
/// shared per-request atomics (the Drop guard folds them into ProxyStats).
/// Shared by the chunk scanner and the leftover-buffer pass.
fn publish_sse_usage(u: &UsageStats, metrics: &StreamMetrics) {
    if let Some(p) = u.prompt_tokens {
        metrics.prompt_tokens.store(p, Ordering::Relaxed);
    }
    if let Some(c) = u.completion_tokens {
        metrics.completion_tokens.store(c, Ordering::Relaxed);
    }
    let r = u.reasoning_tokens();
    if r > 0 {
        metrics.reasoning_tokens.store(r, Ordering::Relaxed);
    }
}

/// Build the labeled " tokens=N (reasoning=M, X t/s)" log suffix; empty when no
/// completion tokens were reported. Shared by the Drop guard and the
/// usage-stats accumulator.
fn format_token_info(tokens: u64, reasoning: u64, elapsed: f64, ttft: f64, label: &str) -> String {
    if tokens == 0 {
        return String::new();
    }
    let gen_time = (elapsed - ttft).max(0.001);
    let tps = tokens as f64 / gen_time;
    if reasoning > 0 {
        format!(
            " {label}={} (reasoning={}, {:.1} t/s)",
            tokens, reasoning, tps
        )
    } else {
        format!(" {label}={} ({:.1} t/s)", tokens, tps)
    }
}

/// Accumulate one usage object into ProxyStats (prompt/reasoning/completion)
/// and build the " tokens=..." log suffix. Shared by the streaming
/// end-of-body and buffered-response paths.
fn apply_usage_stats(
    stats: &ProxyStats,
    usage: &UsageStats,
    elapsed: f64,
    ttft: f64,
    label: &str,
) -> String {
    let mut token_info = String::new();
    if let Some(p) = usage.prompt_tokens {
        stats.total_tokens_prompt.fetch_add(p, Ordering::Relaxed);
    }
    let reasoning = usage.reasoning_tokens();
    if reasoning > 0 {
        stats
            .total_tokens_reasoning
            .fetch_add(reasoning, Ordering::Relaxed);
    }
    if let Some(c) = usage.completion_tokens {
        stats
            .total_tokens_completion
            .fetch_add(c, Ordering::Relaxed);
        token_info = format_token_info(c, reasoning, elapsed, ttft, label);
    }
    token_info
}

fn make_json_response(status: StatusCode, body: Value) -> Response {
    let mut resp = Json(body).into_response();
    *resp.status_mut() = status;
    apply_nocache_headers(resp.headers_mut());
    resp
}

fn make_text_response(status: StatusCode, text: &str) -> Response {
    // Every caller is a failure path. Emit the OpenAI error envelope rather than
    // text/plain: SDKs parse {"error":{...}} and report decode errors otherwise.
    make_error_response(status, text)
}

fn make_error_response(status: StatusCode, msg: &str) -> Response {
    let err_json = json!({
        "error": {
            "message": msg,
            "type": "proxy_error",
            "code": status.as_u16().to_string(),
        }
    });
    make_json_response(status, err_json)
}

// ---------------------------------------------------------------------------
// App State
// ---------------------------------------------------------------------------
struct PresetRuntime {
    config: Arc<Config>,
    client: UpstreamClient,
    model_index: AtomicUsize,
    key_index: AtomicUsize,
}

struct AppState {
    slots: Vec<Arc<PresetRuntime>>,
    semaphore: Arc<Semaphore>,
    stats: Arc<ProxyStats>,
    stripped_headers: HashSet<HeaderName>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------
async fn handle_options() -> Response {
    let mut resp = StatusCode::NO_CONTENT.into_response();
    let headers = resp.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("*"),
    );
    apply_nocache_headers(headers);
    resp
}

async fn handle_fallback(req: Request) -> Response {
    if req.method() == Method::OPTIONS {
        handle_options().await
    } else if responses::stored_operation(req.uri().path(), req.method()) {
        make_error_response(StatusCode::BAD_REQUEST, "This proxy provides stateless Responses only; stored-response operations are unavailable")
    } else {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        make_json_response(
            StatusCode::NOT_FOUND,
            json!({
                "error": {
                    "message": format!("Route not found: {} {}", method, path),
                    "type": "invalid_request_error",
                    "code": "404"
                }
            }),
        )
    }
}

fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(handle_health))
        .route("/", get(handle_health))
        .route("/v1/models", get(handle_models))
        .route("/models", get(handle_models))
        .route("/stats", get(handle_stats))
        .route(
            "/v1/chat/completions",
            post(handle_chat_completions).options(handle_options),
        )
        .route(
            "/chat/completions",
            post(handle_chat_completions).options(handle_options),
        )
        .route(
            "/v1/responses",
            post(handle_chat_completions).options(handle_options),
        )
        .route(
            "/responses",
            post(handle_chat_completions).options(handle_options),
        )
        .route(
            "/v1/responses/compact",
            post(handle_chat_completions).options(handle_options),
        )
        .route(
            "/responses/compact",
            post(handle_chat_completions).options(handle_options),
        )
        .route(
            "/v1/responses/input_tokens",
            post(handle_chat_completions).options(handle_options),
        )
        .route(
            "/responses/input_tokens",
            post(handle_chat_completions).options(handle_options),
        )
        .fallback(handle_fallback)
        .with_state(state)
}

static HEALTH_JSON_BYTES: &[u8] =
    br#"{"engine":"h2-rust-async","provider":"souffle_proxy","status":"ok"}"#;

static MODELS_JSON_BYTES: LazyLock<Bytes> = LazyLock::new(|| {
    let payload = json!({
        "object": "list",
        "data": exposed_models()
    });
    Bytes::from(serde_json::to_vec(&payload).expect("models JSON serialization"))
});

fn make_static_json_response(status: StatusCode, body: Bytes) -> Response {
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    apply_nocache_headers(headers);
    resp
}

async fn handle_health() -> Response {
    make_static_json_response(StatusCode::OK, Bytes::from_static(HEALTH_JSON_BYTES))
}

async fn handle_models() -> Response {
    make_static_json_response(StatusCode::OK, MODELS_JSON_BYTES.clone())
}

async fn handle_stats(State(state): State<Arc<AppState>>) -> Response {
    make_json_response(StatusCode::OK, state.stats.snapshot().await)
}

struct ActiveRequestGuard(Arc<ProxyStats>);
impl ActiveRequestGuard {
    fn new(stats: Arc<ProxyStats>) -> Self {
        stats.active_requests.fetch_add(1, Ordering::Relaxed);
        Self(stats)
    }
}
impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        self.0.active_requests.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Only a 500-char preview of an upstream error body is ever shown, so buffering more
/// than this is pointless -- and an unbounded read would let a broken upstream exhaust
/// memory. Caps both the retry-preview read and the final error-body read.
const ERROR_BODY_CAP: usize = 64 * 1024;
/// A stalled upstream that already sent error headers must not hang the request.
const ERROR_BODY_TIMEOUT: Duration = Duration::from_secs(5);

async fn handle_chat_completions(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let req_id = format!("{:08x}", fastrand::u32(..));
    let t_start = Instant::now();

    state.stats.total_requests.fetch_add(1, Ordering::Relaxed);
    let active_guard = ActiveRequestGuard::new(state.stats.clone());
    let options = responses::RequestOptions::capture(&request);

    // Reject an oversized body before buffering it at all. A streaming request with
    // no Content-Length is still capped below by the bounded read; this just fails
    // the declared-length case early.
    if let Some(len) = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
    {
        if len > state.slots[0].config.max_body_bytes {
            state.stats.error_count.fetch_add(1, Ordering::Relaxed);
            log(
                &format!(
                    "Rejecting body of {} bytes (limit {}).",
                    len, state.slots[0].config.max_body_bytes
                ),
                None,
            );
            return make_text_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &format!(
                    "Request body of {} bytes exceeds the {} byte limit",
                    len, state.slots[0].config.max_body_bytes
                ),
            );
        }
    }

    let raw_bytes =
        match axum::body::to_bytes(request.into_body(), state.slots[0].config.max_body_bytes).await
        {
            Ok(b) => b,
            Err(e) => {
                state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                let msg = format!("Body read error: {}", e);
                // A length-limit breach is a client error (413); anything else is a bad request.
                let status = if msg.contains("length limit") {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::BAD_REQUEST
                };
                return make_text_response(status, &msg);
            }
        };

    let raw_len = raw_bytes.len();
    state
        .stats
        .last_request_time
        .store(jiff::Timestamp::now().as_second(), Ordering::Relaxed);
    if options.operation.native() {
        responses::raw_path(state, raw_bytes, req_id, t_start, active_guard, options).await
    } else {
        chat_completions_raw_path(state, raw_bytes, raw_len, req_id, t_start, active_guard).await
    }
}

/// Select the slot index based on the client's requested model string.
/// Returns 1 (slot 2) only for "deepseek-sol" when 2+ slots exist;
/// everything else falls back to 0 (slot 1).
fn select_slot_index(requested_model: &str, num_slots: usize) -> usize {
    match requested_model {
        "deepseek-sol" if num_slots > 1 => 1,
        _ => 0,
    }
}

/// Owned-RawValue chat-completions hot path.
/// Eliminates recursive Value tree allocations and giant object heap fragmentation.
/// Preserves:
/// (a) is_stream captured from client body before inject merge;
/// (b) inject merges non-structural keys;
/// (c) model forced last from pre-serialized models_raw;
/// (d) error surfaces match OpenAI API specification verbatim.
async fn chat_completions_raw_path(
    state: Arc<AppState>,
    raw_bytes: Bytes,
    raw_len: usize,
    req_id: String,
    t_start: Instant,
    active_guard: ActiveRequestGuard,
) -> Response {
    let mut payload: BTreeMap<String, Box<RawValue>> = match serde_json::from_slice(&raw_bytes) {
        Ok(m) => m,
        Err(e) => {
            state.stats.error_count.fetch_add(1, Ordering::Relaxed);
            match serde_json::from_slice::<Value>(&raw_bytes) {
                Ok(v) if !v.is_object() => {
                    return make_error_response(
                        StatusCode::BAD_REQUEST,
                        "Request body must be a JSON object",
                    );
                }
                _ => {
                    return make_text_response(
                        StatusCode::BAD_REQUEST,
                        &format!("Malformed JSON: {}", e),
                    );
                }
            }
        }
    };
    drop(raw_bytes);

    let is_stream = payload
        .get("stream")
        .map(|rv| rv.get().trim() == "true")
        .unwrap_or(false);
    let requested_model = payload
        .get("model")
        .and_then(|rv| {
            let s = rv.get().trim();
            if s.starts_with('"') && s.ends_with('"') && !s[1..s.len() - 1].contains('\\') {
                Some(s[1..s.len() - 1].to_string())
            } else {
                serde_json::from_str::<String>(s).ok()
            }
        })
        .unwrap_or_default();

    let slot_idx = select_slot_index(&requested_model, state.slots.len());
    if slot_idx == 0
        && !requested_model.is_empty()
        && requested_model != "deepseek-souffle"
        && state.slots.len() > 1
    {
        log(
            &format!(
                "[WARN] Model '{}' matched no slot; falling back to slot 1 (preset '{}', model {})",
                requested_model,
                state.slots[0].config.preset_name,
                state.slots[0]
                    .config
                    .models
                    .first()
                    .map(|s| s.as_str())
                    .unwrap_or("")
            ),
            Some(&req_id),
        );
    }
    let preset = state.slots[slot_idx].clone();
    if preset.config.api_mode != responses::ApiMode::ChatCompletions {
        state.stats.error_count.fetch_add(1, Ordering::Relaxed);
        return make_error_response(StatusCode::BAD_REQUEST, "Selected preset uses Responses; send a native /v1/responses request instead of Chat Completions");
    }

    for (k, v) in preset.config.inject_raw.iter() {
        match k.as_str() {
            "messages" | "stream" | "model" => {
                log(
                    &format!("Preset inject key '{}' ignored (structural/forced key)", k),
                    Some(&req_id),
                );
            }
            _ => {
                payload.insert(k.clone(), v.clone());
            }
        }
    }

    let (selected_model, model_idx, model_count, model_raw) = {
        let models = &preset.config.models;
        let idx = preset.model_index.fetch_add(1, Ordering::Relaxed) % models.len();
        (
            &models[idx],
            idx,
            models.len(),
            preset.config.models_raw[idx].clone(),
        )
    };
    payload.insert("model".to_string(), model_raw);
    let model_note = if log_verbose() {
        if model_count > 1 {
            log(
                &format!(
                    "Model requested: {} → rewriting to {} (preset '{}', model {}/{})",
                    requested_model,
                    selected_model,
                    preset.config.preset_name,
                    model_idx + 1,
                    model_count
                ),
                Some(&req_id),
            );
        } else {
            log(
                &format!(
                    "Model requested: {} → rewriting to {} (preset '{}')",
                    requested_model, selected_model, preset.config.preset_name
                ),
                Some(&req_id),
            );
        }
        String::new()
    } else {
        format!(" ({} → {})", requested_model, selected_model)
    };

    // In-Content CoT Folding (souffle_pout)
    if preset.config.souffle_pout {
        if let Some(msgs_raw) = payload.get("messages") {
            if let Some(folded) = fold_in_content_cot(msgs_raw.get()) {
                payload.insert("messages".to_string(), folded);
                log(
                    "Preset: CoT folded into <think> (souffle_pout)",
                    Some(&req_id),
                );
            }
        }
    }

    // Splice in preset messages lazily: the client array stays in place and the
    // serializer emits prefix/inner/suffix ranges instead of a copied array.
    let (msg_count, prepended_added, appended_added, spliced_messages) =
        match payload.remove("messages") {
            Some(msgs) => {
                let (splice, count, p_add, a_add) = plan_messages_splice(
                    msgs,
                    preset.config.prepend_raw.as_deref(),
                    preset.config.prepend_messages.len(),
                    preset.config.append_raw.as_deref(),
                    preset.config.append_messages.len(),
                );
                match splice {
                    MsgsSplice::Verbatim(m) => {
                        payload.insert("messages".to_string(), m);
                        (count, p_add, a_add, None)
                    }
                    MsgsSplice::Spliced(s) => (count, p_add, a_add, Some(s)),
                }
            }
            None => (0, 0, 0, None),
        };

    if prepended_added > 0 {
        log(
            &format!("Preset: +{} msg (system)", prepended_added),
            Some(&req_id),
        );
    }
    if appended_added > 0 {
        log(
            &format!("Preset: +{} msg (prefill)", appended_added),
            Some(&req_id),
        );
    }

    let kb_size = raw_len as f64 / 1024.0;

    log(
        &format!(
            "POST /v1/chat/completions msgs={} size={:.1}KB stream={}{}",
            msg_count, kb_size, is_stream, model_note
        ),
        Some(&req_id),
    );

    let permit = match state.semaphore.clone().acquire_owned().await {
        Ok(p) => p,
        Err(e) => {
            state.stats.error_count.fetch_add(1, Ordering::Relaxed);
            return make_text_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!("Semaphore error: {}", e),
            );
        }
    };

    dispatch_upstream(
        state.clone(),
        preset.clone(),
        UpstreamPayload {
            map: payload,
            spliced_messages,
        },
        raw_len,
        is_stream,
        req_id,
        t_start,
        permit,
        active_guard,
        responses::RequestOptions::default(),
    )
    .await
}

/// Structural scan result of a JSON array.
struct ArrayScan<'a> {
    element_count: usize,
    inner_start: usize,
    inner_end: usize,
    last_element: Option<&'a str>,
}

/// Scans a JSON array without materializing an AST tree.
/// Uses SIMD `memchr` to scan strings at ~30 GB/s.
/// Returns `None` on non-arrays or malformed input.
fn scan_json_array(s: &str) -> Option<ArrayScan<'_>> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'[' {
        return None;
    }
    i += 1;
    let inner_start = i;

    let mut peek = i;
    while peek < bytes.len() && bytes[peek].is_ascii_whitespace() {
        peek += 1;
    }
    if peek >= bytes.len() {
        return None;
    }
    if bytes[peek] == b']' {
        return Some(ArrayScan {
            element_count: 0,
            inner_start: peek,
            inner_end: peek,
            last_element: None,
        });
    }

    let mut count = 1;
    let mut depth: u32 = 1;
    let len = bytes.len();
    let mut last_elem_start = i;

    while i < len {
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < len {
                    let pos = memchr::memchr2(b'"', b'\\', &bytes[i..])?;
                    let hit = i + pos;
                    if bytes[hit] == b'"' {
                        i = hit;
                        break;
                    } else {
                        if hit + 1 >= len {
                            return None;
                        }
                        i = hit + 2;
                    }
                }
            }
            b'{' | b'[' => {
                depth += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
            }
            b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let inner_end = i;
                    let last_elem_slice = s[last_elem_start..inner_end].trim();
                    return Some(ArrayScan {
                        element_count: count,
                        inner_start,
                        inner_end,
                        last_element: Some(last_elem_slice),
                    });
                }
            }
            b',' if depth == 1 => {
                count += 1;
                last_elem_start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }

    None
}

/// End offset (one past the closing quote) of the JSON string literal starting at `i`.
/// Escape-aware: `\\` and `\"` never terminate the literal.
fn scan_json_string_end(bytes: &[u8], mut i: usize) -> Option<usize> {
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    i += 1;
    while i < bytes.len() {
        let pos = memchr::memchr2(b'"', b'\\', &bytes[i..])?;
        let hit = i + pos;
        if bytes[hit] == b'"' {
            return Some(hit + 1);
        }
        // Escaped byte: skipping two is safe even for \uXXXX (hex digits
        // are never a quote or a backslash).
        i = hit + 2;
    }
    None
}

/// End offset (one past the last byte) of the JSON value starting at `i`.
fn scan_json_value_end(bytes: &[u8], i: usize) -> Option<usize> {
    match *bytes.get(i)? {
        b'"' => scan_json_string_end(bytes, i),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut j = i;
            while j < bytes.len() {
                match bytes[j] {
                    b'"' => {
                        j = scan_json_string_end(bytes, j)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            return Some(j + 1);
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            None
        }
        _ => {
            // Scalar (number/true/false/null): ends at a structural byte.
            let mut j = i;
            while j < bytes.len() {
                match bytes[j] {
                    b',' | b'}' | b']' => return Some(j),
                    b if b.is_ascii_whitespace() => return Some(j),
                    _ => j += 1,
                }
            }
            Some(bytes.len())
        }
    }
}

/// Byte span `[start, end)` of a top-level object member's value.
/// Only depth-1 members are examined, so nested `"model"` keys can't match.
fn find_top_level_value_span(bytes: &[u8], key: &str) -> Option<(usize, usize)> {
    let len = bytes.len();
    let mut i = 0;
    while i < len && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if bytes.get(i) != Some(&b'{') {
        return None;
    }
    i += 1;
    loop {
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if bytes.get(i) != Some(&b'"') {
            return None;
        }
        let key_start = i;
        let key_end = scan_json_string_end(bytes, i)?;
        let raw_key = &bytes[key_start + 1..key_end - 1];
        let key_matches = raw_key == key.as_bytes()
            || (raw_key.contains(&b'\\')
                && std::str::from_utf8(&bytes[key_start..key_end])
                    .ok()
                    .and_then(|s| serde_json::from_str::<String>(s).ok())
                    .is_some_and(|s| s == key));
        i = key_end;
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if bytes.get(i) != Some(&b':') {
            return None;
        }
        i += 1;
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let value_start = i;
        let value_end = scan_json_value_end(bytes, i)?;
        if key_matches {
            return Some((value_start, value_end));
        }
        i = value_end;
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if bytes.get(i) != Some(&b',') {
            return None;
        }
        i += 1;
    }
}

/// Outcome of swapping the top-level `"model"` literal in a serialized body.
enum ModelPatch {
    /// The body already carries this exact literal: nothing to rewrite.
    Unchanged,
    /// Body rebuilt with the new literal.
    Replaced(Bytes),
    /// `model` not found (or malformed body): caller must re-serialize.
    NotFound,
}

/// Swap the top-level `"model"` value span inside an already-serialized body.
///
/// Byte-identical to re-serializing the whole payload map: top-level keys are
/// emitted in `BTreeMap` order and the model value is a pre-serialized raw
/// literal, so a model rotation can only move that one span. One memcpy beats
/// re-serializing (and re-brotli'ing) multi-MB JSON while a permit is held.
fn patch_serialized_model(body: &Bytes, model_raw: &str) -> ModelPatch {
    let Some((value_start, value_end)) = find_top_level_value_span(body, "model") else {
        return ModelPatch::NotFound;
    };
    let current = &body[value_start..value_end];
    let new_literal = model_raw.as_bytes();
    if current == new_literal {
        return ModelPatch::Unchanged;
    }
    let mut out = BytesMut::with_capacity(body.len() - current.len() + new_literal.len());
    out.extend_from_slice(&body[..value_start]);
    out.extend_from_slice(new_literal);
    out.extend_from_slice(&body[value_end..]);
    ModelPatch::Replaced(out.freeze())
}

#[derive(serde::Deserialize)]
struct RoleCheck<'a> {
    #[serde(borrow, default)]
    role: Option<&'a str>,
}

/// A `messages` array with preset prefix/suffix spliced in at serialize time.
///
/// Holds the client array verbatim plus the byte range of its element list, so
/// emitting it is a couple of `extend_from_slice` calls instead of copying the
/// whole (multi-MB) array into a fresh String and re-validating it as a RawValue.
struct SplicedMessages {
    /// Client array, byte-for-byte as received (CoT-folded content included).
    body: Box<RawValue>,
    /// Range between `[` and `]`, client whitespace included.
    inner: std::ops::Range<usize>,
    /// Comma-joined preset messages emitted right after `[`.
    prefix: Option<String>,
    /// Comma-joined preset messages emitted right before `]`.
    suffix: Option<String>,
}

impl SplicedMessages {
    /// Write `[prefix, <client elements>, suffix]` without materializing it.
    fn emit_into(&self, buf: &mut Vec<u8>) {
        buf.push(b'[');
        let inner = &self.body.get().as_bytes()[self.inner.clone()];
        let prefix = self.prefix.as_deref().filter(|p| !p.is_empty());
        let suffix = self.suffix.as_deref().filter(|s| !s.is_empty());
        if let Some(p) = prefix {
            buf.extend_from_slice(p.as_bytes());
        }
        if !inner.is_empty() {
            if prefix.is_some() {
                buf.push(b',');
            }
            buf.extend_from_slice(inner);
            if suffix.is_some() {
                buf.push(b',');
            }
        }
        if let Some(s) = suffix {
            buf.extend_from_slice(s.as_bytes());
        }
        buf.push(b']');
    }

    fn estimated_len(&self) -> usize {
        // The client array itself is the dominant term: `map` holds no `messages`
        // entry when splicing, so omitting it here made the outbound Vec double
        // once (a full memcpy) on every spliced request -- the copy the splice
        // exists to avoid.
        self.body.get().len()
            + self.prefix.as_ref().map_or(0, |p| p.len() + 1)
            + self.suffix.as_ref().map_or(0, |s| s.len() + 1)
            + 1
    }
}

/// How `messages` should be emitted for this request.
enum MsgsSplice {
    /// Nothing to add: keep the array in the payload map untouched.
    Verbatim(Box<RawValue>),
    /// Prefix/suffix spliced from byte ranges at serialize time.
    Spliced(SplicedMessages),
}

/// Decides whether preset prepend/append messages apply.
///
/// Preserves verbatim byte formatting of client elements while prepending system
/// messages and/or appending prefill messages if the last message has role="user".
/// Returns byte ranges instead of a materialized copy of the array.
/// Returns (splice, total_count, prepended_added, appended_added).
fn plan_messages_splice(
    body: Box<RawValue>,
    prepend_raw: Option<&str>,
    prepend_count: usize,
    append_raw: Option<&str>,
    append_count: usize,
) -> (MsgsSplice, usize, usize, usize) {
    let scan = match scan_json_array(body.get()) {
        Some(sc) => sc,
        None => return (MsgsSplice::Verbatim(body), 0, 0, 0),
    };
    let element_count = scan.element_count;
    let inner = scan.inner_start..scan.inner_end;
    // Append only applies when the conversation currently ends on a user turn.
    let last_is_user = append_raw.is_some()
        && scan
            .last_element
            .and_then(|elem| serde_json::from_str::<RoleCheck>(elem).ok())
            .and_then(|rc| rc.role.map(|r| r == "user"))
            .unwrap_or(false);

    if prepend_raw.is_none() && !last_is_user {
        return (MsgsSplice::Verbatim(body), element_count, 0, 0);
    }

    if element_count == 0 {
        // Empty client array `[]`: only a prepend can apply (no last role).
        return match prepend_raw {
            Some(prep) => (
                MsgsSplice::Spliced(SplicedMessages {
                    body,
                    inner,
                    prefix: Some(prep.to_string()),
                    suffix: None,
                }),
                prepend_count,
                prepend_count,
                0,
            ),
            None => (MsgsSplice::Verbatim(body), 0, 0, 0),
        };
    }

    let p_add = if prepend_raw.is_some() {
        prepend_count
    } else {
        0
    };
    let a_add = if last_is_user { append_count } else { 0 };

    if p_add == 0 && a_add == 0 {
        return (MsgsSplice::Verbatim(body), element_count, 0, 0);
    }

    let spliced = SplicedMessages {
        body,
        inner,
        prefix: prepend_raw.map(str::to_string),
        suffix: if last_is_user {
            append_raw.map(str::to_string)
        } else {
            None
        },
    };
    (
        MsgsSplice::Spliced(spliced),
        element_count + p_add + a_add,
        p_add,
        a_add,
    )
}

/// In-Content CoT Folding (`souffle_pout`):
/// Folds `reasoning_content` (or `reasoning`) into `content` as `<think>\n...\n</think>\n\n`
/// for assistant messages, while preserving user messages, non-assistant turns, and multi-modal text parts.
/// Returns Some(Box<RawValue>) if folded, or None if no folding occurred.
///
/// Byte-level splice: member spans are located by a quote/escape-aware scanner and
/// only the folded values are rewritten, so a 20-turn agent conversation no longer
/// pays 20 `serde_json::Map` parse -> mutate -> serialize round-trips.
fn fold_in_content_cot(msgs_raw: &str) -> Option<Box<RawValue>> {
    // 1. O(1) byte pre-scan: return None immediately if neither key exists
    if !msgs_raw.contains("\"reasoning_content\"") && !msgs_raw.contains("\"reasoning\"") {
        return None;
    }

    // 2. Borrow message elements as RawValue slices; only scan matching elements
    let raw_msgs: Vec<Box<RawValue>> = serde_json::from_str(msgs_raw).ok()?;
    let mut modified = false;

    // 3. Rebuild the array once: folded elements are spliced, the rest copied verbatim
    let mut out = String::with_capacity(msgs_raw.len() + 1024);
    out.push('[');
    for (i, slot) in raw_msgs.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        match fold_one_message(slot.get()) {
            Some(elem) => {
                out.push_str(&elem);
                modified = true;
            }
            None => out.push_str(slot.get()),
        }
    }
    out.push(']');

    if !modified {
        return None;
    }

    RawValue::from_string(out).ok()
}

const FOLD_THINK_OPEN: &str = "<think>";
const FOLD_THINK_CLOSE: &str = "</think>";

/// Byte spans of the members folding cares about, plus the object's closing brace.
struct MsgFieldSpans {
    role: Option<(usize, usize)>,
    content: Option<(usize, usize)>,
    reasoning_content: Option<(usize, usize)>,
    reasoning: Option<(usize, usize)>,
    obj_close: usize,
}

/// Walks the top-level members of a JSON object, handing each key (quotes included)
/// and its value span to `f`. Returns the index of the closing brace.
fn for_each_object_member(s: &str, mut f: impl FnMut(&str, usize, usize)) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if bytes.get(i) != Some(&b'{') {
        return None;
    }
    i += 1;
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        match *bytes.get(i)? {
            b'}' => return Some(i),
            b'"' => {}
            _ => return None,
        }
        let key_start = i;
        let key_end = scan_json_string_end(bytes, i)?;
        i = key_end;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if bytes.get(i) != Some(&b':') {
            return None;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let value_end = scan_json_value_end(bytes, i)?;
        f(s.get(key_start..key_end)?, i, value_end);
        i = value_end;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        match *bytes.get(i)? {
            b',' => i += 1,
            b'}' => return Some(i),
            _ => return None,
        }
    }
}

/// Walks the top-level elements of a JSON array, handing each element span to `f`.
fn for_each_array_element(s: &str, mut f: impl FnMut(usize, usize)) -> Option<()> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if bytes.get(i) != Some(&b'[') {
        return None;
    }
    i += 1;
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if *bytes.get(i)? == b']' {
            return Some(());
        }
        let end = scan_json_value_end(bytes, i)?;
        f(i, end);
        i = end;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        match *bytes.get(i)? {
            b',' => i += 1,
            b']' => return Some(()),
            _ => return None,
        }
    }
}

/// Member key with quotes stripped and escapes resolved. `Borrowed` when the key
/// has no escapes (the common case), so the scanner stays allocation-free.
fn decode_member_key(key: &str) -> Option<std::borrow::Cow<'_, str>> {
    if key.len() < 2 || !key.starts_with('"') || !key.ends_with('"') {
        return None;
    }
    let body = &key[1..key.len() - 1];
    if !body.contains('\\') {
        return Some(std::borrow::Cow::Borrowed(body));
    }
    serde_json::from_str::<String>(key)
        .ok()
        .map(std::borrow::Cow::Owned)
}

fn scan_message_spans(s: &str) -> Option<MsgFieldSpans> {
    let mut spans = MsgFieldSpans {
        role: None,
        content: None,
        reasoning_content: None,
        reasoning: None,
        obj_close: 0,
    };
    // Keys are compared in their DECODED form: "\u0063ontent" is the same member as
    // "content", and missing it would append a second content member while the
    // client's text (and any media) stayed under the escaped one.
    let mut duplicate = false;
    let obj_close = for_each_object_member(s, |key, vs, ve| {
        let Some(decoded) = decode_member_key(key) else {
            return;
        };
        let slot = match decoded.as_ref() {
            "role" => &mut spans.role,
            "content" => &mut spans.content,
            "reasoning_content" => &mut spans.reasoning_content,
            "reasoning" => &mut spans.reasoning,
            _ => return,
        };
        // Repeated key: rewriting only one occurrence would leave a duplicate that
        // still wins (or loses) on the far side. Leave the element untouched instead.
        if slot.is_some() {
            duplicate = true;
        }
        *slot = Some((vs, ve));
    })?;
    if duplicate {
        return None;
    }
    spans.obj_close = obj_close;
    Some(spans)
}

/// Byte length of the whitespace token at the head of `b`, or 0 if it is not
/// whitespace. Escape-aware so raw string bodies can be trimmed without decoding.
fn raw_ws_token_len(b: &[u8]) -> usize {
    match b.first() {
        Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r') => 1,
        Some(b'\\') => match b.get(1) {
            Some(b'n') | Some(b't') | Some(b'r') => 2,
            Some(b'u') if b.len() >= 6 => {
                let mut code = 0u32;
                let mut valid = true;
                for &c in &b[2..6] {
                    match (c as char).to_digit(16) {
                        Some(d) => code = code * 16 + d,
                        None => {
                            valid = false;
                            break;
                        }
                    }
                }
                if valid && matches!(code, 0x20 | 0x09 | 0x0a | 0x0d | 0x0c | 0x0b) {
                    6
                } else {
                    0
                }
            }
            _ => 0,
        },
        _ => 0,
    }
}

/// Equivalent of `str::trim_start` over raw JSON string content (escapes preserved).
fn raw_trim_start(s: &str) -> &str {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let n = raw_ws_token_len(&b[i..]);
        if n == 0 {
            break;
        }
        i += n;
    }
    &s[i..]
}

/// Equivalent of `str::trim_end` over raw JSON string content (escapes preserved).
fn raw_trim_end(s: &str) -> &str {
    let b = s.as_bytes();
    let mut i = 0;
    let mut end = 0;
    while i < b.len() {
        let n = raw_ws_token_len(&b[i..]);
        if n > 0 {
            i += n;
            continue;
        }
        let step = if b[i] == b'\\' {
            let want = if b.get(i + 1) == Some(&b'u') { 6 } else { 2 };
            want.min(b.len() - i)
        } else {
            1
        };
        i += step;
        end = i;
    }
    &s[..end]
}

fn raw_trim(s: &str) -> &str {
    raw_trim_end(raw_trim_start(s))
}

/// Inner bytes of a JSON string value (quotes stripped), or None for non-strings.
fn raw_string_body(src: &str, span: Option<(usize, usize)>) -> Option<&str> {
    let (vs, ve) = span?;
    let raw = src.get(vs..ve)?;
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        Some(&raw[1..raw.len() - 1])
    } else {
        None
    }
}

/// Text being folded, in one of two domains: `escaped` keeps the original JSON
/// escapes byte-for-byte (plain ASCII, spliced as-is), while a decoded value
/// holds real text that must be re-escaped on output. An escaped tag only looks
/// like `<​think>` once decoded, so a body carrying a backslash starts out decoded
/// — otherwise both the tag strip and the idempotency guard miss `\u003c`.
struct FoldText<'a> {
    text: std::borrow::Cow<'a, str>,
    escaped: bool,
}

impl<'a> FoldText<'a> {
    /// `body` is the inner text of a JSON string value (surrounding quotes stripped).
    fn from_body(body: &'a str) -> Self {
        // Decode when the body carries an escape or non-ASCII text: escapes need
        // resolving (so \u003c matches a literal tag), and Unicode whitespace such as
        // NBSP must be trimmable the way str::trim does it. Pure ASCII with no
        // backslash stays borrowed.
        if body.bytes().any(|b| b == b'\\' || b >= 0x80) {
            if let Some(decoded) = decode_json_string_body(body) {
                return Self::decoded(decoded);
            }
            // Undecodable (e.g. an unpaired surrogate): leave the bytes alone and
            // let the element-level check decide whether folding is safe.
        }
        Self::raw(body)
    }

    fn raw(text: &'a str) -> Self {
        Self {
            text: std::borrow::Cow::Borrowed(text),
            escaped: true,
        }
    }

    fn decoded(text: String) -> Self {
        Self {
            text: std::borrow::Cow::Owned(text),
            escaped: false,
        }
    }

    fn as_str(&self) -> &str {
        &self.text
    }

    /// Trim whitespace in this text's domain, over any slice of it.
    fn trim<'s>(&self, s: &'s str) -> &'s str {
        if self.escaped {
            raw_trim(s)
        } else {
            s.trim()
        }
    }

    fn trim_start<'s>(&self, s: &'s str) -> &'s str {
        if self.escaped {
            raw_trim_start(s)
        } else {
            s.trim_start()
        }
    }

    fn trim_end<'s>(&self, s: &'s str) -> &'s str {
        if self.escaped {
            raw_trim_end(s)
        } else {
            s.trim_end()
        }
    }

    /// Append a slice of this text as JSON string body bytes.
    fn write(&self, s: &str, out: &mut String) {
        if self.escaped {
            out.push_str(s);
        } else {
            escape_json_body_into(s, out);
        }
    }
}

/// Decode one JSON string body (quotes stripped). `None` when the escapes are not
/// valid JSON text, e.g. an unpaired surrogate.
fn decode_json_string_body(body: &str) -> Option<String> {
    let mut quoted = String::with_capacity(body.len() + 2);
    quoted.push('"');
    quoted.push_str(body);
    quoted.push('"');
    serde_json::from_str(&quoted).ok()
}

/// Append `s` as JSON string body bytes (no surrounding quotes).
fn escape_json_body_into(s: &str, out: &mut String) {
    // serde_json cannot fail on a &str; dropping the quotes lets the escaped text
    // splice into an existing string value.
    if let Ok(quoted) = serde_json::to_string(s) {
        out.push_str(&quoted[1..quoted.len() - 1]);
    }
}

/// `<​think>\n{rc}\n<​/think>` written as JSON string body.
fn push_think_block(out: &mut String, rc: &FoldText<'_>, rc_text: &str) {
    out.push_str(FOLD_THINK_OPEN);
    out.push_str("\\n");
    rc.write(rc_text, out);
    out.push_str("\\n");
    out.push_str(FOLD_THINK_CLOSE);
}

fn quote_json_string(body: &str) -> String {
    let mut s = String::with_capacity(body.len() + 2);
    s.push('"');
    s.push_str(body);
    s.push('"');
    s
}

/// Classifies an array content part: `Some(Some(body))` is a text part carrying
/// string text, `Some(None)` a text part whose `text` is not a string, `None` a
/// non-text part (image_url, input_audio, ...) that must be carried verbatim.
fn part_text_body(part: &str) -> Option<Option<&str>> {
    if part.len() >= 2 && part.starts_with('"') && part.ends_with('"') {
        return Some(Some(&part[1..part.len() - 1]));
    }
    if !part.starts_with('{') {
        return None;
    }
    let mut found = None;
    for_each_object_member(part, |key, vs, ve| {
        if key == "\"text\"" {
            let raw = &part[vs..ve];
            found = Some(
                if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
                    Some(&raw[1..raw.len() - 1])
                } else {
                    None
                },
            );
        }
    })?;
    found
}

/// Folds array content: text parts are concatenated and become the first text
/// part; every non-text part is re-emitted verbatim so media is never dropped.
fn fold_array_content(raw: &str, rc: &FoldText<'_>, rc_text: &str) -> Option<String> {
    let mut bodies: Vec<&str> = Vec::new();
    let mut media: Vec<&str> = Vec::new();
    for_each_array_element(raw, |vs, ve| {
        let part = &raw[vs..ve];
        match part_text_body(part) {
            Some(Some(body)) => bodies.push(body),
            Some(None) => {}
            None => media.push(part),
        }
    })?;

    // Joining raw bodies only stays valid while every part is plain ASCII: one
    // escaped part would leave the joined text half-decoded.
    let text = if bodies.iter().any(|b| b.bytes().any(|c| c == b'\\')) {
        let mut decoded = String::with_capacity(bodies.iter().map(|b| b.len()).sum());
        for body in &bodies {
            decoded.push_str(&decode_json_string_body(body)?);
        }
        FoldText::decoded(decoded)
    } else {
        FoldText::decoded(bodies.concat())
    };

    let trimmed = text.trim_start(text.as_str());
    if trimmed.starts_with(FOLD_THINK_OPEN) {
        return None;
    }

    let mut body = String::with_capacity(text.as_str().len() + rc_text.len() + 16);
    push_think_block(&mut body, rc, rc_text);
    if !text.trim(text.as_str()).is_empty() {
        body.push_str("\\n\\n");
        text.write(trimmed, &mut body);
    }

    let cap = body.len() + 32 + media.iter().map(|m| m.len() + 1).sum::<usize>();
    let mut out = String::with_capacity(cap);
    out.push_str("[{\"type\":\"text\",\"text\":\"");
    out.push_str(&body);
    out.push_str("\"}");
    for m in media {
        out.push(',');
        out.push_str(m);
    }
    out.push(']');
    Some(out)
}

/// The reasoning text of a message (preferred key first, whitespace-only values
/// skipped), decoded once into the domain folding needs.
fn pick_reasoning<'a>(elem: &'a str, spans: &MsgFieldSpans) -> Option<FoldText<'a>> {
    for span in [spans.reasoning_content, spans.reasoning] {
        let Some(body) = raw_string_body(elem, span) else {
            continue;
        };
        let text = FoldText::from_body(body);
        if !text.trim(text.as_str()).is_empty() {
            return Some(text);
        }
    }
    None
}

/// Rewrites one message element in place. Returns None when the element is not a
/// foldable assistant turn (non-assistant, no reasoning, or already folded).
fn fold_one_message(elem: &str) -> Option<String> {
    if !elem.contains("assistant")
        || (!elem.contains("\"reasoning_content\"") && !elem.contains("\"reasoning\""))
    {
        return None;
    }

    // Escaped elements get one validation pass: an unpaired surrogate (or any other
    // invalid escape) would otherwise be re-emitted verbatim as invalid JSON. Only
    // elements that actually carry a \u escape pay for this.
    if elem.contains("\\u") && serde_json::from_str::<Value>(elem).is_err() {
        return None;
    }

    let spans = scan_message_spans(elem)?;

    let (role_start, role_end) = spans.role?;
    if elem.get(role_start..role_end)? != "\"assistant\"" {
        return None;
    }

    // Non-empty reasoning, preferring "reasoning_content" over "reasoning".
    let rc_text = pick_reasoning(elem, &spans)?;

    // Inner Tag Strip Guard: drop outer <​think> / <​/think> the model already added.
    // Running it in the text's own domain is what makes `\u003cthink\u003e` match.
    let mut rc = rc_text.trim(rc_text.as_str());
    if let Some(rest) = rc.strip_prefix(FOLD_THINK_OPEN) {
        rc = rc_text.trim_start(rest);
    }
    if let Some(rest) = rc.strip_suffix(FOLD_THINK_CLOSE) {
        rc = rc_text.trim_end(rest);
    }
    let rc = rc_text.trim(rc);
    if rc.is_empty() {
        return None;
    }

    let content_span = spans.content;
    let content_raw = match content_span {
        Some((vs, ve)) => elem.get(vs..ve)?,
        None => "",
    };

    // 5. Idempotency guard + 6. build the folded value
    let new_value = match (content_span, content_raw) {
        (None, _) | (_, "null") => {
            // Null or absent content (e.g. tool call turns)
            let mut body = String::with_capacity(rc.len() + 16);
            push_think_block(&mut body, &rc_text, rc);
            quote_json_string(&body)
        }
        (_, raw) if raw.starts_with('"') => {
            let body = &raw[1..raw.len() - 1];
            let content = FoldText::from_body(body);
            let trimmed = content.trim_start(content.as_str());
            if trimmed.starts_with(FOLD_THINK_OPEN) {
                return None;
            }
            let mut s = String::with_capacity(body.len() + rc.len() + 16);
            push_think_block(&mut s, &rc_text, rc);
            if !content.trim(content.as_str()).is_empty() {
                s.push_str("\\n\\n");
                content.write(trimmed, &mut s);
            }
            quote_json_string(&s)
        }
        (_, raw) if raw.starts_with('[') => fold_array_content(raw, &rc_text, rc)?,
        (_, raw) => {
            let trimmed = raw_trim_start(raw);
            if trimmed.starts_with(FOLD_THINK_OPEN) {
                return None;
            }
            // Non-string scalar/object content still folds into a *string*. Decode the
            // JSON value first (escapes resolved, numbers normalised) so the text the
            // model sees matches the pre-splice behaviour, then escape it for embedding.
            let value: Value = serde_json::from_str(trimmed).ok()?;
            let as_text = value.to_string();
            let escaped = serde_json::to_string(&as_text).ok()?;
            let mut s = String::with_capacity(escaped.len() + rc.len() + 16);
            push_think_block(&mut s, &rc_text, rc);
            s.push_str("\\n\\n");
            s.push_str(&escaped[1..escaped.len() - 1]);
            quote_json_string(&s)
        }
    };

    // 7. Schema normalization: blank the reasoning keys the element actually carried.
    // Injecting reasoning_content into a message that never had one can trip strict
    // OpenAI-compatible schema validators, so absent keys stay absent.
    let mut edits: Vec<(usize, usize, String)> = Vec::with_capacity(4);
    let cap = elem.len() + new_value.len() + 16;
    match content_span {
        Some((vs, ve)) => edits.push((vs, ve, new_value)),
        None => edits.push((
            spans.obj_close,
            spans.obj_close,
            format!(",\"content\":{}", new_value),
        )),
    }
    if let Some((vs, ve)) = spans.reasoning_content {
        edits.push((vs, ve, "\"\"".to_string()));
    }
    if let Some((vs, ve)) = spans.reasoning {
        edits.push((vs, ve, "\"\"".to_string()));
    }
    edits.sort_by_key(|e| e.0);

    let mut out = String::with_capacity(cap);
    let mut cursor = 0;
    for (start, end, repl) in &edits {
        if *start < cursor || *end > elem.len() || start > end {
            return None;
        }
        out.push_str(elem.get(cursor..*start)?);
        out.push_str(repl);
        cursor = *end;
    }
    out.push_str(elem.get(cursor..)?);
    Some(out)
}

/// Helper function to estimate serialized JSON capacity for upstream payloads.
/// Sums `k.len() + v.get().len() + 4` over the map, adds 34 base (2 delimiters + 32 slack),
/// plus 16384 if cot_active else 1024.
pub fn estimate_payload_capacity(
    payload: &BTreeMap<String, Box<RawValue>>,
    cot_active: bool,
) -> usize {
    let base: usize =
        2 + payload.iter().map(|(k, v)| k.len() + v.get().len() + 4).sum::<usize>() + 32;
    if cot_active {
        base + 16384
    } else {
        base + 1024
    }
}

/// The chat-completions request payload on its way upstream.
struct UpstreamPayload {
    map: BTreeMap<String, Box<RawValue>>,
    /// Present when preset prepend/append applies: `messages` lives here instead
    /// of in `map` so the array is emitted from byte ranges, not a copy.
    spliced_messages: Option<SplicedMessages>,
}

impl UpstreamPayload {
    #[cfg(test)]
    fn new(map: BTreeMap<String, Box<RawValue>>) -> Self {
        Self {
            map,
            spliced_messages: None,
        }
    }

    /// Serialize payload directly into the pre-allocated buffer without reallocations.
    fn serialize_into(&self, buf: &mut Vec<u8>) -> Result<(), serde_json::Error> {
        let Some(messages) = &self.spliced_messages else {
            return serde_json::to_writer(buf, &self.map);
        };
        // Hand-emit so `messages` keeps the exact slot serde_json would give it
        // in BTreeMap order (byte-identical output) while its array is written
        // from ranges rather than a materialized String.
        buf.push(b'{');
        let mut first = true;
        let mut messages_done = false;
        for (k, v) in &self.map {
            if k == "messages" {
                continue;
            }
            if !messages_done && k.as_str() > "messages" {
                push_member_sep(buf, &mut first);
                buf.extend_from_slice(b"\"messages\":");
                messages.emit_into(buf);
                messages_done = true;
            }
            push_member_sep(buf, &mut first);
            serde_json::to_writer(&mut *buf, k)?;
            buf.push(b':');
            buf.extend_from_slice(v.get().as_bytes());
        }
        if !messages_done {
            push_member_sep(buf, &mut first);
            buf.extend_from_slice(b"\"messages\":");
            messages.emit_into(buf);
        }
        buf.push(b'}');
        Ok(())
    }

    /// Estimated serialized length of the payload in JSON format.
    #[allow(dead_code)]
    pub fn estimated_len(&self) -> usize {
        2 + self
            .map
            .iter()
            .map(|(k, v)| k.len() + v.get().len() + 4)
            .sum::<usize>()
            + self
                .spliced_messages
                .as_ref()
                .map_or(0, SplicedMessages::estimated_len)
    }

    /// Pre-allocated buffer capacity taking into account CoT expansion.
    pub fn estimated_capacity(&self, cot_active: bool) -> usize {
        estimate_payload_capacity(&self.map, cot_active)
            + self
                .spliced_messages
                .as_ref()
                .map_or(0, SplicedMessages::estimated_len)
    }

    /// Force `model` on multi-model retry rotation.
    fn rewrite_model(&mut self, model_raw: &RawValue) {
        self.map.insert("model".to_string(), model_raw.to_owned());
    }
}

/// Append `,` between object members.
fn push_member_sep(buf: &mut Vec<u8>, first: &mut bool) {
    if *first {
        *first = false;
    } else {
        buf.push(b',');
    }
}

// ---------------------------------------------------------------------------
// Outbound body compression (upload-throttle mitigation, 2026-10-08)
// ---------------------------------------------------------------------------
// The box->relay uplink is the bottleneck (~4.7 KB/s measured on this route:
// a 200KB body uploads for ~43s, and with generation time on top the relay's
// Cloudflare edge hits its 100s proxy window -> 524). Brotli-compressing the
// serialized JSON before it touches the link cuts upload bytes ~3.5x (live
// probe 2026-10-08: upstream decodes Content-Encoding: br request bodies
// correctly; authentic 224KB body -> 63.5KB wire (28.3% at q9)).
// The response direction is untouched — download is not throttled, and the
// SSE scan path must keep seeing plaintext.
struct OutboundBody {
    bytes: Bytes,
    is_brotli: bool,
}

/// Adaptive sliding window size for brotli compression:
/// Smooth 1-bit progression (2x steps) using branchless next_power_of_two,
/// clamped between floor 14 (16KB) and ceiling 22 (4MB).
/// For a 400k-token payload (~1.9MB), next_power_of_two resolves to 2MB (21 bits) snugly,
/// saving 50% hasher RAM compared to a flat 4MB window.
fn brotli_window_bits_for(raw_len: usize) -> u8 {
    raw_len
        .max(16 * 1024)
        .next_power_of_two()
        .trailing_zeros()
        .clamp(14, 22) as u8
}

// Kept as an unbounded lock-free `thread_local!`: Tokio worker thread count is fixed at
// startup, so TLS slots are bounded by worker count without mutex contention or RSS runaway.
thread_local! {
    static THREAD_BROTLI_COMPRESSOR: std::cell::RefCell<Option<mbrotli::Compressor>> =
        const { std::cell::RefCell::new(None) };
}

/// Synchronous brotli encode via `mbrotli` with lock-free thread-local compressor reuse:
/// Adaptive sliding window (16KB..4MB), CompressionMode::Generic, LiteralContextMode::Auto, BlockSize::Auto.
///
/// Returns:
/// - `Ok(Some(compressed))` when compression shrinks the body.
/// - `Ok(None)` when the compressed output is >= the input (expansion guard).
/// - `Err(msg)` on a real encoder error (config validation, allocation failure).
fn brotli_compress_bytes(data: &[u8], quality: i32) -> Result<Option<Vec<u8>>, String> {
    let q = mbrotli::Quality::try_from(quality.clamp(0, 11) as u8)
        .map_err(|e| format!("invalid quality {quality}: {e}"))?;
    let window_bits = brotli_window_bits_for(data.len());
    let window = mbrotli::Window::standard(window_bits)
        .map_err(|e| format!("invalid window {window_bits}: {e}"))?;
    let config = mbrotli::EncoderConfig::default()
        .with_quality(q)
        .with_window(window)
        .with_mode(mbrotli::CompressionMode::Generic)
        .with_literal_context(mbrotli::LiteralContextMode::Auto)
        .with_block_size(mbrotli::BlockSize::Auto);

    THREAD_BROTLI_COMPRESSOR.with(|cell| {
        let mut borrow = cell.borrow_mut();
        let compressor = match borrow.as_mut() {
            Some(comp) => {
                if *comp.config() != config {
                    comp.reconfigure(config)
                        .map_err(|e| format!("compressor reconfigure: {e}"))?;
                }
                comp
            }
            None => {
                let comp = mbrotli::Compressor::new(config)
                    .map_err(|e| format!("compressor init: {e}"))?;
                *borrow = Some(comp);
                borrow.as_mut().unwrap()
            }
        };

        let mut out_buf = Vec::with_capacity(data.len() / 2);
        compressor
            .compress_into(data, &mut out_buf)
            .map_err(|e| format!("encode: {e}"))?;

        if out_buf.len() < data.len() {
            Ok(Some(out_buf))
        } else {
            Ok(None)
        }
    })
}

/// Effective outbound-brotli quality for a body of `raw_len` bytes.
///
/// Physical Rationale for q10 Escalation on Throttled WAN Relays:
/// Upstream relay connections are severely bandwidth-throttled (~11-14 KB/s measured upload
/// throughput), making wire serialization the overwhelming bottleneck rather than compression CPU.
/// On an ~12 KB/s uplink, every 1 KB eliminated from the payload saves ~83ms of serialized upload time.
/// Powered by `mbrotli` with AVX-512 vectorization:
/// - <256KB: base quality (default q9, ~20ms CPU).
/// - \>=256KB: escalates to max(base, 10). On a ~3MB JSON body, q10 consumes ~200ms CPU in a
///   spawn_blocking pool while eliminating an additional ~8-12 KB of wire payload compared to q9.
///   At 12 KB/s wire speed, saving ~8-12 KB shaves ~670-1000ms of upload latency, netting an
///   end-to-end speedup of ~500ms+ before upstream finishes receiving the request body.
///
/// Quality is strictly clamped to max q10: q11 adds ~190ms of additional CPU time to shave <1KB wire,
/// which crosses the break-even threshold and produces negative net latency.
/// Thus, maintaining q10 for bodies \>= 256KB is physically optimal for throttled WAN links.
/// Do NOT lower this behavior or threshold.
fn brotli_level_for(base_level: i32, raw_len: usize) -> i32 {
    let base = base_level.clamp(0, 10);
    if raw_len >= 256 * 1024 {
        base.max(10)
    } else {
        base
    }
}

/// Compress the outbound JSON once per (re)serialization. Runs on
/// spawn_blocking so the encode CPU (mbrotli q9 ~20ms, q10 ~200ms on 3MB)
/// never stalls a tokio worker.
async fn prep_outbound_body(config: &Config, json_bytes: Bytes, req_id: &str) -> OutboundBody {
    let raw_len = json_bytes.len();
    if !config.brotli_enabled || raw_len < config.brotli_min_bytes {
        return OutboundBody {
            bytes: json_bytes,
            is_brotli: false,
        };
    }
    // Automatic size escalation (owner ruling 2026-10-08): bigger bodies
    // get HIGHER quality — the relay throttles uploads (13-14 KB/s
    // owner-measured), so encode CPU hides behind throttle-bound upload.
    let level = brotli_level_for(config.brotli_level, raw_len);
    let t = Instant::now();
    let input = json_bytes.clone();
    let joined = tokio::task::spawn_blocking(move || brotli_compress_bytes(&input, level)).await;
    match joined {
        Ok(Ok(Some(comp))) => {
            let raw_kb = raw_len as f64 / 1024.0;
            let comp_kb = comp.len() as f64 / 1024.0;
            log(
                &format!(
                    "Brotli q{level}: {:.1}KB -> {:.1}KB ({:.1}%) in {}ms",
                    raw_kb,
                    comp_kb,
                    100.0 * comp.len() as f64 / raw_len as f64,
                    t.elapsed().as_millis()
                ),
                Some(req_id),
            );
            OutboundBody {
                bytes: Bytes::from(comp),
                is_brotli: true,
            }
        }
        // Expansion guard: compressed output >= input, send raw (expected for
        // small or incompressible bodies, not worth logging).
        Ok(Ok(None)) => OutboundBody {
            bytes: json_bytes,
            is_brotli: false,
        },
        // Encoder error (config validation, allocation failure): log and fall
        // back to raw — the request can still succeed uncompressed.
        Ok(Err(e)) => {
            log(
                &format!("Brotli encode error (falling back to raw): {e}"),
                Some(req_id),
            );
            OutboundBody {
                bytes: json_bytes,
                is_brotli: false,
            }
        }
        // spawn_blocking panic: serious — the compressor thread crashed.
        Err(join_err) => {
            log(
                &format!("Brotli spawn_blocking panic (falling back to raw): {join_err}"),
                Some(req_id),
            );
            OutboundBody {
                bytes: json_bytes,
                is_brotli: false,
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_upstream(
    state: Arc<AppState>,
    preset: Arc<PresetRuntime>,
    mut payload: UpstreamPayload,
    _raw_len: usize,
    is_stream: bool,
    req_id: String,
    t_start: Instant,
    permit: OwnedSemaphorePermit,
    active_guard: ActiveRequestGuard,
    options: responses::RequestOptions,
) -> Response {
    let cot_active = preset.config.souffle_pout
        || preset.config.prepend_raw.is_some()
        || preset.config.append_raw.is_some();
    let mut buf = Vec::with_capacity(payload.estimated_capacity(cot_active));
    let mut payload_bytes = match payload.serialize_into(&mut buf) {
        Ok(()) => Bytes::from(buf),
        Err(e) => {
            state.stats.error_count.fetch_add(1, Ordering::Relaxed);
            return make_text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("JSON serialize error: {}", e),
            );
        }
    };

    // Compress the outbound body once; retries only patch the model literal,
    // so a re-encode happens only when that literal really changed.
    let mut outbound = prep_outbound_body(&preset.config, payload_bytes.clone(), &req_id).await;

    let send_timeout = preset.config.read_timeout;
    let mut attempt = 0;
    // Bound on "free" (no-attempt-cost) immediate retries. A REFUSED_STREAM or a
    // GOAWAY NO_ERROR is a cheap expected reconnect rather than a real attempt
    // failure, so these branches deliberately do not consume the attempt budget.
    // They MUST still be capped: a persistently-resetting upstream would otherwise
    // spin here forever (~10ms apart) while holding this request's semaphore permit.
    const MAX_FREE_RETRIES: u32 = 8;
    let mut free_retries: u32 = 0;

    // A native Responses request may execute hosted tools before a transport
    // failure. Never silently resubmit an ambiguously accepted generation.
    let max_retry = if options.operation.native() {
        1
    } else {
        preset.config.max_retry
    };

    while attempt < max_retry {
        let t_dispatch = Instant::now();
        if attempt > 0 && preset.config.models.len() > 1 {
            let next_idx =
                preset.model_index.fetch_add(1, Ordering::Relaxed) % preset.config.models.len();
            let next_model = &preset.config.models[next_idx];
            let next_model_raw = &preset.config.models_raw[next_idx];
            // A rotation only swaps the top-level model literal, so splice that
            // span in the already-serialized body instead of re-serializing (and
            // re-brotli'ing) multi-MB JSON on every retry under the permit.
            match patch_serialized_model(&payload_bytes, next_model_raw.get()) {
                ModelPatch::Unchanged => {}
                ModelPatch::Replaced(patched) => {
                    payload_bytes = patched;
                    // Brotli output is content-dependent, so a changed literal
                    // always invalidates it (identical literals took the
                    // Unchanged arm above and keep the old encode).
                    outbound = if preset.config.brotli_enabled {
                        prep_outbound_body(&preset.config, payload_bytes.clone(), &req_id).await
                    } else {
                        OutboundBody {
                            bytes: payload_bytes.clone(),
                            is_brotli: false,
                        }
                    };
                }
                // Body shape not recognized: fall back to a full re-serialize.
                ModelPatch::NotFound => {
                    payload.rewrite_model(next_model_raw);
                    let mut buf = Vec::with_capacity(payload.estimated_capacity(cot_active));
                    if payload.serialize_into(&mut buf).is_ok() {
                        payload_bytes = Bytes::from(buf);
                        outbound =
                            prep_outbound_body(&preset.config, payload_bytes.clone(), &req_id).await;
                    }
                }
            }
            log(
                &format!(
                    "Retrying attempt {}/{} with alternative model: {} (preset '{}', model {}/{})",
                    attempt + 1,
                    preset.config.max_retry,
                    next_model,
                    preset.config.preset_name,
                    next_idx + 1,
                    preset.config.models.len()
                ),
                Some(&req_id),
            );
        } else if attempt > 0 || log_verbose() {
            // Normal verbosity: attempt 1 is silent; retries stay visible.
            log(
                &format!(
                    "Dispatching attempt {}/{} ({}). Waiting for response headers...",
                    attempt + 1,
                    preset.config.max_retry,
                    preset.client.transport_name()
                ),
                Some(&req_id),
            );
        }

        let target = preset.client.current_target();

        let auth_hdr = {
            let hdrs = &preset.config.auth_headers;
            let idx = preset.key_index.fetch_add(1, Ordering::Relaxed) % hdrs.len();
            hdrs[idx].clone()
        };

        let uri = match options.uri(target) {
            Ok(uri) => uri,
            Err(message) => return make_error_response(StatusCode::BAD_REQUEST, &message),
        };
        let user_agent = if options.operation.native() {
            options
                .headers
                .get(header::USER_AGENT)
                .cloned()
                .unwrap_or_else(|| HeaderValue::from_static("souffle_proxy"))
        } else {
            HeaderValue::from_static("curl/8.0.0")
        };
        let mut req_builder = http::Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::AUTHORIZATION, auth_hdr)
            .header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )
            .header(
                header::ACCEPT,
                if is_stream {
                    HeaderValue::from_static("text/event-stream")
                } else {
                    HeaderValue::from_static("application/json")
                },
            )
            .header(header::USER_AGENT, user_agent)
            .header("X-Accel-Buffering", HeaderValue::from_static("no"))
            .header(
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-cache, no-store, must-revalidate"),
            )
            .header("CDN-Cache-Control", HeaderValue::from_static("no-store"))
            .header(
                "Cloudflare-CDN-Cache-Control",
                HeaderValue::from_static("no-store"),
            )
            .header(header::PRAGMA, HeaderValue::from_static("no-cache"))
            .header(header::EXPIRES, HeaderValue::from_static("0"));

        if options.operation.native() {
            req_builder = req_builder.header(
                header::ACCEPT_ENCODING,
                HeaderValue::from_static("identity"),
            );
            for (name, value) in &options.headers {
                if name != header::USER_AGENT {
                    req_builder = req_builder.header(name, value);
                }
            }
        }

        req_builder = req_builder.header(
            header::CONTENT_LENGTH,
            HeaderValue::from(outbound.bytes.len() as u64),
        );

        if outbound.is_brotli {
            req_builder =
                req_builder.header(header::CONTENT_ENCODING, HeaderValue::from_static("br"));
        }

        let mut req = match req_builder.body(outbound.bytes.clone()) {
            Ok(r) => r,
            Err(e) => {
                state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                return make_text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Build request error: {}", e),
                );
            }
        };
        // One late replacement point covers built-in, caller/native, framing and
        // compression headers for every operation and transport.
        preset.config.extra_headers.apply(req.headers_mut());

        let send_res = tokio::time::timeout(send_timeout, preset.client.send_stream(req)).await;
        // Native responses retain their own error envelopes, headers and retry
        // semantics. Nothing below this branch may inspect or replay them as chat.
        if options.operation.native() {
            return match send_res {
                Ok(Ok(response)) => {
                    let header_latency = t_dispatch.elapsed().as_secs_f64();
                    let token_timing = Arc::new(FirstTokenTiming::new(t_start));
                    responses::forward(
                        response.status,
                        response.headers,
                        response.body,
                        state.clone(),
                        preset.clone(),
                        options.operation,
                        is_stream,
                        req_id,
                        header_latency,
                        token_timing,
                        t_start,
                        permit,
                        active_guard,
                    )
                    .await
                }
                Ok(Err(error)) => {
                    if let Some(conn_id) = error.conn_id {
                        if !is_terminal_upstream_error(&error.error) {
                            if error.error.is_stream_scoped() {
                                preset.client.invalidate_stream_if_same(conn_id).await;
                            } else {
                                preset.client.invalidate_if_same(conn_id).await;
                            }
                        }
                    }
                    state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                    make_error_response(
                        StatusCode::BAD_GATEWAY,
                        &format!("Responses upstream transport failed: {}", error.error),
                    )
                }
                Err(_) => {
                    state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                    make_error_response(
                        StatusCode::GATEWAY_TIMEOUT,
                        "Responses upstream request timed out",
                    )
                }
            };
        }
        match send_res {
            Ok(Ok(upstream_resp)) => {
                let conn_id = upstream_resp.conn_id;
                let status = upstream_resp.status;
                let status_u16 = status.as_u16();
                let header_latency = t_dispatch.elapsed().as_secs_f64();

                // Retryable upstream statuses. Matches the Python shim's set:
                // 429/500-504/524 plus 522 (CF could not reach the origin) and
                // 529 (origin overloaded) -- both are transient, not client errors.
                if is_retryable_upstream_status(status_u16) && attempt < max_retry - 1 {
                    let err_preview = match tokio::time::timeout(
                        ERROR_BODY_TIMEOUT,
                        upstream_resp.body.read_full_limited(ERROR_BODY_CAP),
                    )
                    .await
                    {
                        Ok(Ok(b)) => {
                            let s = String::from_utf8_lossy(&b);
                            s.chars().take(200).collect::<String>()
                        }
                        _ => String::from("<unable to read body>"),
                    };
                    log(
                        &format!("Upstream HTTP {}: {}", status_u16, err_preview),
                        Some(&req_id),
                    );
                    let delay = retry_delay(attempt);
                    log(
                        &format!("Auto-retry in {:.1}s...", delay.as_secs_f64()),
                        Some(&req_id),
                    );
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }

                // If fatal error >= 400
                if status_u16 >= 400 {
                    let err_body = tokio::time::timeout(
                        ERROR_BODY_TIMEOUT,
                        upstream_resp.body.read_full_limited(ERROR_BODY_CAP),
                    )
                    .await
                    .ok()
                    .and_then(|r| r.ok())
                    .unwrap_or_default();
                    let s = String::from_utf8_lossy(&err_body);
                    let preview = s.chars().take(500).collect::<String>();
                    // Cloudflare's edge codes (520-527) are non-standard and carry an HTML
                    // interstitial rather than a JSON error. Translate them to a standard
                    // 504 Gateway Timeout so the client gets a parseable, semantically
                    // correct answer (524 = proxy read timeout, 522 = origin unreachable).
                    let cf_edge = (520..=527).contains(&status_u16);
                    let client_status = if cf_edge {
                        StatusCode::GATEWAY_TIMEOUT
                    } else {
                        StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_GATEWAY)
                    };
                    log(
                        &format!(
                            "Upstream HTTP {} (final){}. Returning JSON error.",
                            status_u16,
                            if cf_edge {
                                " -> 504 upstream_timeout"
                            } else {
                                ""
                            }
                        ),
                        Some(&req_id),
                    );
                    state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                    let err_json = json!({
                        "error": {
                            "message": if cf_edge {
                                format!("Upstream timed out (Cloudflare {}): the relay did not respond in time.", status_u16)
                            } else {
                                format!("Upstream HTTP {}: {}", status_u16, preview)
                            },
                            "type": if cf_edge { "upstream_timeout" } else { "upstream_error" },
                            "code": client_status.as_u16().to_string(),
                        }
                    });
                    return make_json_response(client_status, err_json);
                }

                let token_timing = Arc::new(FirstTokenTiming::new(t_start));

                let upstream_status = upstream_resp.status;
                let upstream_headers = upstream_resp.headers;
                let upstream_version = upstream_resp.version;

                if is_stream {
                    let mut stream = upstream_resp.body;

                    // Peek first chunk with per-read idle timeout
                    let first_chunk_res =
                        tokio::time::timeout(preset.config.read_timeout, stream.next()).await;
                    let first_chunk = match first_chunk_res {
                        Ok(Some(Ok(c))) => c,
                        Ok(Some(Err(e))) => {
                            // Classify once: a per-stream reset must not tear down the
                            // shared connection and the other requests riding it.
                            let stream_scoped = e.is_stream_scoped();
                            match e {
                                UpstreamError::H2StreamReset { error_code: 7 }
                                | UpstreamError::H3StreamReset { error_code: 0x010b } => {
                                    // REFUSED_STREAM / H3_REQUEST_REJECTED → retry immediately, no backoff, no attempt cost
                                    if free_retries < MAX_FREE_RETRIES {
                                        free_retries += 1;
                                        log(&format!("Upstream stream reset (error=REFUSED/REJECTED). Retrying immediately (free retry {}/{})...", free_retries, MAX_FREE_RETRIES), Some(&req_id));
                                        // Stream-scoped: the connection is healthy, leave concurrent responses alone.
                                        preset.client.invalidate_stream_if_same(conn_id).await;
                                        drop(stream);
                                        tokio::time::sleep(Duration::from_millis(10)).await;
                                        continue;
                                    }
                                    log(&format!("Upstream stream reset (REFUSED/REJECTED) free-retry budget exhausted after {} tries", MAX_FREE_RETRIES), Some(&req_id));
                                    state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                                    return make_text_response(
                                        StatusCode::BAD_GATEWAY,
                                        "Upstream REFUSED_STREAM / H3_REQUEST_REJECTED retry budget exhausted",
                                    );
                                }
                                UpstreamError::H2StreamReset { error_code: 8 }
                                | UpstreamError::H3StreamReset { error_code: 0x010c } => {
                                    // CANCEL / H3_REQUEST_CANCELLED → retry with normal backoff
                                    log(
                                        "Upstream stream reset (error=CANCEL / H3_REQUEST_CANCELLED)",
                                        Some(&req_id),
                                    );
                                    preset.client.invalidate_stream_if_same(conn_id).await;
                                    if attempt < max_retry - 1 {
                                        drop(stream);
                                        let delay = retry_delay(attempt);
                                        log(
                                            &format!(
                                                "Auto-retry in {:.1}s...",
                                                delay.as_secs_f64()
                                            ),
                                            Some(&req_id),
                                        );
                                        tokio::time::sleep(delay).await;
                                        attempt += 1;
                                        continue;
                                    } else {
                                        state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                                        return make_text_response(
                                            StatusCode::BAD_GATEWAY,
                                            "Upstream stream reset CANCEL exhausted",
                                        );
                                    }
                                }
                                UpstreamError::H2GoAway { error_code: 0, .. }
                                | UpstreamError::H3GoAway { error_code: 0x0100 }
                                | UpstreamError::H3GoAway { error_code: 0 } => {
                                    // GOAWAY NO_ERROR / H3_NO_ERROR → reconnect on a fresh connection, no backoff, no attempt cost
                                    if free_retries < MAX_FREE_RETRIES {
                                        free_retries += 1;
                                        log(&format!("Upstream GOAWAY (error=NO_ERROR). Reconnecting immediately (free retry {}/{})...", free_retries, MAX_FREE_RETRIES), Some(&req_id));
                                        preset.client.invalidate_if_same(conn_id).await;
                                        drop(stream);
                                        continue;
                                    }
                                    log(&format!("Upstream GOAWAY (NO_ERROR) free-retry budget exhausted after {} tries", MAX_FREE_RETRIES), Some(&req_id));
                                    state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                                    return make_text_response(
                                        StatusCode::BAD_GATEWAY,
                                        "Upstream GOAWAY retry budget exhausted",
                                    );
                                }
                                UpstreamError::H2GoAway { error_code: 11, .. }
                                | UpstreamError::H3StreamReset { error_code: 0x0107 }
                                | UpstreamError::H3GoAway { error_code: 0x0107 } => {
                                    // GOAWAY ENHANCE_YOUR_CALM / H3_EXCESSIVE_LOAD → retry with 2x backoff
                                    log("Upstream overloaded (error=ENHANCE_YOUR_CALM / H3_EXCESSIVE_LOAD). Backing off 2x...", Some(&req_id));
                                    if stream_scoped {
                                        preset.client.invalidate_stream_if_same(conn_id).await;
                                    } else {
                                        preset.client.invalidate_if_same(conn_id).await;
                                    }
                                    if attempt < max_retry - 1 {
                                        drop(stream);
                                        let delay = retry_delay(attempt) * 2;
                                        log(
                                            &format!("Auto-retry in {:.1}s...", delay.as_secs_f64()),
                                            Some(&req_id),
                                        );
                                        tokio::time::sleep(delay).await;
                                        attempt += 1;
                                        continue;
                                    } else {
                                        state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                                        return make_text_response(
                                            StatusCode::BAD_GATEWAY,
                                            "Upstream overloaded (ENHANCE_YOUR_CALM / H3_EXCESSIVE_LOAD) exhausted",
                                        );
                                    }
                                }
                                UpstreamError::H3GoAway { error_code } => {
                                    log(
                                        &format!("Upstream H3 GOAWAY (error_code={:#x})", error_code),
                                        Some(&req_id),
                                    );
                                    preset.client.invalidate_if_same(conn_id).await;
                                    state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                                    return make_text_response(
                                        StatusCode::BAD_GATEWAY,
                                        &format!("Upstream H3 GOAWAY error_code={:#x}", error_code),
                                    );
                                }
                                UpstreamError::H2GoAway { error_code, .. } => {
                                    // Other GOAWAY → do not retry, surface error
                                    log(
                                        &format!("Upstream GOAWAY (error_code={})", error_code),
                                        Some(&req_id),
                                    );
                                    preset.client.invalidate_if_same(conn_id).await;
                                    state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                                    return make_text_response(
                                        StatusCode::BAD_GATEWAY,
                                        &format!("Upstream GOAWAY error_code={}", error_code),
                                    );
                                }
                                other if is_terminal_upstream_error(&other) => {
                                    // Terminal: the same request is too large for the peer on
                                    // any connection. Retrying (and evicting the pool each
                                    // time) cannot succeed, so surface it immediately.
                                    log(
                                        &format!("Upstream request rejected: {}", other),
                                        Some(&req_id),
                                    );
                                    state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                                    return make_text_response(
                                        StatusCode::BAD_GATEWAY,
                                        &format!("Upstream error: {}", other),
                                    );
                                }
                                other => {
                                    log(
                                        &format!("Upstream error on first chunk: {}", other),
                                        Some(&req_id),
                                    );
                                    // Only a connection-level fault may evict the pool: for H3
                                    // that call closes the QUIC connection and aborts every
                                    // concurrent response riding it.
                                    if stream_scoped {
                                        preset.client.invalidate_stream_if_same(conn_id).await;
                                    } else {
                                        preset.client.invalidate_if_same(conn_id).await;
                                    }
                                    if attempt < max_retry - 1 {
                                        drop(stream);
                                        let delay = retry_delay(attempt);
                                        log(
                                            &format!(
                                                "Auto-retry in {:.1}s...",
                                                delay.as_secs_f64()
                                            ),
                                            Some(&req_id),
                                        );
                                        tokio::time::sleep(delay).await;
                                        attempt += 1;
                                        continue;
                                    } else {
                                        state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                                        return make_text_response(
                                            StatusCode::BAD_GATEWAY,
                                            &format!("Upstream first-chunk error: {}", other),
                                        );
                                    }
                                }
                            }
                        }
                        Ok(None) => Bytes::new(),
                        Err(_) => {
                            log(
                                &format!(
                                    "Upstream idle timeout ({:.1}s) waiting for first chunk",
                                    preset.config.read_timeout.as_secs_f64()
                                ),
                                Some(&req_id),
                            );
                            if attempt < max_retry - 1 {
                                drop(stream);
                                let delay = retry_delay(attempt);
                                log(
                                    &format!("Auto-retry in {:.1}s...", delay.as_secs_f64()),
                                    Some(&req_id),
                                );
                                tokio::time::sleep(delay).await;
                                attempt += 1;
                                continue;
                            } else {
                                state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                                return make_text_response(
                                    StatusCode::GATEWAY_TIMEOUT,
                                    "Upstream read timeout waiting for first chunk",
                                );
                            }
                        }
                    };
                    let first_chunk_received_at = Instant::now();

                    let mut is_empty = false;
                    if first_chunk.is_empty() {
                        is_empty = true;
                        log("Upstream returned 0-byte stream.", Some(&req_id));
                    } else if is_empty_sse_response(&first_chunk) {
                        is_empty = true;
                        log(
                            "Empty stream response detected (0 content/reasoning tokens).",
                            Some(&req_id),
                        );
                    }

                    if is_empty {
                        if attempt < max_retry - 1 {
                            drop(stream);
                            let delay = retry_delay(attempt);
                            log(
                                &format!("Empty stream retry in {:.1}s...", delay.as_secs_f64()),
                                Some(&req_id),
                            );
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        } else {
                            state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                            let err_json = json!({
                                "error": {
                                    "message": "Upstream returned empty stream (0 tokens) across all retry attempts",
                                    "type": "empty_stream_error",
                                    "code": "502",
                                }
                            });
                            return make_json_response(StatusCode::BAD_GATEWAY, err_json);
                        }
                    }

                    // --- Degenerate-output repetition check (chunk 1) ---
                    let (repeat_watch, first_chunk_repeat_fed_until) = if preset.config.degen_repeat {
                        let mut watch = RepeatWatch::new();
                        let complete_end = memchr::memrchr(b'\n', &first_chunk).map_or(0, |p| p + 1);
                        let mut hit = None;
                        for line in first_chunk[..complete_end].split(|&b| b == b'\n') {
                            if let Some(m) = watch.feed_sse_line(line) {
                                hit = Some(m);
                                break;
                            }
                        }
                        if let Some(m) = hit {
                            log(
                                &format!(
                                    "Degenerate repetition loop detected on chunk 1 ({:?}, period={}B, span={}B). Treating as retryable failure.",
                                    m.channel, m.period, m.span
                                ),
                                Some(&req_id),
                            );
                            if attempt < max_retry - 1 {
                                drop(stream);
                                let delay = retry_delay(attempt);
                                log(
                                    &format!(
                                        "Degenerate-output retry in {:.1}s...",
                                        delay.as_secs_f64()
                                    ),
                                    Some(&req_id),
                                );
                                tokio::time::sleep(delay).await;
                                attempt += 1;
                                continue;
                            } else {
                                state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                                let err_json = json!({
                                    "error": {
                                        "message": format!(
                                            "Upstream returned degenerate repetition loop ({:?}, period={}B) across all retry attempts",
                                            m.channel, m.period
                                        ),
                                        "type": "degenerate_output_error",
                                        "code": "502",
                                    }
                                });
                                return make_json_response(StatusCode::BAD_GATEWAY, err_json);
                            }
                        }
                        (Some(watch), complete_end)
                    } else {
                        (None, 0)
                    };

                    // Hand off to streaming pipeline with permit + active_guard held across body stream
                    return stream_response(
                        upstream_status,
                        upstream_headers,
                        upstream_version,
                        first_chunk,
                        stream,
                        state.clone(),
                        preset.clone(),
                        req_id,
                        header_latency,
                        token_timing.clone(),
                        first_chunk_received_at,
                        t_start,
                        permit,
                        active_guard,
                        repeat_watch,
                        first_chunk_repeat_fed_until,
                    );
                } else {
                    // Non-stream: read the whole body here (bounded) so the
                    // degenerate-output classifier can veto before we answer.
                    let (body_bytes, body_truncated) = match tokio::time::timeout(
                        preset.config.read_timeout,
                        upstream_resp
                            .body
                            .read_full_limited_checked(preset.config.max_body_bytes),
                    )
                    .await
                    {
                        Ok(Ok(b)) => b,
                        Ok(Err(e)) => {
                            // Same scope rule as the mid-stream arms: a per-stream reset
                            // leaves the shared connection (and its other responses) alive.
                            if e.is_stream_scoped() {
                                preset.client.invalidate_stream_if_same(conn_id).await;
                            } else {
                                preset.client.invalidate_if_same(conn_id).await;
                            }
                            log(&format!("Upstream body read error: {}", e), Some(&req_id));
                            if attempt < max_retry - 1 {
                                let delay = retry_delay(attempt);
                                log(
                                    &format!("Auto-retry in {:.1}s...", delay.as_secs_f64()),
                                    Some(&req_id),
                                );
                                tokio::time::sleep(delay).await;
                                attempt += 1;
                                continue;
                            }
                            state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                            return make_error_response(
                                StatusCode::BAD_GATEWAY,
                                &format!("Body read error: {}", e),
                            );
                        }
                        Err(_) => {
                            log(
                                &format!(
                                    "Upstream idle timeout ({:.1}s) waiting for response body",
                                    preset.config.read_timeout.as_secs_f64()
                                ),
                                Some(&req_id),
                            );
                            if attempt < max_retry - 1 {
                                let delay = retry_delay(attempt);
                                log(
                                    &format!("Auto-retry in {:.1}s...", delay.as_secs_f64()),
                                    Some(&req_id),
                                );
                                tokio::time::sleep(delay).await;
                                attempt += 1;
                                continue;
                            }
                            state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                            return make_error_response(
                                StatusCode::GATEWAY_TIMEOUT,
                                "Read timeout waiting for response body",
                            );
                        }
                    };
                    if body_truncated {
                        // Never forward a cut-off payload as a 200: the client would try to
                        // parse half a JSON document and report a decode error.
                        state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                        log(
                            &format!(
                                "Upstream body exceeded max_body_bytes ({}); returning 502 instead of a truncated 200",
                                preset.config.max_body_bytes
                            ),
                            Some(&req_id),
                        );
                        return make_error_response(
                            StatusCode::BAD_GATEWAY,
                            "Upstream response exceeded max_body_bytes",
                        );
                    }
                    let parsed_buffered = if preset.config.degen_repeat {
                        serde_json::from_slice::<BufferedResponse>(&body_bytes).ok()
                    } else {
                        // No classifier to run: do not build a typed view of the whole
                        // response just to read its trailing usage object.
                        None
                    };
                    if preset.config.degen_repeat
                        && parsed_buffered
                            .as_ref()
                            .and_then(|p| p.detect_repetition())
                            .is_some()
                    {
                        log(
                            "Degenerate repetition loop detected in buffered response. Treating as retryable failure.",
                            Some(&req_id),
                        );
                        if attempt < max_retry - 1 {
                            let delay = retry_delay(attempt);
                            log(
                                &format!(
                                    "Degenerate-output retry in {:.1}s...",
                                    delay.as_secs_f64()
                                ),
                                Some(&req_id),
                            );
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        } else {
                            state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                            let err_json = json!({
                                "error": {
                                    "message": "Upstream returned degenerate repetition loop across all retry attempts",
                                    "type": "degenerate_output_error",
                                    "code": "502",
                                }
                            });
                            return make_json_response(StatusCode::BAD_GATEWAY, err_json);
                        }
                    }
                    let usage = parsed_buffered
                        .and_then(|p| p.extract_usage())
                        .or_else(|| extract_usage_from_body_tail(&body_bytes))
                        .or_else(|| {
                            serde_json::from_slice::<BufferedResponse>(&body_bytes)
                                .ok()
                                .and_then(|p| p.extract_usage())
                        });
                    return buffer_response(
                        upstream_status,
                        upstream_headers,
                        upstream_version,
                        body_bytes,
                        state.clone(),
                        req_id,
                        header_latency,
                        t_start,
                        permit,
                        active_guard,
                        usage,
                    )
                    .await;
                }
            }
            Ok(Err(send_err)) => {
                let failed_conn_id = send_err.conn_id;
                let stream_scoped = send_err.error.is_stream_scoped();
                match send_err.error {
                    UpstreamError::H2StreamReset { error_code: 7 }
                    | UpstreamError::H3StreamReset { error_code: 0x010b } => {
                        // REFUSED_STREAM / H3_REQUEST_REJECTED → retry immediately, no backoff, no attempt cost
                        if free_retries < MAX_FREE_RETRIES {
                            free_retries += 1;
                            log(&format!("Upstream stream reset (error=REFUSED/REJECTED). Retrying immediately (free retry {}/{})...", free_retries, MAX_FREE_RETRIES), Some(&req_id));
                            if let Some(cid) = failed_conn_id {
                                preset.client.invalidate_stream_if_same(cid).await;
                            }
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            continue;
                        }
                        log(&format!("Upstream stream reset (REFUSED/REJECTED) free-retry budget exhausted after {} tries", MAX_FREE_RETRIES), Some(&req_id));
                        state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                        return make_text_response(
                            StatusCode::BAD_GATEWAY,
                            "Upstream REFUSED_STREAM / H3_REQUEST_REJECTED retry budget exhausted",
                        );
                    }
                    UpstreamError::H2StreamReset { error_code: 8 }
                    | UpstreamError::H3StreamReset { error_code: 0x010c } => {
                        // CANCEL / H3_REQUEST_CANCELLED → retry with normal backoff (mirrors the first-chunk branch)
                        log("Upstream stream reset (error=CANCEL / H3_REQUEST_CANCELLED)", Some(&req_id));
                        if let Some(cid) = failed_conn_id {
                            preset.client.invalidate_stream_if_same(cid).await;
                        }
                        if attempt < max_retry - 1 {
                            let delay = retry_delay(attempt);
                            log(
                                &format!("Auto-retry in {:.1}s...", delay.as_secs_f64()),
                                Some(&req_id),
                            );
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        } else {
                            state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                            return make_text_response(
                                StatusCode::BAD_GATEWAY,
                                "Upstream stream reset CANCEL exhausted",
                            );
                        }
                    }
                    UpstreamError::H2GoAway { error_code: 0, .. }
                    | UpstreamError::H3GoAway { error_code: 0x0100 }
                    | UpstreamError::H3GoAway { error_code: 0 } => {
                        if free_retries < MAX_FREE_RETRIES {
                            free_retries += 1;
                            log(&format!("Upstream GOAWAY (error=NO_ERROR). Reconnecting immediately (free retry {}/{})...", free_retries, MAX_FREE_RETRIES), Some(&req_id));
                            if let Some(cid) = failed_conn_id {
                                preset.client.invalidate_if_same(cid).await;
                            }
                            continue;
                        }
                        log(&format!("Upstream GOAWAY (NO_ERROR) free-retry budget exhausted after {} tries", MAX_FREE_RETRIES), Some(&req_id));
                        state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                        return make_text_response(
                            StatusCode::BAD_GATEWAY,
                            "Upstream GOAWAY retry budget exhausted",
                        );
                    }
                    UpstreamError::H2GoAway { error_code: 11, .. }
                    | UpstreamError::H3StreamReset { error_code: 0x0107 }
                    | UpstreamError::H3GoAway { error_code: 0x0107 } => {
                        log("Upstream overloaded (error=ENHANCE_YOUR_CALM / H3_EXCESSIVE_LOAD). Backing off 2x...", Some(&req_id));
                        if let Some(cid) = failed_conn_id {
                            if stream_scoped {
                                preset.client.invalidate_stream_if_same(cid).await;
                            } else {
                                preset.client.invalidate_if_same(cid).await;
                            }
                        }
                        if attempt < max_retry - 1 {
                            let delay = retry_delay(attempt) * 2;
                            log(
                                &format!("Auto-retry in {:.1}s...", delay.as_secs_f64()),
                                Some(&req_id),
                            );
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        } else {
                            state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                            return make_text_response(
                                StatusCode::BAD_GATEWAY,
                                "Upstream overloaded (ENHANCE_YOUR_CALM / H3_EXCESSIVE_LOAD) exhausted",
                            );
                        }
                    }
                    UpstreamError::H3GoAway { error_code } => {
                        log(
                            &format!("Upstream H3 GOAWAY (error_code={:#x})", error_code),
                            Some(&req_id),
                        );
                        if let Some(cid) = failed_conn_id {
                            preset.client.invalidate_if_same(cid).await;
                        }
                        state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                        return make_text_response(
                            StatusCode::BAD_GATEWAY,
                            &format!("Upstream H3 GOAWAY error_code={:#x}", error_code),
                        );
                    }
                    UpstreamError::H2GoAway { error_code, .. } => {
                        log(
                            &format!("Upstream GOAWAY (error_code={})", error_code),
                            Some(&req_id),
                        );
                        if let Some(cid) = failed_conn_id {
                            preset.client.invalidate_if_same(cid).await;
                        }
                        state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                        return make_text_response(
                            StatusCode::BAD_GATEWAY,
                            &format!("Upstream GOAWAY error_code={}", error_code),
                        );
                    }
                    other if is_terminal_upstream_error(&other) => {
                        // Same terminal rule as the first-chunk arm: no retry, no eviction.
                        log(&format!("Upstream request rejected: {}", other), Some(&req_id));
                        state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                        return make_text_response(
                            StatusCode::BAD_GATEWAY,
                            &format!("Upstream error: {}", other),
                        );
                    }
                    other => {
                        log(&format!("Network error: {}", other), Some(&req_id));
                        if let Some(cid) = failed_conn_id {
                            // Same rule as the first-chunk catch-all: a stream-scoped
                            // failure must not tear down the shared connection.
                            if stream_scoped {
                                preset.client.invalidate_stream_if_same(cid).await;
                            } else {
                                preset.client.invalidate_if_same(cid).await;
                            }
                        }
                        if attempt < max_retry - 1 {
                            let delay = retry_delay(attempt);
                            log(
                                &format!("Auto-retry in {:.1}s...", delay.as_secs_f64()),
                                Some(&req_id),
                            );
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        }
                        state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                        return make_text_response(
                            StatusCode::BAD_GATEWAY,
                            &format!("Upstream failure: {}", other),
                        );
                    }
                }
            }
            Err(_) => {
                log(
                    &format!(
                        "Upstream response timeout ({:.1}s) waiting for headers",
                        send_timeout.as_secs_f64()
                    ),
                    Some(&req_id),
                );
                // A response-header timeout means the pooled connection may be wedged while still
                // reporting ready; drop it so the retry dials fresh (mirrors the
                // Ok(Err) branch, which invalidates on transport failure).
                preset.client.invalidate_connection().await;
                if attempt < max_retry - 1 {
                    let delay = retry_delay(attempt);
                    log(
                        &format!("Auto-retry in {:.1}s...", delay.as_secs_f64()),
                        Some(&req_id),
                    );
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                state.stats.error_count.fetch_add(1, Ordering::Relaxed);
                return make_text_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "Upstream response-header timeout",
                );
            }
        }
    }

    state.stats.error_count.fetch_add(1, Ordering::Relaxed);
    make_text_response(StatusCode::BAD_GATEWAY, "All upstream attempts exhausted")
}

/// Drops with the response body.  When the generator completes normally the
/// stats block at the end of the `stream!` calls `mark_done()` and this guard
/// is a no-op.  When the client closes the connection mid-yield (Hermes got
/// `[DONE]`, user cancelled, network blip) the generator is dropped before
/// the stats block runs.  The guard then logs stats that would otherwise be
/// lost and credits `success_count` when `[DONE]` was already observed.
struct StreamDisconnectGuard {
    req_id: String,
    done: std::sync::atomic::AtomicBool,
    // Shared counters written by the stream! body, readable here on Drop.
    metrics: Arc<StreamMetrics>,
    token_timing: Arc<FirstTokenTiming>,
    t_start: Instant,
    state: Arc<AppState>,
}

impl StreamDisconnectGuard {
    fn new(
        req_id: String,
        metrics: Arc<StreamMetrics>,
        token_timing: Arc<FirstTokenTiming>,
        t_start: Instant,
        state: Arc<AppState>,
    ) -> Self {
        Self {
            req_id,
            done: std::sync::atomic::AtomicBool::new(false),
            metrics,
            token_timing,
            t_start,
            state,
        }
    }

    fn mark_done(&self) {
        self.done.store(true, Ordering::Relaxed);
    }
}

impl Drop for StreamDisconnectGuard {
    fn drop(&mut self) {
        if self.done.load(Ordering::Relaxed) {
            return; // Stats were already logged by the generator's completion path.
        }
        let chunks = self.metrics.chunks.load(Ordering::Relaxed);
        let bytes = self.metrics.bytes.load(Ordering::Relaxed);
        let elapsed = self.t_start.elapsed().as_secs_f64();

        if self.metrics.seen_done.load(Ordering::Relaxed) {
            // Client closed after [DONE] was seen — this is a successful completion.
            if !self.metrics.seen_error.load(Ordering::Relaxed) {
                self.token_timing.commit(&self.state.stats);
            }
            self.state
                .stats
                .success_count
                .fetch_add(1, Ordering::Relaxed);
            self.state
                .stats
                .total_chunks
                .fetch_add(chunks, Ordering::Relaxed);
            self.state
                .stats
                .total_bytes
                .fetch_add(bytes, Ordering::Relaxed);
            let prompt = self.metrics.prompt_tokens.load(Ordering::Relaxed);
            let tokens = self.metrics.completion_tokens.load(Ordering::Relaxed);
            let reasoning = self.metrics.reasoning_tokens.load(Ordering::Relaxed);
            if prompt > 0 {
                self.state
                    .stats
                    .total_tokens_prompt
                    .fetch_add(prompt, Ordering::Relaxed);
            }
            if tokens > 0 {
                self.state
                    .stats
                    .total_tokens_completion
                    .fetch_add(tokens, Ordering::Relaxed);
            }
            if reasoning > 0 {
                self.state
                    .stats
                    .total_tokens_reasoning
                    .fetch_add(reasoning, Ordering::Relaxed);
            }
            let token_info = format_token_info(
                tokens, reasoning, elapsed, self.token_timing.seconds(), "tokens",
            );
            log(
                &format!(
                    "DONE [OK] chunks={} bytes={:.1}KB elapsed={:.2}s{}",
                    chunks,
                    bytes as f64 / 1024.0,
                    elapsed,
                    token_info
                ),
                Some(&self.req_id),
            );
        } else {
            self.state
                .stats
                .total_chunks
                .fetch_add(chunks, Ordering::Relaxed);
            self.state
                .stats
                .total_bytes
                .fetch_add(bytes, Ordering::Relaxed);
            log(
                &format!(
                    "Client disconnected mid-stream. chunks={} bytes={:.1}KB elapsed={:.2}s",
                    chunks,
                    bytes as f64 / 1024.0,
                    elapsed
                ),
                Some(&self.req_id),
            );
        }
    }
}

/// Failures that are terminal for this request: the identical bytes fail the same
/// way on a fresh connection, so retrying only burns the retry budget and evicts a
/// healthy pool entry on every attempt.
fn is_terminal_upstream_error(e: &UpstreamError) -> bool {
    matches!(e, UpstreamError::HeaderTooBig { .. })
}

fn log_midstream_upstream_error(e: UpstreamError, req_id: &str) -> &'static str {
    match e {
        UpstreamError::H2StreamReset { error_code } => {
            if error_code == 8 {
                log("Upstream RST_STREAM (CANCEL, code=8)", Some(req_id));
            } else if error_code == 7 {
                log("Upstream RST_STREAM (REFUSED_STREAM, code=7)", Some(req_id));
            } else if error_code == 2 {
                log("Upstream RST_STREAM (INTERNAL_ERROR, code=2)", Some(req_id));
            } else {
                log(&format!("Upstream RST_STREAM (code={})", error_code), Some(req_id));
            }
            "upstream_http2_reset"
        }
        UpstreamError::H2GoAway { error_code, .. } => {
            if error_code == 0 {
                log("Upstream GOAWAY (NO_ERROR, code=0)", Some(req_id));
            } else if error_code == 11 {
                log("Upstream GOAWAY (ENHANCE_YOUR_CALM, code=11)", Some(req_id));
            } else {
                log(&format!("Upstream GOAWAY (code={})", error_code), Some(req_id));
            }
            "upstream_goaway"
        }
        UpstreamError::H3StreamReset { error_code } => {
            if error_code == 0x010c {
                log("Upstream H3 RST_STREAM (H3_REQUEST_CANCELLED, code=0x010c)", Some(req_id));
            } else if error_code == 0x010b {
                log("Upstream H3 RST_STREAM (H3_REQUEST_REJECTED, code=0x010b)", Some(req_id));
            } else if error_code == 0x0107 {
                log("Upstream H3 RST_STREAM (H3_EXCESSIVE_LOAD, code=0x0107)", Some(req_id));
            } else {
                log(&format!("Upstream H3 RST_STREAM (code={:#x})", error_code), Some(req_id));
            }
            "upstream_http3_reset"
        }
        UpstreamError::H3GoAway { error_code } => {
            if error_code == 0x0100 || error_code == 0 {
                log("Upstream H3 GOAWAY (H3_NO_ERROR, code=0x0100)", Some(req_id));
            } else if error_code == 0x0107 {
                log("Upstream H3 GOAWAY (H3_EXCESSIVE_LOAD, code=0x0107)", Some(req_id));
            } else {
                log(&format!("Upstream H3 GOAWAY (code={:#x})", error_code), Some(req_id));
            }
            "upstream_http3_goaway"
        }
        other => {
            log(&format!("Upstream reset: {}", other), Some(req_id));
            "upstream_reset"
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn stream_response(
    upstream_status: StatusCode,
    upstream_headers: HeaderMap,
    upstream_version: http::Version,
    first_chunk: Bytes,
    upstream_stream: BodyStream,
    state: Arc<AppState>,
    preset: Arc<PresetRuntime>,
    req_id: String,
    header_latency: f64,
    token_timing: Arc<FirstTokenTiming>,
    first_chunk_received_at: Instant,
    t_start: Instant,
    permit: OwnedSemaphorePermit,
    active_guard: ActiveRequestGuard,
    mut repeat_watch: Option<RepeatWatch>,
    first_chunk_repeat_fed_until: usize,
) -> Response {


    log(
        &format!(
            "Upstream response headers in {:.2}s; streaming status={} ({:?}).",
            header_latency,
            upstream_status.as_u16(),
            upstream_version
        ),
        Some(&req_id),
    );

    // Build downstream response headers
    let mut response_headers = HeaderMap::new();
    for (name, val) in upstream_headers.iter() {
        if !state.stripped_headers.contains(name) && name != header::CONTENT_TYPE {
            response_headers.insert(name.clone(), val.clone());
        }
    }
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    apply_nocache_headers(&mut response_headers);

    let state_clone = state.clone();
    let preset_clone = preset.clone();
    let req_id_clone = req_id.clone();

    // Stream generator using async_stream
    // Shared cells so the disconnect guard can read final counters on Drop.
    let shared_metrics = Arc::new(StreamMetrics::default());

    let body_stream = stream! {
        // Hold concurrency permit and active_requests guard until stream completes or drops
        let _permit = permit;
        let _active_guard = active_guard;
        let disconnect_guard = StreamDisconnectGuard::new(
            req_id_clone.clone(),
            shared_metrics.clone(),
            token_timing.clone(),
            t_start,
            state.clone(),
        );
        let conn_id = upstream_stream.conn_id();
        let mut upstream_stream = Some(upstream_stream);
        let mut chunk_count = 0u64;
        let mut total_bytes = 0u64;
        let mut seen_done = false;
        let mut last_usage: Option<UsageStats> = None;
        let mut sse_buffer = BytesMut::with_capacity(4096);
        let mut warned_huge_sse_line = false;
        let mut stream_completed = false;
        let mut truncation_reason = None;
        // Set when the upstream stream dies mid-flight (reset/GOAWAY/read timeout/repetition loop).
        // Drives the downstream abort at the end so the client re-fires.
        let mut downstream_broke = false;

        // Zero-copy SSE chunk scanning using BytesMut and SIMD memchr
        let process_chunk = |chunk: &[u8],
                             seen_done: &mut bool,
                             last_usage: &mut Option<UsageStats>,
                             sse_buffer: &mut BytesMut,
                             repeat_watch: &mut Option<RepeatWatch>,
                             repeat_skip_until: usize,
                             warned_huge_sse_line: &mut bool,
                             received_at: Instant|
         -> Option<RepeatMatch> {
            sse_buffer.extend_from_slice(chunk);
            if sse_buffer.len() > 1024 * 1024 && !*warned_huge_sse_line {
                *warned_huge_sse_line = true;
                log(
                    "Warning: SSE buffer exceeded 1MB without newline (malformed upstream)",
                    Some(&req_id_clone),
                );
            }
            let mut start = 0;
            let mut repeat_hit = None;
            while let Some(rel) = memchr::memchr(b'\n', &sse_buffer[start..]) {
                let pos = start + rel;
                let line = &sse_buffer[start..pos];
                if !line.is_empty() {
                    if chat_sse_line_has_error(line) {
                        shared_metrics.seen_error.store(true, Ordering::Relaxed);
                    }
                    if !*seen_done && is_sse_done_line(line) {
                        *seen_done = true;
                        shared_metrics.seen_done.store(true, Ordering::Relaxed);
                    } else if FINDER_USAGE.find(line).is_some() {
                        if let Ok(s) = std::str::from_utf8(line) {
                            if let Some(u) = extract_usage_from_sse_line(s.trim()) {
                                publish_sse_usage(&u, &shared_metrics);
                                *last_usage = Some(u);
                            }
                        }
                    }
                    if upstream_status.is_success()
                        && !token_timing.recorded()
                        && chat_sse_line_has_generated_delta(line) {
                        if let Some(ttft) = token_timing.record_at(received_at) {
                            log(
                                &format!("TTFT={ttft:.3}s to first generated delta"),
                                Some(&req_id_clone),
                            );
                        }
                    }
                    if repeat_hit.is_none() && pos >= repeat_skip_until {
                        if let Some(ref mut w) = repeat_watch {
                            repeat_hit = w.feed_sse_line(line);
                            if repeat_hit.is_some() {
                                break;
                            }
                        }
                    }
                }
                start = pos + 1;
            }
            if start > 0 {
                if start == sse_buffer.len() {
                    sse_buffer.clear();
                } else {
                    let _ = sse_buffer.split_to(start);
                }
            }
            repeat_hit
        };

        // Emit peeked first chunk
        if !first_chunk.is_empty() {
            chunk_count += 1;
            total_bytes += first_chunk.len() as u64;
            shared_metrics.chunks.store(chunk_count, Ordering::Relaxed);
            shared_metrics.bytes.store(total_bytes, Ordering::Relaxed);
            let _ = process_chunk(
                &first_chunk,
                &mut seen_done,
                &mut last_usage,
                &mut sse_buffer,
                &mut repeat_watch,
                first_chunk_repeat_fed_until,
                &mut warned_huge_sse_line,
                first_chunk_received_at,
            );
            yield Ok::<Bytes, std::io::Error>(first_chunk);
        }

        // Stream remaining chunks from upstream with single pinned idle timeout Sleep
        // and non-blocking burst chunk coalescing (0 extra copies for single ready frames).
        const COALESCE_MAX_BYTES: usize = 32 * 1024;
        let read_timeout = preset_clone.config.read_timeout;
        let throttle_reset = read_timeout >= Duration::from_secs(2);
        let start_now = tokio::time::Instant::now();
        let deadline_sleep = tokio::time::sleep_until(start_now + read_timeout);
        tokio::pin!(deadline_sleep);
        let mut last_deadline_reset = start_now;
        let mut last_chunk_at = start_now;

        'stream_loop: loop {
            let next_res = tokio::select! {
                biased;
                res = upstream_stream.as_mut().unwrap().next() => Some(res),
                () = &mut deadline_sleep => None,
            };
            match next_res {
                Some(Some(Ok(first))) => {
                    if first.is_empty() {
                        continue;
                    }
                    let now = tokio::time::Instant::now();
                    last_chunk_at = now;
                    if !throttle_reset
                        || now.duration_since(last_deadline_reset) >= Duration::from_secs(1)
                    {
                        deadline_sleep.as_mut().reset(now + read_timeout);
                        last_deadline_reset = now;
                    }
                    if let Some(hit) = process_chunk(
                        &first,
                        &mut seen_done,
                        &mut last_usage,
                        &mut sse_buffer,
                        &mut repeat_watch,
                        0,
                        &mut warned_huge_sse_line,
                        now.into_std(),
                    ) {
                        log(
                            &format!(
                                "Degenerate repetition loop detected mid-stream ({:?}, period={}B, span={}B). Aborting stream.",
                                hit.channel, hit.period, hit.span
                            ),
                            Some(&req_id_clone),
                        );
                        truncation_reason = Some("degenerate_output");
                        state_clone.stats.error_count.fetch_add(1, Ordering::Relaxed);
                        downstream_broke = true;
                        drop(upstream_stream.take());
                        break;
                    }

                    let mut coalesced: Option<BytesMut> = None;
                    let mut buffered_len = first.len();
                    let mut post_drain_err: Option<UpstreamError> = None;
                    let mut post_drain_eof = false;
                    let mut hit_during_drain: Option<RepeatMatch> = None;

                    if buffered_len < COALESCE_MAX_BYTES {
                        while buffered_len < COALESCE_MAX_BYTES {
                            let ready = futures_util::future::poll_fn(|cx| {
                                match upstream_stream.as_mut().unwrap().poll_next_unpin(cx) {
                                    std::task::Poll::Ready(item) => {
                                        std::task::Poll::Ready(Some(item))
                                    }
                                    std::task::Poll::Pending => std::task::Poll::Ready(None),
                                }
                            })
                            .await;

                            match ready {
                                Some(Some(Ok(extra))) => {
                                    if extra.is_empty() {
                                        continue;
                                    }
                                    if let Some(hit) = process_chunk(
                                        &extra,
                                        &mut seen_done,
                                        &mut last_usage,
                                        &mut sse_buffer,
                                        &mut repeat_watch,
                                        0,
                                        &mut warned_huge_sse_line,
                                        Instant::now(),
                                    ) {
                                        hit_during_drain = Some(hit);
                                        break;
                                    }
                                    let buf = coalesced.get_or_insert_with(|| {
                                        let mut b = BytesMut::with_capacity(
                                            (buffered_len + extra.len()).min(COALESCE_MAX_BYTES),
                                        );
                                        b.extend_from_slice(&first);
                                        b
                                    });
                                    buffered_len += extra.len();
                                    buf.extend_from_slice(&extra);
                                }
                                Some(Some(Err(e))) => {
                                    post_drain_err = Some(e);
                                    break;
                                }
                                Some(None) => {
                                    post_drain_eof = true;
                                    break;
                                }
                                None => break,
                            }
                        }
                    }

                    let out = coalesced.map(|b| b.freeze()).unwrap_or(first);
                    chunk_count += 1;
                    total_bytes += out.len() as u64;
                    shared_metrics.chunks.store(chunk_count, Ordering::Relaxed);
                    shared_metrics.bytes.store(total_bytes, Ordering::Relaxed);
                    yield Ok(out);

                    if let Some(hit) = hit_during_drain {
                        log(
                            &format!(
                                "Degenerate repetition loop detected mid-stream ({:?}, period={}B, span={}B). Aborting stream.",
                                hit.channel, hit.period, hit.span
                            ),
                            Some(&req_id_clone),
                        );
                        truncation_reason = Some("degenerate_output");
                        state_clone.stats.error_count.fetch_add(1, Ordering::Relaxed);
                        downstream_broke = true;
                        drop(upstream_stream.take());
                        break 'stream_loop;
                    }
                    if let Some(e) = post_drain_err {
                        let stream_scoped = e.is_stream_scoped();
                        truncation_reason = Some(log_midstream_upstream_error(e, &req_id_clone));
                        downstream_broke = true;
                        if stream_scoped {
                            preset_clone.client.invalidate_stream_if_same(conn_id).await;
                        } else {
                            preset_clone.client.invalidate_if_same(conn_id).await;
                        }
                        state_clone.stats.error_count.fetch_add(1, Ordering::Relaxed);
                        break 'stream_loop;
                    }
                    if post_drain_eof {
                        break 'stream_loop;
                    }
                }
                Some(Some(Err(e))) => {
                    let stream_scoped = e.is_stream_scoped();
                    truncation_reason = Some(log_midstream_upstream_error(e, &req_id_clone));
                    downstream_broke = true;
                    if stream_scoped {
                        preset_clone.client.invalidate_stream_if_same(conn_id).await;
                    } else {
                        preset_clone.client.invalidate_if_same(conn_id).await;
                    }
                    state_clone.stats.error_count.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Some(None) => {
                    break;
                }
                None => {
                    let exact_deadline = last_chunk_at + read_timeout;
                    let now = tokio::time::Instant::now();
                    if now < exact_deadline {
                        // A chunk arrived within the <1s reset-throttle window; extend to the
                        // true idle deadline instead of firing prematurely.
                        deadline_sleep.as_mut().reset(exact_deadline);
                        last_deadline_reset = now;
                        continue;
                    }
                    log(
                        &format!(
                            "Upstream idle read timeout after {:.1}s",
                            read_timeout.as_secs_f64()
                        ),
                        Some(&req_id_clone),
                    );
                    truncation_reason = Some("idle_read_timeout");
                    state_clone.stats.error_count.fetch_add(1, Ordering::Relaxed);
                    downstream_broke = true;
                    break;
                }
            }
        }

        if truncation_reason.is_none() {
            stream_completed = true;
            // Process leftover buffer
            if !sse_buffer.is_empty() {
                if !seen_done && is_sse_done_line(&sse_buffer) {
                    seen_done = true;
                    shared_metrics.seen_done.store(true, Ordering::Relaxed);
                } else if FINDER_USAGE.find(&sse_buffer).is_some() {
                    if let Ok(s) = std::str::from_utf8(&sse_buffer) {
                        if let Some(u) = extract_usage_from_sse_line(s.trim()) {
                            publish_sse_usage(&u, &shared_metrics);
                            last_usage = Some(u);
                        }
                    }
                }
            }
        }

        // Truncation diagnostics
        if stream_completed && !seen_done {
            log("WARNING: Stream ended without [DONE] sentinel", Some(&req_id_clone));
        }

        // Update statistics
        let elapsed = t_start.elapsed().as_secs_f64();
        if let Some(reason) = truncation_reason {
            log(
                &format!(
                    "DONE [TRUNCATED({})] chunks={} bytes={:.1}KB elapsed={:.2}s seen_done={}",
                    reason,
                    chunk_count,
                    total_bytes as f64 / 1024.0,
                    elapsed,
                    seen_done
                ),
                Some(&req_id_clone),
            );
        } else {
            if seen_done && !shared_metrics.seen_error.load(Ordering::Relaxed) {
                token_timing.commit(&state_clone.stats);
            }
            state_clone.stats.success_count.fetch_add(1, Ordering::Relaxed);

            let mut token_info = String::new();
            if let Some(usage) = &last_usage {
                token_info = apply_usage_stats(
                    &state_clone.stats,
                    usage,
                    elapsed,
                    token_timing.seconds(),
                    "tokens",
                );
            }

            log(
                &format!(
                    "DONE [OK] chunks={} bytes={:.1}KB elapsed={:.2}s{}",
                    chunk_count,
                    total_bytes as f64 / 1024.0,
                    elapsed,
                    token_info
                ),
                Some(&req_id_clone),
            );
        }

        state_clone.stats.total_chunks.fetch_add(chunk_count, Ordering::Relaxed);
        state_clone.stats.total_bytes.fetch_add(total_bytes, Ordering::Relaxed);

        disconnect_guard.mark_done();
        // Mid-stream upstream failure: the status line and some bytes have already
        // gone out, so a retry here is impossible — instead abort the downstream
        // stream so the client sees a broken transfer and re-fires the request.
        // Mirrors the souffloir-shim pattern (transport.abort() + HTTPBadGateway).
        if downstream_broke {
            log(
                "Upstream broke mid-stream (aborting downstream)",
                Some(&req_id_clone),
            );
            yield Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "upstream stream broke mid-flight",
            ));
        }
    };

    let mut resp = Response::new(Body::from_stream(body_stream));
    *resp.status_mut() = upstream_status;
    *resp.headers_mut() = response_headers;
    resp
}

#[allow(clippy::too_many_arguments)]
async fn buffer_response(
    upstream_status: StatusCode,
    upstream_headers: HeaderMap,
    upstream_version: http::Version,
    body_bytes: Bytes,
    state: Arc<AppState>,
    req_id: String,
    header_latency: f64,
    t_start: Instant,
    _permit: OwnedSemaphorePermit,
    _active_guard: ActiveRequestGuard,
    usage: Option<UsageStats>,
) -> Response {
    let mut response_headers = HeaderMap::new();
    for (name, val) in upstream_headers.iter() {
        if !state.stripped_headers.contains(name) {
            response_headers.insert(name.clone(), val.clone());
        }
    }
    apply_nocache_headers(&mut response_headers);

    let elapsed = t_start.elapsed().as_secs_f64();
    let mut token_info = String::new();
    // Extract token usage
    if let Some(ref u) = usage {
        token_info = apply_usage_stats(&state.stats, u, elapsed, 0.0, "tokens");
    }

    state.stats.success_count.fetch_add(1, Ordering::Relaxed);
    state
        .stats
        .total_bytes
        .fetch_add(body_bytes.len() as u64, Ordering::Relaxed);

    log(
        &format!(
            "Non-stream complete ({:?}) {:.1}KB headers={:.2}s elapsed={:.2}s{}",
            upstream_version,
            body_bytes.len() as f64 / 1024.0,
            header_latency,
            elapsed,
            token_info
        ),
        Some(&req_id),
    );

    let mut resp = Response::new(Body::from(body_bytes));
    *resp.status_mut() = upstream_status;
    *resp.headers_mut() = response_headers;
    resp
}

// ---------------------------------------------------------------------------
// Main Application Entry Point
// ---------------------------------------------------------------------------
// Launch resolution: choose a preset (headless flag / interactive menu /
// first-run questionnaire). Runs INSIDE the #[tokio::main] runtime — blocking
// stdin stalls one worker thread, which is safe at startup because no request
// traffic is being served yet. Never hangs on stdin without a TTY.
// ---------------------------------------------------------------------------
struct LaunchArgs {
    headless: bool,
    presets: Vec<String>,
}

fn parse_args_from<I: Iterator<Item = String>>(args: I) -> LaunchArgs {
    let mut headless = false;
    let mut presets: Vec<String> = Vec::new();
    let mut it = args;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--headless" => headless = true,
            "--preset" => {
                if let Some(v) = it.next() {
                    presets.push(v);
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--preset=") {
                    presets.push(v.to_string());
                }
            }
        }
    }
    LaunchArgs { headless, presets }
}

fn parse_args() -> LaunchArgs {
    parse_args_from(std::env::args().skip(1))
}

fn print_preset_names(presets: &[Preset], default: &Option<String>) {
    if presets.is_empty() {
        eprintln!("No presets available (config.json missing or empty).");
        return;
    }
    eprintln!("Available presets:");
    for p in presets {
        let mark = if default.as_deref() == Some(p.name.as_str()) {
            " (default)"
        } else {
            ""
        };
        eprintln!("  - {}{}", p.name, mark);
    }
}

fn prompt_line(prompt: &str, default: &str) -> String {
    print!("{prompt}");
    if !default.is_empty() {
        print!(" [{default}]");
    }
    print!(": ");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    if std::io::stdin().read_line(&mut s).is_err() {
        return default.to_string();
    }
    let s = s.trim().to_string();
    if s.is_empty() {
        default.to_string()
    } else {
        s
    }
}

/// Interactive questionnaire that builds one preset. Blocking stdin; caller must
/// only invoke this when a TTY is present.
fn questionnaire() -> Preset {
    println!("\n=== souffle_proxy preset setup ===");
    let name = prompt_line("Preset name", "deepseek-sol");
    let model_raw = prompt_line(
        "Upstream model id(s), comma-separated for round-robin",
        "deepseek-sol",
    );
    let models: Vec<String> = model_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let models = if models.is_empty() {
        vec!["deepseek-sol".to_string()]
    } else {
        models
    };
    let key_envs_raw = prompt_line(
        "Secret env var name(s), comma-separated for round-robin",
        "SOUFFLE_API_KEY",
    );
    let key_envs: Vec<String> = key_envs_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let bases_raw = prompt_line(
        "Upstream base URL(s), comma-separated",
        "https://api.soufflotheque.internal/v1",
    );
    let upstream_bases: Vec<String> = bases_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // inject: offer shortcut prefills, then let the user paste/edit raw JSON.
    println!("\nInject block (raw params merged into every request; proxy always wins):");
    println!("  1) thinking -> {{\"thinking\":{{\"type\":\"enabled\",\"clear_thinking\":false}},\"reasoning_effort\":\"max\"}}");
    println!("  2) kimi-k3 -> {{\"reasoning_effort\":\"max\"}}");
    println!("  3) none    -> {{}}");
    println!("  4) custom  -> paste your own JSON object");
    let choice = prompt_line("Choose 1-4", "1");
    let inject_text = match choice.as_str() {
        "2" => "{\"reasoning_effort\":\"max\"}".to_string(),
        "3" => "{}".to_string(),
        "4" => loop {
            let pasted = prompt_line("Paste inject JSON object", "{}");
            match serde_json::from_str::<Value>(&pasted) {
                Ok(Value::Object(_)) => break pasted,
                _ => println!("  Not a JSON object, try again."),
            }
        },
        _ => "{\"thinking\":{\"type\":\"enabled\",\"clear_thinking\":false},\"reasoning_effort\":\"max\"}".to_string(),
    };
    let inject = match serde_json::from_str::<Value>(&inject_text) {
        Ok(Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };

    let inject_raw = inject_to_raw(&inject).unwrap_or_default();
    let models_raw = models_to_raw(&models).unwrap_or_default();
    let preset = Preset {
        name,
        api_mode: responses::ApiMode::ChatCompletions,
        models,
        models_raw,
        key_envs,
        upstream_bases,
        inject,
        inject_raw,
        append_messages: Vec::new(),
        append_raw: None,
        prepend_messages: Vec::new(),
        prepend_raw: None,
        degen_repeat: false,
        brotli: None,
        http3: None,
        souffle_pout: false,
        extra_headers: HeaderOverrides::default(),
    };
    if let Err(e) = write_preset_to_config(&preset) {
        eprintln!("[WARN] Could not write config.json: {e}");
    } else {
        println!(
            "Saved preset '{}' to {}",
            preset.name,
            config_json_path().display()
        );
    }
    preset
}

/// Merge/insert a preset into config.json beside the exe, setting it as default.
fn write_preset_to_config(preset: &Preset) -> Result<(), String> {
    let path = config_json_path();
    let mut root: Value = if path.is_file() {
        let txt = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        // Never treat an unparsable operator file as empty: rebuilding it from {}
        // would silently drop every preset the operator had configured.
        serde_json::from_str(&txt)
            .map_err(|e| format!("refusing to rewrite unparsable {}: {e}", path.display()))?
    } else {
        json!({})
    };
    if !root.is_object() {
        root = json!({});
    }
    let obj = root.as_object_mut().unwrap();
    obj.insert("default".to_string(), json!(preset.name));
    let presets = obj.entry("presets").or_insert_with(|| json!({}));
    if !presets.is_object() {
        *presets = json!({});
    }
    // Seed from any existing entry so fields this questionnaire does not edit
    // (brotli, http3, souffle_pout, degen_repeat, alias) survive a re-save.
    let mut preset_obj = presets
        .as_object()
        .and_then(|m| m.get(&preset.name))
        .cloned()
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    preset_obj["name"] = json!(preset.name);
    preset_obj
        .as_object_mut()
        .unwrap()
        .entry("api_mode")
        .or_insert_with(|| json!(preset.api_mode.as_str()));
    preset_obj["model"] = if preset.models.len() == 1 {
        json!(preset.models[0])
    } else {
        json!(preset.models)
    };
    preset_obj["key_env"] = if preset.key_envs.len() == 1 {
        json!(preset.key_envs[0])
    } else {
        json!(preset.key_envs)
    };
    preset_obj["upstream_bases"] = json!(preset.upstream_bases);
    preset_obj["inject"] = Value::Object(preset.inject.clone());
    if !preset.append_messages.is_empty() {
        preset_obj["append_messages"] = json!(preset.append_messages);
    }
    if !preset.prepend_messages.is_empty() {
        preset_obj["prepend_messages"] = json!(preset.prepend_messages);
    }
    presets
        .as_object_mut()
        .unwrap()
        .insert(preset.name.clone(), preset_obj);
    let pretty = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
    // Atomic replace: a crash, panic=abort or full disk mid-write must never leave
    // a truncated config.json behind - the next start would die parsing it.
    let tmp = path.with_extension("json.tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)
            .map_err(|e| format!("create {}: {e}", tmp.display()))?;
        f.write_all(pretty.as_bytes())
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("rename {} -> {}: {e}", tmp.display(), path.display())
    })?;
    Ok(())
}

/// Resolve which preset(s) to serve. Exits the process (non-zero) on
/// unrecoverable selection errors; never blocks on stdin without a TTY.
/// Returns a Vec<Preset> — empty-vec paths are unreachable (they exit).
/// One element = single-slot mode (byte-identical to the old behaviour);
/// two elements = dual-slot mode.
fn resolve_presets() -> Vec<Preset> {
    let args = parse_args();
    let loaded = load_config_file().unwrap_or_else(|e| {
        eprintln!("[FATAL] {e}");
        std::process::exit(1);
    });
    let (default, presets) = loaded.unwrap_or((None, Vec::new()));
    let is_tty = std::io::stdin().is_terminal();

    let pick = |name: &str| {
        presets
            .iter()
            .find(|p| p.name == name)
            .or_else(|| presets.iter().find(|p| p.name.eq_ignore_ascii_case(name)))
            .or_else(|| {
                presets
                    .iter()
                    .find(|p| p.models.iter().any(|m| m.eq_ignore_ascii_case(name)))
            })
            .cloned()
    };

    // Cap at 2 slots — a third --preset is a hard error, not silent ignore.
    if args.presets.len() > 2 {
        eprintln!(
            "[FATAL] at most two presets (slots) are supported; got {}.",
            args.presets.len()
        );
        std::process::exit(2);
    }

    // Explicit --preset(s) (with or without --headless): non-interactive select.
    if !args.presets.is_empty() {
        let mut resolved: Vec<Preset> = Vec::with_capacity(args.presets.len());
        for want in &args.presets {
            let p = pick(want).unwrap_or_else(|| {
                eprintln!("[FATAL] preset '{want}' not found.");
                print_preset_names(&presets, &default);
                std::process::exit(2);
            });
            resolved.push(p);
        }
        return resolved;
    }
    // Headless without --preset: print names and die (never prompt).
    if args.headless {
        eprintln!("[FATAL] --headless requires --preset <name>.");
        print_preset_names(&presets, &default);
        std::process::exit(2);
    }
    // No --preset flag:
    if presets.is_empty() {
        // First run.
        if is_tty {
            return vec![questionnaire()];
        }
        eprintln!("[FATAL] No config.json and no TTY to create one. Run interactively once, or pass --preset.");
        std::process::exit(2);
    }
    // config exists. Non-TTY -> use default silently.
    if !is_tty {
        let name = default.clone().unwrap_or_else(|| presets[0].name.clone());
        return vec![pick(&name).unwrap_or_else(|| presets[0].clone())];
    }
    // TTY menu: pick existing or create new (single-select, same as today).
    println!("Select a preset:");
    for (i, p) in presets.iter().enumerate() {
        let mark = if default.as_deref() == Some(p.name.as_str()) {
            " (default)"
        } else {
            ""
        };
        println!("  {}) {}{}", i + 1, p.name, mark);
    }
    println!("  {}) create new", presets.len() + 1);
    let default_idx = presets
        .iter()
        .position(|p| default.as_deref() == Some(p.name.as_str()))
        .map(|i| i + 1)
        .unwrap_or(1);
    let sel = prompt_line("Choice", &default_idx.to_string());
    if let Ok(n) = sel.parse::<usize>() {
        if n >= 1 && n <= presets.len() {
            return vec![presets[n - 1].clone()];
        }
        if n == presets.len() + 1 {
            return vec![questionnaire()];
        }
    }
    vec![presets
        .get(default_idx - 1)
        .cloned()
        .unwrap_or_else(|| presets[0].clone())]
}

// mimalloc tuning deliberately absent: arena_eager_commit (=2) and purge_decommits (=1)
// equal the vendored v3 defaults. Rationale: soufflotheque lib, llm-inference/souffle-proxy-operator.md.

// ---------------------------------------------------------------------------
#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() {
    init_log_writer();
    let presets = resolve_presets();
    let stats = Arc::new(ProxyStats::new());

    let stripped_headers: HashSet<HeaderName> = [
        header::CONTENT_LENGTH,
        header::TRANSFER_ENCODING,
        header::CONNECTION,
        header::CACHE_CONTROL,
        header::PRAGMA,
        header::EXPIRES,
        header::ETAG,
        header::AGE,
        header::LAST_MODIFIED,
        header::CONTENT_ENCODING,
    ]
    .into_iter()
    .collect();

    // Env tunables (same for every slot) read once before the loop.
    let insecure_tls = std::env::var("SOUFFLE_INSECURE_TLS")
        .map(|v| v == "1")
        .unwrap_or(false);

    // Build one PresetRuntime per preset (slot 1 = first --preset, slot 2 = second).
    let mut slots: Vec<Arc<PresetRuntime>> = Vec::with_capacity(presets.len());
    for preset in &presets {
        let config = Arc::new(Config::from_preset(preset));
        let client = if config.http3_enabled {
            UpstreamClient::H3(
                H3Client::new(
                    &config.upstream_bases,
                    config.connect_timeout,
                    insecure_tls,
                )
                .expect("Failed to build HTTP/3 upstream client"),
            )
        } else {
            UpstreamClient::H2(
                H2Client::new(
                    &config.upstream_bases,
                    config.connect_timeout,
                    config.keepalive_expiry,
                    insecure_tls,
                )
                .expect("Failed to build HTTP/2 upstream client"),
            )
        };
        slots.push(Arc::new(PresetRuntime {
            config,
            client,
            model_index: AtomicUsize::new(0),
            key_index: AtomicUsize::new(0),
        }));
    }
    // Configs are immutable and shared with the PresetRuntime instances;
    // keep an Arc clone of each for the startup banner below.
    let slot_configs: Vec<Arc<Config>> = slots.iter().map(|rt| rt.config.clone()).collect();
    // Concurrency limit is env-derived and identical across slots.
    let semaphore = Arc::new(Semaphore::new(slot_configs[0].max_concurrency));

    let state = Arc::new(AppState {
        slots,
        semaphore,
        stats,
        stripped_headers,
    });

    // Eagerly prewarm upstreams on startup (strictly non-billable transport handshake).
    for slot in &state.slots {
        let slot_clone = slot.clone();
        tokio::spawn(async move {
            if let Err(e) = slot_clone.client.prewarm().await {
                log(
                    &format!(
                        "Upstream prewarm for preset '{}' encountered error (will retry on demand): {}",
                        slot_clone.config.preset_name, e
                    ),
                    None,
                );
            }
        });
    }

    // Background idle watchdog (>360s idle trigger):
    // Preserves warm connections ahead of Cloudflare's 400s edge timeout, and
    // re-establishes pooled HTTP/3 connections if Quinn's 60s max_idle_timeout
    // closed them while idle.
    let watchdog_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let last_req = watchdog_state
                .stats
                .last_request_time
                .load(Ordering::Relaxed);
            if last_req > 0 {
                let now = jiff::Timestamp::now().as_second();
                if now.saturating_sub(last_req) > 360 {
                    watchdog_state
                        .stats
                        .last_request_time
                        .store(now, Ordering::Relaxed);
                    for slot in &watchdog_state.slots {
                        let _ = slot.client.prewarm().await;
                    }
                }
            }
        }
    });

    let app = build_router(state);

    let cfg0 = &slot_configs[0];
    log(
        &format!(
            "Starting Soufflé Proxy on http://{}:{}/v1",
            cfg0.host, cfg0.port
        ),
        None,
    );
    let log_upstreams = |label_prefix: &str, upstream_bases: &str| {
        let bases: Vec<&str> = upstream_bases
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if bases.len() > 1 {
            log(
                &format!(
                    "{} failover list ({}): {}",
                    label_prefix,
                    bases.len(),
                    bases.join(" -> ")
                ),
                None,
            );
            log("Note: failover covers per-domain DNS/route flap; verify targets are distinct origins for real redundancy.", None);
        } else {
            log(
                &format!("{}: {}", label_prefix, bases.first().copied().unwrap_or("")),
                None,
            );
        }
    };
    if slot_configs.len() == 1 {
        log_upstreams("Upstream", &cfg0.upstream_bases);
    }
    if slot_configs.len() > 1 {
        for (slot_idx, cfg) in slot_configs.iter().enumerate() {
            log(&format!(
                "Slot {} ({}) → Preset: {} | api_mode: {} | model: {} | inject keys: {:?} | prepend_messages: {} | append_messages: {} | degen_repeat: {}",
                slot_idx + 1,
                if slot_idx == 0 { "deepseek-souffle" } else { "deepseek-sol" },
                cfg.preset_name,
                cfg.api_mode.as_str(),
                if cfg.models.len() > 1 {
                    format!("{:?} (round-robin)", cfg.models)
                } else {
                    cfg.models.first().cloned().unwrap_or_default()
                },
                cfg.inject.keys().collect::<Vec<_>>(),
                cfg.prepend_messages.len(),
                cfg.append_messages.len(),
                cfg.degen_repeat
            ), None);
            log_upstreams(&format!("Slot {} upstream", slot_idx + 1), &cfg.upstream_bases);
            {
                let n = cfg.api_keys.len();
                if n > 1 {
                    log(
                        &format!("API keys: {} keys loaded, round-robin rotation enabled", n),
                        None,
                    );
                } else {
                    log("API key: 1 key loaded", None);
                }
            }
            if cfg.http3_enabled {
                log("Transport: HTTP/3 (QUIC / RFC 9114, 15s keepalive)", None);
            } else {
                log("Transport: HTTP/2 (TCP / RFC 9113)", None);
            }
            if cfg.brotli_enabled {
                log(
                    &format!(
                        "Brotli upload compression: ON (engine: mbrotli AVX-512, base level {}, min {}B; >=256KB escalates to 10, clamped at q10)",
                        cfg.brotli_level, cfg.brotli_min_bytes
                    ),
                    None,
                );
            } else {
                log(
                    "Brotli upload compression: OFF (preset did not opt in - set \"brotli\": true in config.json, or SOUFFLE_BROTLI=1)",
                    None,
                );
            }
        }
        log(
            &format!(
                "Dual-slot mode: 2 presets loaded (deepseek-souffle→{}, deepseek-sol→{}). Unknown ids fall back to slot 1.",
                slot_configs[0].preset_name, slot_configs[1].preset_name
            ),
            None,
        );
    } else {
        log(&format!("Preset: {} | api_mode: {} | model: {} | inject keys: {:?} | prepend_messages: {} | append_messages: {} | degen_repeat: {}",
            cfg0.preset_name,
            cfg0.api_mode.as_str(),
            if cfg0.models.len() > 1 {
                format!("{:?} (round-robin)", cfg0.models)
            } else {
                cfg0.models.first().cloned().unwrap_or_default()
            },
            cfg0.inject.keys().collect::<Vec<_>>(),
            cfg0.prepend_messages.len(),
            cfg0.append_messages.len(),
            cfg0.degen_repeat), None);
        if cfg0.http3_enabled {
            log("Transport: HTTP/3 (QUIC / RFC 9114, 15s keepalive)", None);
        } else {
            log("Transport: HTTP/2 (TCP / RFC 9113)", None);
        }
        {
            let n = cfg0.api_keys.len();
            if n > 1 {
                log(
                    &format!("API keys: {} keys loaded, round-robin rotation enabled", n),
                    None,
                );
            } else {
                log("API key: 1 key loaded", None);
            }
        }
        {
            let m = cfg0.models.len();
            if m > 1 {
                log(
                    &format!(
                        "Models: {} upstream models loaded, round-robin rotation enabled ({})",
                        m,
                        cfg0.models.join(" <-> ")
                    ),
                    None,
                );
            }
        }
    }
    log(
        &format!(
            "Exposed models: {:?}",
            exposed_models()
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|m| m["id"].as_str())
                .collect::<Vec<_>>()
        ),
        None,
    );
    log(&format!("Max concurrency: {}", cfg0.max_concurrency), None);
    log(
        &format!(
            "Timeouts: connect={:.1}s read={:.1}s",
            cfg0.connect_timeout.as_secs_f64(),

            cfg0.read_timeout.as_secs_f64()
        ),
        None,
    );
    log(
        &format!(
            "Retry: {} attempts, exponential backoff (base 1.0s)",
            cfg0.max_retry
        ),
        None,
    );
    let any_h3 = slot_configs.iter().any(|c| c.http3_enabled);
    let all_h3 = slot_configs.iter().all(|c| c.http3_enabled);
    if all_h3 {
        log(
            "Engine: axum server + quinn/h3 HTTP/3 upstream (native Rust binary)",
            None,
        );
    } else if any_h3 {
        log(
            "Engine: axum server + hybrid HTTP/2 (hyper/h2) & HTTP/3 (quinn/h3) upstream (native Rust binary)",
            None,
        );
    } else {
        log(
            "Engine: axum server + hyper/h2 direct HTTP/2 upstream (native Rust binary)",
            None,
        );
    }
    if slot_configs.len() == 1 {
        if cfg0.brotli_enabled {
            log(
                &format!(
                    "Brotli upload compression: ON (engine: mbrotli AVX-512, base level {}, min {}B; >=256KB escalates to 10, clamped at q10)",
                    cfg0.brotli_level, cfg0.brotli_min_bytes
                ),
                None,
            );
        } else {
            log(
                "Brotli upload compression: OFF (preset did not opt in - set \"brotli\": true in config.json, or SOUFFLE_BROTLI=1)",
                None,
            );
        }
    }
    log(
        "Hermes trick: model name contains 'deepseek' → reasoning echo enabled",
        None,
    );

    let addr: SocketAddr = format!("{}:{}", cfg0.host, cfg0.port)
        .parse()
        .unwrap_or_else(|e| {
            eprintln!(
                "[FATAL] Invalid listen address '{}:{}': {}",
                cfg0.host, cfg0.port, e
            );
            std::process::exit(1);
        });

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("[FATAL] Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        });

    // TCP_NODELAY on every accepted connection. axum 0.8 does NOT set it
    // (axum #2521; Serve::tcp_nodelay existed in 0.7.6 and was removed in 0.8),
    // and Nagle is a measured TTFT stall for SSE traffic shapes (hyper #3269:
    // 8.62s -> 6.02s with nodelay on client-reuse traffic; sglang: ~13ms).
    // Zero-cost insurance on loopback.
    let listener = listener.tap_io(|tcp_stream| {
        let _ = tcp_stream.set_nodelay(true);
    });

    #[cfg(windows)]
    let wait_for_signal = async {
        let mut ctrl_c = tokio::signal::windows::ctrl_c().expect("Failed to register ctrl_c");
        let mut ctrl_break =
            tokio::signal::windows::ctrl_break().expect("Failed to register ctrl_break");
        tokio::select! {
            _ = ctrl_c.recv() => {
                log("Shutdown signal received (Ctrl+C), shutting down gracefully...", None);
            }
            _ = ctrl_break.recv() => {
                log("Shutdown signal received (Ctrl+Break), shutting down gracefully...", None);
            }
        }
    };
    #[cfg(not(windows))]
    let wait_for_signal = async {
        let _ = tokio::signal::ctrl_c().await;
        log(
            "Shutdown signal received (Ctrl+C), shutting down gracefully...",
            None,
        );
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    tokio::spawn(async move {
        wait_for_signal.await;
        let _ = shutdown_tx.send(true);
    });

    let mut rx1 = shutdown_rx.clone();
    let axum_shutdown = async move {
        let _ = rx1.wait_for(|&v| v).await;
        log(
            "Shutdown signal received: no longer accepting; waiting for in-flight requests (close the window to force-exit).",
            None,
        );
    };

    // Await the server instead of racing it against a fixed timer. The old
    // 1.5 s window dropped axum::serve and cut live SSE streams mid-body while
    // logging that the drain had "completed".
    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(axum_shutdown)
        .await
    {
        eprintln!("[FATAL] Server error: {}", e);
    }

    // Let the log writer drain before the process exits (the writer thread is a
    // daemon; pending lines flush within microseconds of the last send).
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sse_reasoning_delta(payload: &str) -> String {
        format!(
            "data: {{\"choices\":[{{\"delta\":{{\"reasoning_content\":{}}}}}]}}\n\n",
            json!(payload)
        )
    }

    fn sse_content_delta(payload: &str) -> String {
        format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":{}}}}}]}}\n\n",
            json!(payload)
        )
    }

    #[test]
    fn first_token_timing_observes_once_and_commits_only_when_successful() {
        let stats = ProxyStats::new();
        let start = Instant::now();
        let timing = FirstTokenTiming::new(start);
        assert_eq!(
            timing.record_at(start + Duration::from_millis(37)),
            Some(0.037)
        );
        assert_eq!(timing.record_at(start + Duration::from_millis(90)), None);
        assert_eq!(stats.ttft_samples.load(Ordering::Relaxed), 0);
        timing.commit(&stats);
        timing.commit(&stats);
        assert_eq!(stats.ttft_samples.load(Ordering::Relaxed), 1);
        assert_eq!(stats.total_ttft_us.load(Ordering::Relaxed), 37_000);

        FirstTokenTiming::new(start).commit(&stats);
        assert_eq!(stats.ttft_samples.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn chat_sse_ttft_probe_ignores_setup_empty_and_terminal_frames() {
        for line in [
            b"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}".as_slice(),
            b"data: {\"choices\":[{\"delta\":{\"content\":\"\",\"reasoning_content\":\"\"}}]}"
                .as_slice(),
            b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}".as_slice(),
            b"data: {\"usage\":{\"completion_tokens\":0}}".as_slice(),
            b"data: [DONE]".as_slice(),
        ] {
            assert!(!chat_sse_line_has_generated_delta(line), "{line:?}");
        }
        for line in [
            b"data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}".as_slice(),
            b"data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"thinking\"}}]}".as_slice(),
            b"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"name\":\"lookup\"}}]}}]}".as_slice(),
            b"data: {\"choices\":[{\"delta\":{\"function_call\":{\"arguments\":\"{}\"}}}]}".as_slice(),
        ] {
            assert!(chat_sse_line_has_generated_delta(line), "{line:?}");
        }
    }

    #[tokio::test]
    async fn chat_ttft_uses_final_fragment_of_first_nonempty_delta() {
        let setup =
            Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n");
        let empty_delta =
            Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"\"}}]}\n\n");
        let first_delta_fragment =
            Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"first");
        let final_delta_fragment = Bytes::from_static(b" token\"}}]}\n\n");
        let done = Bytes::from_static(b"data: [DONE]\n\n");
        let (addr, _, _, _) =
            spawn_mock_h2_server(vec![MockUpstreamReply::StreamDelayedSchedule {
                steps: vec![
                    (setup, Duration::from_millis(10)),
                    (empty_delta, Duration::from_millis(30)),
                    (first_delta_fragment, Duration::from_millis(20)),
                    (final_delta_fragment, Duration::from_millis(40)),
                    (done, Duration::ZERO),
                ],
            }])
            .await;
        let state = make_test_app_state(&format!("http://{addr}/v1"), false, 1);
        let response = handle_chat_completions(State(state.clone()), make_chat_req(true)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(std::str::from_utf8(&body).unwrap().contains("first token"));
        let stats = state.stats.snapshot().await;
        let ttft = stats["avg_ttft_seconds"].as_f64().unwrap();
        assert!((0.08..1.0).contains(&ttft), "unexpected TTFT: {ttft}s");
        assert_eq!(state.stats.ttft_samples.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn chat_ttft_preserves_first_chunk_observation_before_downstream_poll() {
        let (addr, _, _, _) = spawn_mock_h2_server(vec![MockUpstreamReply::StreamChunks {
            chunks: vec![Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: [DONE]\n\n")],
            delay_ms: 0,
        }]).await;
        let state = make_test_app_state(&format!("http://{addr}/v1"), false, 1);
        let start = Instant::now();
        let response = handle_chat_completions(State(state.clone()), make_chat_req(true)).await;
        tokio::time::sleep(Duration::from_millis(120)).await;
        let poll_started = start.elapsed();
        axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let measured = Duration::from_micros(state.stats.total_ttft_us.load(Ordering::Relaxed));
        assert_eq!(state.stats.ttft_samples.load(Ordering::Relaxed), 1);
        assert!(measured + Duration::from_millis(90) < poll_started);
    }

    #[tokio::test]
    async fn chat_ttft_excludes_buffered_empty_and_in_band_error_responses() {
        let wire = b"data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\ndata: {\"error\":{\"message\":\"generation failed\"}}\n\ndata: [DONE]\n\n";
        for drop_at_done in [false, true] {
            let (addr, _, _, _) = spawn_mock_h2_server(vec![MockUpstreamReply::StreamChunks {
                chunks: vec![Bytes::from_static(wire)],
                delay_ms: 0,
            }]).await;
            let state = make_test_app_state(&format!("http://{addr}/v1"), false, 1);
            let response = handle_chat_completions(State(state.clone()), make_chat_req(true)).await;
            if drop_at_done {
                let mut body = response.into_body().into_data_stream();
                let first = body.next().await.unwrap().unwrap();
                assert_eq!(first.as_ref(), wire);
                drop(body);
            } else {
                assert_eq!(axum::body::to_bytes(response.into_body(), 4096).await.unwrap().as_ref(), wire);
            }
            assert_eq!(state.stats.ttft_samples.load(Ordering::Relaxed), 0);
        }
        for (reply, stream) in [
            (MockUpstreamReply::BufferedJson(Bytes::from_static(b"{\"choices\":[{\"message\":{\"content\":\"hello\"}}]}")), false),
            (MockUpstreamReply::StreamChunks { chunks: vec![Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\ndata: [DONE]\n\n")], delay_ms: 0 }, true),
        ] {
            let (addr, _, _, _) = spawn_mock_h2_server(vec![reply]).await;
            let state = make_test_app_state(&format!("http://{addr}/v1"), false, 1);
            let response = handle_chat_completions(State(state.clone()), make_chat_req(stream)).await;
            axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
            assert_eq!(state.stats.ttft_samples.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn preset_degen_repeat_opt_in_and_no_env_override() {
        // Absent -> false
        let base = json!({
            "model": "m",
            "key_env": "TEST_DEGEN_REPEAT_NO_OVERRIDE",
            "upstream_bases": ["https://ex.com/v1"]
        });
        let p_absent = Preset::from_value("absent", &base).expect("absent degen_repeat should parse");
        assert!(!p_absent.degen_repeat);

        // Explicit true / false
        let mut t = base.clone();
        t["degen_repeat"] = json!(true);
        let p_true = Preset::from_value("enabled", &t).expect("bool true should parse");
        assert!(p_true.degen_repeat);

        let mut f = base.clone();
        f["degen_repeat"] = json!(false);
        let p_false = Preset::from_value("disabled", &f).expect("bool false should parse");
        assert!(!p_false.degen_repeat);

        // Non-boolean must fail fatally at preset parse time
        for bad in [json!("true"), json!(1), json!(0), json!(null), json!([]), json!({})] {
            let mut v = base.clone();
            v["degen_repeat"] = bad.clone();
            let err = Preset::from_value("bad", &v).expect_err("non-bool degen_repeat must fail");
            assert!(
                err.contains("field 'degen_repeat' must be a boolean"),
                "unexpected error for {bad:?}: {err}"
            );
        }

        // No env override: setting SOUFFLE_DEGEN_REPEAT=1 must NOT flip a disabled preset on
        std::env::set_var("TEST_DEGEN_REPEAT_NO_OVERRIDE", "sk-test");
        std::env::set_var("SOUFFLE_DEGEN_REPEAT", "1");
        let cfg = Config::from_preset(&p_false);
        std::env::remove_var("SOUFFLE_DEGEN_REPEAT");
        std::env::remove_var("TEST_DEGEN_REPEAT_NO_OVERRIDE");
        assert!(!cfg.degen_repeat);
    }

    #[test]
    fn repeat_watch_catches_mid_stream_glued_and_spaced_loops() {
        // 1. Varied non-looping reasoning prefix (1.5 KB), then glued "console" across 3-byte splits
        let mut w1 = RepeatWatch::new();
        let mut prefix = String::new();
        for i in 0..30 {
            prefix.push_str(&format!(
                "Step {i}: analyzing module_{i} layout and transport path {idx} in detail. ",
                idx = i * 7 + 3
            ));
        }
        for chunk in prefix.as_bytes().chunks(13) {
            assert!(
                w1.feed_text(RepeatChannel::Reasoning, std::str::from_utf8(chunk).unwrap())
                    .is_none()
            );
        }
        let glued = "console".repeat(80);
        let mut hit_at = None;
        let mut fed = 0usize;
        for chunk in glued.as_bytes().chunks(3) {
            fed += chunk.len();
            if let Some(m) = w1.feed_text(RepeatChannel::Reasoning, std::str::from_utf8(chunk).unwrap()) {
                assert_eq!(m.channel, RepeatChannel::Reasoning);
                assert_eq!(m.period, 7);
                hit_at = Some(fed);
                break;
            }
        }
        let bytes_to_detect = hit_at.expect("glued 'console' loop must trigger mid-stream");
        assert!(
            bytes_to_detect <= 512,
            "must catch glued loop quickly, took {bytes_to_detect}B"
        );

        // 2. Varied non-looping content prefix, then spaced "i need " loop
        let mut w2 = RepeatWatch::new();
        let mut content_prefix = String::new();
        for i in 0..25 {
            content_prefix.push_str(&format!(
                "Item {i}: checking configuration key_{i} before applying delta. "
            ));
        }
        assert!(w2
            .feed_text(RepeatChannel::Content, &content_prefix)
            .is_none());
        let spaced = "i need ".repeat(80);
        let mut hit2 = None;
        let mut fed2 = 0usize;
        for chunk in spaced.as_bytes().chunks(5) {
            fed2 += chunk.len();
            if let Some(m) = w2.feed_text(RepeatChannel::Content, std::str::from_utf8(chunk).unwrap()) {
                assert_eq!(m.channel, RepeatChannel::Content);
                assert_eq!(m.period, 7);
                hit2 = Some(fed2);
                break;
            }
        }
        let bytes2 = hit2.expect("spaced 'i need ' loop must trigger mid-stream");
        assert!(
            bytes2 <= 512,
            "must catch spaced loop quickly, took {bytes2}B"
        );

        // 3. UTF-8 multi-byte word loop
        let mut w3 = RepeatWatch::new();
        let utf8_loop = "tôi cần kiểm tra ".repeat(40);
        assert!(w3.feed_text(RepeatChannel::Reasoning, &utf8_loop).is_some());
    }

    #[test]
    fn repeat_watch_channel_isolation_and_sse_line_feeding() {
        let mut w = RepeatWatch::new();
        // Alternating healthy content must not break detection of a reasoning loop
        for i in 0..80 {
            let line_r = "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"console\"}}]}";
            let line_c = format!(
                "data: {{\"choices\":[{{\"delta\":{{\"content\":\"step {i} normal output \"}}}}]}}"
            );
            if w.feed_sse_line(line_r.as_bytes()).is_some() {
                return;
            }
            assert!(
                w.feed_sse_line(line_c.as_bytes()).is_none(),
                "healthy content should not trigger"
            );
        }
        panic!("reasoning loop must trigger even when interleaved with normal content deltas");
    }

    #[test]
    fn repeat_watch_avoids_false_positives_and_retires_exclamation_sniff() {
        let mut w = RepeatWatch::new();
        // Markdown horizontal rules, tables, indentation, hex, base64 padding
        assert!(w.feed_text(RepeatChannel::Content, &"-".repeat(1000)).is_none());
        assert!(w.feed_text(RepeatChannel::Content, &"=".repeat(1000)).is_none());
        assert!(w.feed_text(RepeatChannel::Content, &"| --- ".repeat(150)).is_none());
        assert!(w.feed_text(RepeatChannel::Content, &"00000000 ".repeat(150)).is_none());
        assert!(w.feed_text(RepeatChannel::Content, &"    \n".repeat(200)).is_none());
        assert!(w.feed_text(RepeatChannel::Content, &"V".repeat(1000)).is_none());
        // Short legitimate repeats (< 256B span)
        assert!(w.feed_text(RepeatChannel::Content, &"i need ".repeat(4)).is_none());
        assert!(w.feed_text(RepeatChannel::Content, &"break;\n".repeat(8)).is_none());
        // Legacy kimi '!' mark-collapse is retired
        assert!(w.feed_text(RepeatChannel::Reasoning, &"!".repeat(64)).is_none());
    }

    #[test]
    fn buffered_response_detects_mid_response_repetition_and_keeps_compat_edges() {
        // Varied normal text + mid-response repetition + trailing closing text
        let mut reasoning = String::new();
        for i in 0..35 {
            reasoning.push_str(&format!(
                "Step {i}: inspecting repository module_{i} and cargo dependency graph. "
            ));
        }
        let healthy_only = json!({
            "choices": [{
                "message": {"role": "assistant", "content": "Done.", "reasoning_content": reasoning},
                "finish_reason": "stop"
            }]
        })
        .to_string();
        assert!(
            serde_json::from_slice::<BufferedResponse>(healthy_only.as_bytes())
                .unwrap()
                .detect_repetition()
                .is_none(),
            "varied normal reasoning must not trigger"
        );

        reasoning.push_str(&"i need ".repeat(60));
        reasoning.push_str("\n</think>");
        let body = json!({
            "choices": [{
                "message": {"role": "assistant", "content": "Done.", "reasoning_content": reasoning},
                "finish_reason": "length"
            }],
            "usage": {"completion_tokens": 500}
        })
        .to_string();
        let parsed = serde_json::from_slice::<BufferedResponse>(body.as_bytes()).unwrap();
        let hit = parsed
            .detect_repetition()
            .expect("buffered response with mid-response repetition + trailing text must trigger");
        assert_eq!(hit.channel, RepeatChannel::Reasoning);
        assert_eq!(hit.period, 7);

        // Legacy 32 '!' no longer triggers
        let marks_body = json!({
            "choices": [{
                "message": {"role": "assistant", "content": null,
                            "reasoning_content": "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"},
                "finish_reason": "stop"
            }]
        })
        .to_string();
        let parsed_marks = serde_json::from_slice::<BufferedResponse>(marks_body.as_bytes()).unwrap();
        assert!(parsed_marks.detect_repetition().is_none());

        // Multimodal array content still parses usage and does not panic
        let mm_body = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "Hello world"}]
                }
            }],
            "usage": {"prompt_tokens": 12, "completion_tokens": 4}
        })
        .to_string();
        let parsed_mm = serde_json::from_slice::<BufferedResponse>(mm_body.as_bytes()).unwrap();
        assert!(parsed_mm.detect_repetition().is_none());
        let usage = parsed_mm.extract_usage().unwrap();
        assert_eq!(usage.prompt_tokens, Some(12));
        assert_eq!(usage.completion_tokens, Some(4));

        // Legacy text completion field still parses cleanly
        let legacy_body = json!({
            "choices": [{"text": "Hello world"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2}
        })
        .to_string();
        let parsed_legacy = serde_json::from_slice::<BufferedResponse>(legacy_body.as_bytes()).unwrap();
        assert!(parsed_legacy.detect_repetition().is_none());
    }

    #[derive(Clone)]
    pub(super) enum MockUpstreamReply {
        StreamChunks { chunks: Vec<Bytes>, delay_ms: u64 },
        StreamDelayedSchedule { steps: Vec<(Bytes, Duration)> },
        BufferedJson(Bytes),
        BufferedDelay { body: Bytes, delay: Duration },
        BufferedReset,
        StreamStallAfterFirst { first: Bytes, stall: Duration },
        GoAwayEnhanceYourCalmPreHeader,
        GoAwayEnhanceYourCalmFirstChunk,
    }

    pub(super) async fn spawn_mock_h2_server(
        replies: Vec<MockUpstreamReply>,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        Arc<std::sync::atomic::AtomicBool>,
    ) {
        spawn_mock_h2_server_with_bodies(replies, Arc::new(std::sync::Mutex::new(Vec::new()))).await
    }

    /// Same mock, plus every received request body in arrival order.
    async fn spawn_mock_h2_server_with_bodies(
        replies: Vec<MockUpstreamReply>,
        bodies: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        Arc<std::sync::atomic::AtomicBool>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let chunks_sent = Arc::new(AtomicUsize::new(0));
        let reset_observed = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let attempts_srv = attempts.clone();
        let chunks_srv = chunks_sent.clone();
        let reset_srv = reset_observed.clone();

        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let replies = replies.clone();
                let attempts = attempts_srv.clone();
                let chunks_sent = chunks_srv.clone();
                let reset_observed = reset_srv.clone();
                let bodies = bodies.clone();
                tokio::spawn(async move {
                    let mut h2_conn = match h2::server::handshake(tcp).await {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    while let Some(Ok((req, mut respond))) = h2_conn.accept().await {
                        let mut req_body = req.into_body();
                        let mut captured: Vec<u8> = Vec::new();
                        while let Some(Ok(frame)) = req_body.data().await {
                            let _ = req_body.flow_control().release_capacity(frame.len());
                            captured.extend_from_slice(&frame);
                        }
                        if !captured.is_empty() {
                            bodies.lock().unwrap().push(captured);
                        }
                        let idx = attempts.fetch_add(1, Ordering::SeqCst);
                        let reply = replies.get(idx).or_else(|| replies.last()).cloned().unwrap();
                        if matches!(reply, MockUpstreamReply::GoAwayEnhanceYourCalmPreHeader) {
                            h2_conn.abrupt_shutdown(h2::Reason::ENHANCE_YOUR_CALM);
                            while h2_conn.accept().await.is_some() {}
                            return;
                        }
                        if matches!(reply, MockUpstreamReply::GoAwayEnhanceYourCalmFirstChunk) {
                            let resp = http::Response::builder()
                                .status(200)
                                .header("content-type", "text/event-stream")
                                .body(())
                                .unwrap();
                            let _send = respond.send_response(resp, false);
                            h2_conn.abrupt_shutdown(h2::Reason::ENHANCE_YOUR_CALM);
                            while h2_conn.accept().await.is_some() {}
                            return;
                        }
                        let chunks_sent = chunks_sent.clone();
                        let reset_observed = reset_observed.clone();
                        tokio::spawn(async move {
                            let content_type = match reply {
                                MockUpstreamReply::StreamChunks { .. }
                                | MockUpstreamReply::StreamDelayedSchedule { .. }
                                | MockUpstreamReply::StreamStallAfterFirst { .. }
                                | MockUpstreamReply::GoAwayEnhanceYourCalmPreHeader
                                | MockUpstreamReply::GoAwayEnhanceYourCalmFirstChunk => {
                                    "text/event-stream"
                                }
                                MockUpstreamReply::BufferedJson(_)
                                | MockUpstreamReply::BufferedDelay { .. }
                                | MockUpstreamReply::BufferedReset => "application/json",
                            };
                            let resp = http::Response::builder()
                                .status(200)
                                .header("content-type", content_type)
                                .body(())
                                .unwrap();
                            match reply {
                                MockUpstreamReply::BufferedJson(body) => {
                                    if let Ok(mut send) = respond.send_response(resp, body.is_empty()) {
                                        if !body.is_empty() {
                                            let _ = send.send_data(body, true);
                                        }
                                    }
                                }
                                MockUpstreamReply::BufferedDelay { body, delay } => {
                                    if let Ok(mut send) = respond.send_response(resp, false) {
                                        tokio::time::sleep(delay).await;
                                        let _ = send.send_data(body, true);
                                    }
                                }
                                MockUpstreamReply::BufferedReset => {
                                    if let Ok(mut send) = respond.send_response(resp, false) {
                                        send.send_reset(h2::Reason::INTERNAL_ERROR);
                                    }
                                }
                                MockUpstreamReply::StreamStallAfterFirst { first, stall } => {
                                    if let Ok(mut send) = respond.send_response(resp, false) {
                                        let _ = send.send_data(first, false);
                                        chunks_sent.fetch_add(1, Ordering::SeqCst);
                                        tokio::time::sleep(stall).await;
                                        let _ = send.send_data(Bytes::from_static(b"data: [DONE]\n\n"), true);
                                    }
                                }
                                MockUpstreamReply::StreamDelayedSchedule { steps } => {
                                    if let Ok(mut send) = respond.send_response(resp, false) {
                                        let total = steps.len();
                                        for (i, (chunk, delay)) in steps.into_iter().enumerate() {
                                            if !delay.is_zero() {
                                                tokio::time::sleep(delay).await;
                                            }
                                            let is_last = i + 1 == total;
                                            if send.send_data(chunk, is_last).is_err() {
                                                reset_observed.store(true, Ordering::SeqCst);
                                                return;
                                            }
                                            chunks_sent.fetch_add(1, Ordering::SeqCst);
                                        }
                                    }
                                }
                                MockUpstreamReply::GoAwayEnhanceYourCalmPreHeader
                                | MockUpstreamReply::GoAwayEnhanceYourCalmFirstChunk => {}
                                MockUpstreamReply::StreamChunks { chunks, delay_ms } => {
                                    if let Ok(mut send) = respond.send_response(resp, false) {
                                        let total = chunks.len();
                                        for (i, chunk) in chunks.into_iter().enumerate() {
                                            send.reserve_capacity(chunk.len());
                                            let ready = futures_util::future::poll_fn(|cx| {
                                                if send.poll_reset(cx).is_ready() {
                                                    return std::task::Poll::Ready(false);
                                                }
                                                match send.poll_capacity(cx) {
                                                    std::task::Poll::Ready(Some(Ok(n))) if n > 0 => {
                                                        std::task::Poll::Ready(true)
                                                    }
                                                    std::task::Poll::Ready(Some(Ok(_)))
                                                    | std::task::Poll::Pending => {
                                                        std::task::Poll::Pending
                                                    }
                                                    std::task::Poll::Ready(Some(Err(_)))
                                                    | std::task::Poll::Ready(None) => {
                                                        std::task::Poll::Ready(false)
                                                    }
                                                }
                                            })
                                            .await;
                                            if !ready {
                                                reset_observed.store(true, Ordering::SeqCst);
                                                return;
                                            }
                                            let is_last = i + 1 == total;
                                            if send.send_data(chunk, is_last).is_err() {
                                                reset_observed.store(true, Ordering::SeqCst);
                                                return;
                                            }
                                            chunks_sent.fetch_add(1, Ordering::SeqCst);
                                            if !is_last && delay_ms > 0 {
                                                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }
                });
            }
        });

        (addr, attempts, chunks_sent, reset_observed)
    }

    async fn spawn_header_capture_h2_server() -> (
        std::net::SocketAddr,
        Arc<std::sync::Mutex<Vec<HeaderMap>>>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_server = captured.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let captured = captured_server.clone();
                tokio::spawn(async move {
                    let Ok(mut connection) = h2::server::handshake(tcp).await else {
                        return;
                    };
                    while let Some(Ok((request, mut respond))) = connection.accept().await {
                        captured.lock().unwrap().push(request.headers().clone());
                        let mut body = request.into_body();
                        while let Some(Ok(frame)) = body.data().await {
                            let _ = body.flow_control().release_capacity(frame.len());
                        }
                        let response = http::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(())
                            .unwrap();
                        if let Ok(mut send) = respond.send_response(response, false) {
                            let _ = send.send_data(
                                Bytes::from_static(br#"{"status":"completed","output":[]}"#),
                                true,
                            );
                        }
                    }
                });
            }
        });
        (addr, captured)
    }

    pub(super) fn make_test_app_state(
        upstream_base: &str,
        degen_repeat: bool,
        max_retry: usize,
    ) -> Arc<AppState> {
        make_test_app_state_with_headers(
            upstream_base,
            degen_repeat,
            max_retry,
            HeaderOverrides::default(),
        )
    }

    fn make_test_app_state_with_headers(
        upstream_base: &str,
        degen_repeat: bool,
        max_retry: usize,
        extra_headers: HeaderOverrides,
    ) -> Arc<AppState> {
        let models = vec!["test-model".to_string()];
        let models_raw = models_to_raw(&models).unwrap();
        let config = Arc::new(Config {
            api_mode: responses::ApiMode::ChatCompletions,
            host: "127.0.0.1".to_string(),
            port: 0,
            upstream_bases: upstream_base.to_string(),
            max_concurrency: 20,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            keepalive_expiry: Duration::from_secs(0),
            max_retry,
            degen_repeat,
            max_body_bytes: 1024 * 1024,
            brotli_enabled: false,
            brotli_level: 9,
            brotli_min_bytes: 1024,
            api_keys: vec!["sk-test".to_string()],
            auth_headers: vec![HeaderValue::from_static("Bearer sk-test")],
            preset_name: "test-preset".to_string(),
            models,
            models_raw,
            inject: serde_json::Map::new(),
            inject_raw: BTreeMap::new(),
            append_messages: Vec::new(),
            append_raw: None,
            prepend_messages: Vec::new(),
            prepend_raw: None,
            souffle_pout: false,
            http3_enabled: false,
            extra_headers,
        });
        let client = UpstreamClient::H2(
            H2Client::new(
                &config.upstream_bases,
                config.connect_timeout,
                config.keepalive_expiry,
                true,
            )
            .unwrap(),
        );
        Arc::new(AppState {
            slots: vec![Arc::new(PresetRuntime {
                config,
                client,
                model_index: AtomicUsize::new(0),
                key_index: AtomicUsize::new(0),
            })],
            semaphore: Arc::new(Semaphore::new(20)),
            stats: Arc::new(ProxyStats::new()),
            stripped_headers: [
                header::CONTENT_LENGTH,
                header::TRANSFER_ENCODING,
                header::CONNECTION,
                header::CONTENT_ENCODING,
            ]
            .into_iter()
            .collect(),
        })
    }

    fn make_chat_req(stream: bool) -> Request {
        let body = json!({
            "model": "deepseek-souffle",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": stream
        })
        .to_string();
        Request::builder()
            .method(Method::POST)
            .uri("/v1/chat/completions")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn e2e_stream_midstream_repeat_aborts_downstream_and_cancels_upstream() {
        let mut loop_chunks = vec![
            Bytes::from(sse_reasoning_delta("First let me examine the repository structure carefully. ")),
            Bytes::from(sse_reasoning_delta("Here is what I found in the configuration: ")),
        ];
        for _ in 0..400 {
            loop_chunks.push(Bytes::from(sse_reasoning_delta("console")));
        }
        loop_chunks.push(Bytes::from("data: [DONE]\n\n"));

        let (addr, attempts, chunks_sent, _reset_observed) = spawn_mock_h2_server(vec![
            MockUpstreamReply::StreamChunks {
                chunks: loop_chunks.clone(),
                delay_ms: 2,
            },
        ])
        .await;

        let state = make_test_app_state(&format!("http://{addr}/v1"), true, 2);
        let resp = handle_chat_completions(State(state.clone()), make_chat_req(true)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let mut data_stream = resp.into_body().into_data_stream();
        let mut received = Vec::new();
        let mut saw_abort_err = false;
        while let Some(item) = data_stream.next().await {
            match item {
                Ok(b) => received.extend_from_slice(&b),
                Err(_) => {
                    saw_abort_err = true;
                    break;
                }
            }
        }

        assert!(saw_abort_err, "mid-stream repetition loop must abort downstream with error");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(
            !received.is_empty(),
            "healthy opening prefix should have been streamed before loop started"
        );
        assert!(
            chunks_sent.load(Ordering::SeqCst) < 150,
            "proxy must cancel upstream stream early instead of reading all 400 loop chunks (sent {})",
            chunks_sent.load(Ordering::SeqCst)
        );
        assert_eq!(state.stats.error_count.load(Ordering::Relaxed), 1);

        // Opt-in disabled: identical loop chunks stream all the way to [DONE]
        let (addr_off, _, chunks_sent_off, _) = spawn_mock_h2_server(vec![
            MockUpstreamReply::StreamChunks {
                chunks: vec![
                    Bytes::from(sse_reasoning_delta("Prefix. ")),
                    Bytes::from(sse_reasoning_delta(&"console".repeat(60))),
                    Bytes::from("data: [DONE]\n\n"),
                ],
                delay_ms: 0,
            },
        ])
        .await;
        let state_off = make_test_app_state(&format!("http://{addr_off}/v1"), false, 2);
        let resp_off = handle_chat_completions(State(state_off), make_chat_req(true)).await;
        assert_eq!(resp_off.status(), StatusCode::OK);
        let body_off = axum::body::to_bytes(resp_off.into_body(), 1024 * 1024)
            .await
            .expect("opt-in disabled preset must complete stream without abort");
        assert!(std::str::from_utf8(&body_off).unwrap().contains("[DONE]"));
        assert_eq!(chunks_sent_off.load(Ordering::SeqCst), 3);

        // Content channel + SSE JSON split across two H2 frames mid-stream -> aborts
        let mut split_chunks = vec![
            Bytes::from(sse_content_delta("Here is the analysis of the issue: ")),
        ];
        for _ in 0..80 {
            let line = sse_content_delta("i need ");
            let mid = line.len() / 2;
            split_chunks.push(Bytes::copy_from_slice(&line.as_bytes()[..mid]));
            split_chunks.push(Bytes::copy_from_slice(&line.as_bytes()[mid..]));
        }
        split_chunks.push(Bytes::from("data: [DONE]\n\n"));
        let (addr_split, _, sent_split, _) = spawn_mock_h2_server(vec![
            MockUpstreamReply::StreamChunks {
                chunks: split_chunks,
                delay_ms: 1,
            },
        ])
        .await;
        let state_split = make_test_app_state(&format!("http://{addr_split}/v1"), true, 2);
        let resp_split = handle_chat_completions(State(state_split), make_chat_req(true)).await;
        assert_eq!(resp_split.status(), StatusCode::OK);
        let mut ds_split = resp_split.into_body().into_data_stream();
        let mut aborted_split = false;
        while let Some(item) = ds_split.next().await {
            if item.is_err() {
                aborted_split = true;
                break;
            }
        }
        assert!(aborted_split, "content channel loop across split SSE lines must abort");
        assert!(sent_split.load(Ordering::SeqCst) < 120);
    }

    #[tokio::test]
    async fn e2e_stream_chunk1_repeat_retries_then_recovers_and_502_on_exhaustion() {
        let bad_first = Bytes::from(sse_reasoning_delta(&"i need ".repeat(60)));
        let good_second = Bytes::from(format!(
            "{}data: [DONE]\n\n",
            sse_content_delta("Recovered clean response.")
        ));

        let (addr, attempts, _, _) = spawn_mock_h2_server(vec![
            MockUpstreamReply::StreamChunks {
                chunks: vec![bad_first.clone(), Bytes::from("data: [DONE]\n\n")],
                delay_ms: 0,
            },
            MockUpstreamReply::StreamChunks {
                chunks: vec![good_second],
                delay_ms: 0,
            },
        ])
        .await;

        let state = make_test_app_state(&format!("http://{addr}/v1"), true, 2);
        let resp = handle_chat_completions(State(state), make_chat_req(true)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(body_str.contains("Recovered clean response."));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        // Exhaustion -> 502 degenerate_output_error
        let (addr_fail, attempts_fail, _, _) = spawn_mock_h2_server(vec![
            MockUpstreamReply::StreamChunks {
                chunks: vec![bad_first, Bytes::from("data: [DONE]\n\n")],
                delay_ms: 0,
            },
        ])
        .await;
        let state_fail = make_test_app_state(&format!("http://{addr_fail}/v1"), true, 2);
        let resp_fail = handle_chat_completions(State(state_fail.clone()), make_chat_req(true)).await;
        assert_eq!(resp_fail.status(), StatusCode::BAD_GATEWAY);
        let err_bytes = axum::body::to_bytes(resp_fail.into_body(), 64 * 1024).await.unwrap();
        let err_json: Value = serde_json::from_slice(&err_bytes).unwrap();
        assert_eq!(err_json["error"]["type"], "degenerate_output_error");
        assert_eq!(attempts_fail.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn e2e_nonstream_buffered_repeat_retries_and_502_on_exhaustion() {
        let mut bad_reasoning = String::new();
        for i in 0..30 {
            bad_reasoning.push_str(&format!("Checking item {i} in the workspace carefully. "));
        }
        bad_reasoning.push_str(&"console".repeat(60));
        let bad_json = Bytes::from(
            json!({
                "choices": [{"message": {"role": "assistant", "content": "ok", "reasoning_content": bad_reasoning}, "finish_reason": "length"}],
                "usage": {"completion_tokens": 200}
            })
            .to_string(),
        );
        let good_json = Bytes::from(
            json!({
                "choices": [{"message": {"role": "assistant", "content": "Clean final answer."}, "finish_reason": "stop"}],
                "usage": {"completion_tokens": 5}
            })
            .to_string(),
        );

        let (addr, attempts, _, _) = spawn_mock_h2_server(vec![
            MockUpstreamReply::BufferedJson(bad_json.clone()),
            MockUpstreamReply::BufferedJson(good_json),
        ])
        .await;
        let state = make_test_app_state(&format!("http://{addr}/v1"), true, 2);
        let resp = handle_chat_completions(State(state), make_chat_req(false)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        assert!(std::str::from_utf8(&bytes).unwrap().contains("Clean final answer."));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        // Exhaustion -> 502 degenerate_output_error
        let (addr_fail, attempts_fail, _, _) =
            spawn_mock_h2_server(vec![MockUpstreamReply::BufferedJson(bad_json)]).await;
        let state_fail = make_test_app_state(&format!("http://{addr_fail}/v1"), true, 2);
        let resp_fail = handle_chat_completions(State(state_fail), make_chat_req(false)).await;
        assert_eq!(resp_fail.status(), StatusCode::BAD_GATEWAY);
        let err_bytes = axum::body::to_bytes(resp_fail.into_body(), 64 * 1024).await.unwrap();
        let err_json: Value = serde_json::from_slice(&err_bytes).unwrap();
        assert_eq!(err_json["error"]["type"], "degenerate_output_error");
        assert_eq!(attempts_fail.load(Ordering::SeqCst), 2);
    }

    async fn read_stats_json(state: &Arc<AppState>) -> Value {
        let resp = handle_stats(State(state.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn e2e_stats_active_requests_tracks_streaming_lifetime() {
        let (addr, _attempts, _chunks_sent, _reset_observed) = spawn_mock_h2_server(vec![
            MockUpstreamReply::StreamChunks {
                chunks: vec![
                    Bytes::from(sse_content_delta("first ")),
                    Bytes::from(sse_content_delta("second ")),
                    Bytes::from("data: [DONE]\n\n"),
                ],
                delay_ms: 40,
            },
            MockUpstreamReply::StreamChunks {
                chunks: vec![
                    Bytes::from(sse_content_delta("first ")),
                    Bytes::from(sse_content_delta("second ")),
                    Bytes::from("data: [DONE]\n\n"),
                ],
                delay_ms: 40,
            },
        ])
        .await;

        let state = make_test_app_state(&format!("http://{addr}/v1"), false, 1);

        // 1. Streaming response returns after TTFT: active_requests must stay 1 until body finishes.
        let resp = handle_chat_completions(State(state.clone()), make_chat_req(true)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let mid_stats = read_stats_json(&state).await;
        assert_eq!(
            mid_stats["active_requests"], 1,
            "active_requests must remain 1 while streaming body is still open"
        );

        let mut ds = resp.into_body().into_data_stream();
        let first = ds.next().await.expect("chunk 1").expect("valid chunk 1");
        assert!(!first.is_empty());
        let after_first = read_stats_json(&state).await;
        assert_eq!(
            after_first["active_requests"], 1,
            "active_requests must stay 1 mid-stream before [DONE]"
        );

        while let Some(item) = ds.next().await {
            item.expect("remaining chunks");
        }
        drop(ds);
        let after_done = read_stats_json(&state).await;
        assert_eq!(
            after_done["active_requests"], 0,
            "active_requests must return to 0 after stream completes"
        );

        // 2. Client disconnects mid-stream (drops response stream early) -> still drops back to 0.
        let resp2 = handle_chat_completions(State(state.clone()), make_chat_req(true)).await;
        assert_eq!(resp2.status(), StatusCode::OK);
        assert_eq!(read_stats_json(&state).await["active_requests"], 1);
        let mut ds2 = resp2.into_body().into_data_stream();
        let _ = ds2.next().await;
        assert_eq!(read_stats_json(&state).await["active_requests"], 1);
        drop(ds2);
        assert_eq!(
            read_stats_json(&state).await["active_requests"], 0,
            "active_requests must decrement when streaming client drops mid-flight"
        );
    }

    #[test]
    fn brotli_roundtrip_q10() {
        let mut body = String::from(r#"{"model":"x","messages":[{"role":"user","content":"#);
        while body.len() < 40_000 {
            body.push_str("pack my box with five dozen liquor jugs. ");
        }
        body.push_str(r#""}]}"#);
        let comp = brotli_compress_bytes(body.as_bytes(), 10)
            .expect("encoder must not error")
            .expect("compression must shrink repetitive JSON");
        assert!(
            comp.len() * 4 < body.len(),
            "q10 should crush repetitive JSON, got {}B from {}B",
            comp.len(),
            body.len()
        );
        let mut decompressor = mbrotli::Decompressor::new(mbrotli::DecoderConfig::default())
            .expect("decompressor must initialize");
        let out = decompressor
            .decompress(&comp)
            .expect("decompression must succeed");
        assert_eq!(out, body.as_bytes());
    }

    #[test]
    fn brotli_never_expands() {
        // xorshift bytes are incompressible: the guard must never emit a
        // body larger than the input.
        let mut data = Vec::with_capacity(64 * 1024);
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..8 * 1024 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            data.extend_from_slice(&x.to_le_bytes());
        }
        match brotli_compress_bytes(&data, 10) {
            Ok(Some(comp)) => assert!(comp.len() < data.len()),
            Ok(None) => {} // expansion guard fired — correct behavior
            Err(e) => panic!("encoder error on incompressible data: {e}"),
        }
    }

    #[test]
    fn brotli_level_curve() {
        // Base level for <256KB is q9.
        for &len in &[1usize, 1024, 100 * 1024, 200 * 1024] {
            assert_eq!(brotli_level_for(9, len), 9);
        }
        // >=256KB escalates to max(base, 10).
        for &len in &[256 * 1024, 300 * 1024, 500 * 1024, 1023 * 1024] {
            assert_eq!(brotli_level_for(9, len), 10);
        }
        // >=1MB is also clamped to max quality 10.
        for &len in &[1024 * 1024, 16 * 1024 * 1024] {
            assert_eq!(brotli_level_for(9, len), 10);
        }
        // A base above is clamped to 10.
        assert_eq!(brotli_level_for(11, 10 * 1024), 10);
        assert_eq!(brotli_level_for(10, 10 * 1024), 10);
    }

    #[test]
    fn brotli_whole_feature_optin_parses() {
        let v = json!({
            "name": "brotli-test",
            "model": "m",
            "upstream_bases": ["https://x.invalid/v1"],
            "brotli": true
        });
        assert_eq!(
            Preset::from_value("brotli-test", &v).unwrap().brotli,
            Some(true)
        );
        let bare = json!({"name": "t", "model": "m", "upstream_bases": ["https://x.invalid/v1"]});
        assert_eq!(Preset::from_value("t", &bare).unwrap().brotli, None);
        let off = json!({"name": "t", "model": "m", "upstream_bases": ["https://x.invalid/v1"], "brotli": false});
        assert_eq!(Preset::from_value("t", &off).unwrap().brotli, Some(false));
        let bad = json!({"name": "t", "model": "m", "upstream_bases": ["https://x.invalid/v1"], "brotli": "yes"});
        assert!(Preset::from_value("t", &bad).is_err());
    }

    #[test]
    fn preset_parses_single_model() {
        let v = json!({
            "name": "souffle-test",
            "model": "deepseek-sol",
            "upstream_bases": ["https://api.soufflotheque.internal/v1"]
        });
        let p = Preset::from_value("souffle-test", &v).unwrap();
        assert_eq!(p.models, vec!["deepseek-sol".to_string()]);
    }

    #[test]
    fn preset_parses_model_array() {
        let v = json!({
            "name": "souffle-test",
            "model": ["deepseek-sol", "souffle-pro"],
            "upstream_bases": ["https://api.soufflotheque.internal/v1"]
        });
        let p = Preset::from_value("souffle-test", &v).unwrap();
        assert_eq!(
            p.models,
            vec!["deepseek-sol".to_string(), "souffle-pro".to_string()]
        );
    }

    #[test]
    fn preset_parses_model_with_alias() {
        let v = json!({
            "name": "souffle-test",
            "model": "deepseek-sol",
            "alias": "souffle-pro",
            "upstream_bases": ["https://api.soufflotheque.internal/v1"]
        });
        let p = Preset::from_value("souffle-test", &v).unwrap();
        assert_eq!(
            p.models,
            vec!["deepseek-sol".to_string(), "souffle-pro".to_string()]
        );
    }

    #[test]
    fn preset_extra_headers_schema_is_strict_and_absent_is_empty() {
        let bare = json!({
            "model": "m",
            "upstream_bases": ["https://x.invalid/v1"]
        });
        let parsed = Preset::from_value("bare", &bare).unwrap();
        assert!(parsed.extra_headers.is_empty());

        let valid = json!({
            "model": "m",
            "upstream_bases": ["https://x.invalid/v1"],
            "extra_headers": {
                "User-Agent": "codex_cli_rs/0.87.0",
                "originator": "codex_cli_rs",
                "x-route-hint": "sol"
            }
        });
        let parsed = Preset::from_value("valid", &valid).unwrap();
        assert_eq!(parsed.extra_headers.len(), 3);
        let debug = format!("{parsed:?}");
        assert!(debug.contains("extra_headers"));
        assert!(!debug.contains("codex_cli_rs/0.87.0"));
        assert!(!debug.contains("sol"));

        let invalid = [
            json!(null),
            json!([]),
            json!({"x-route-hint": 7}),
            json!({"x\n-route-hint": "bad-name"}),
            json!({"x-route-hint": "bad\n-value"}),
            json!({"Host": "upstream.example"}),
            json!({"User-Agent": "one", "user-agent": "two"}),
        ];
        for extra_headers in invalid {
            let mut object = bare.clone();
            object["extra_headers"] = extra_headers;
            let error = Preset::from_value("invalid", &object).unwrap_err();
            assert!(error.contains("preset 'invalid'"), "missing preset context: {error}");
            assert!(error.contains("extra_headers"), "missing field context: {error}");
        }
    }

    #[test]
    fn preset_extra_headers_reject_auth_and_framing_fields() {
        for field in [
            "authorization",
            "proxy-authorization",
            "proxy-authenticate",
            "www-authenticate",
            "x-api-key",
            "api-key",
            "cookie",
            "set-cookie",
            "content-length",
            "content-type",
            "content-encoding",
            "accept",
            "accept-encoding",
            "connection",
            "transfer-encoding",
            "keep-alive",
            "te",
            "trailer",
            "upgrade",
            "cache-control",
            "pragma",
            "expires",
            "cdn-cache-control",
            "cloudflare-cdn-cache-control",
            "x-accel-buffering",
        ] {
            let value = json!({
                "model": "m",
                "upstream_bases": ["https://x.invalid/v1"],
                "extra_headers": {field: "must-not-be-configurable"}
            });
            let error = Preset::from_value("protected", &value).unwrap_err();
            assert!(error.contains("extra_headers"), "missing field context: {error}");
            assert!(error.contains(field), "missing protected field context: {error}");
        }
    }

    #[test]
    fn preset_extra_headers_pseudo_headers_are_rejected() {
        let value = json!({
            "model": "m",
            "upstream_bases": ["https://x.invalid/v1"],
            "extra_headers": {":path": "/not-a-header"}
        });
        let error = Preset::from_value("pseudo", &value).unwrap_err();
        assert!(error.contains("preset 'pseudo'"));
        assert!(error.contains("extra_headers"));
        assert!(error.contains(":path"));
    }

    #[test]
    fn extra_headers_late_override_replaces_caller_identity_without_disclosing_values() {
        let mut headers = HeaderMap::new();
        headers.append(header::USER_AGENT, HeaderValue::from_static("python-sdk/2.54.0"));
        headers.append(
            HeaderName::from_static("originator"),
            HeaderValue::from_static("openai-python"),
        );
        headers.insert(
            HeaderName::from_static("x-route-hint"),
            HeaderValue::from_static("caller-route"),
        );
        let overrides = HeaderOverrides::parse(
            "capture",
            &json!({
                "User-Agent": "codex_cli_rs/0.87.0",
                "originator": "codex_cli_rs",
                "x-route-hint": "configured-route"
            }),
        )
        .unwrap();
        overrides.apply(&mut headers);
        assert_eq!(headers.get(header::USER_AGENT).unwrap(), "codex_cli_rs/0.87.0");
        assert_eq!(headers.get("originator").unwrap(), "codex_cli_rs");
        assert_eq!(headers.get("x-route-hint").unwrap(), "configured-route");
        assert_eq!(headers.get_all(header::USER_AGENT).iter().count(), 1);
        assert_eq!(headers.get_all("originator").iter().count(), 1);
    }

    #[tokio::test]
    async fn configured_codex_identity_wins_at_real_outbound_capture() {
        let (addr, captured) = spawn_header_capture_h2_server().await;
        let mut state = make_test_app_state_with_headers(
            &format!("http://{addr}/v1"),
            false,
            1,
            HeaderOverrides::parse(
                "capture",
                &json!({
                    "User-Agent": "codex_cli_rs/0.87.0",
                    "originator": "codex_cli_rs"
                }),
            )
            .unwrap(),
        );
        {
            let state_mut = Arc::get_mut(&mut state).unwrap();
            let slot = Arc::get_mut(&mut state_mut.slots[0]).unwrap();
            Arc::get_mut(&mut slot.config).unwrap().api_mode = responses::ApiMode::Responses;
        }
        let mut request = make_chat_req(false);
        *request.uri_mut() = "/v1/responses".parse().unwrap();
        request.headers_mut().insert(
            header::USER_AGENT,
            HeaderValue::from_static("python-sdk/2.54.0"),
        );
        request.headers_mut().insert(
            HeaderName::from_static("originator"),
            HeaderValue::from_static("openai-python"),
        );
        let response = handle_chat_completions(State(state), request).await;
        assert_eq!(response.status(), StatusCode::OK);
        for _ in 0..50 {
            if !captured.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let headers = captured.lock().unwrap().first().cloned().expect("captured upstream request");
        assert_eq!(headers.get(header::USER_AGENT).unwrap(), "codex_cli_rs/0.87.0");
        assert_eq!(headers.get("originator").unwrap(), "codex_cli_rs");
        assert_eq!(headers.get_all(header::USER_AGENT).iter().count(), 1);
        assert_eq!(headers.get_all("originator").iter().count(), 1);
    }

    #[test]
    fn native_auxiliary_operations_use_the_same_override_metadata() {
        for path in [
            "/v1/responses",
            "/v1/responses/compact",
            "/v1/responses/input_tokens",
        ] {
            let request = Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::USER_AGENT, "python-sdk/2.54.0")
                .header("originator", "openai-python")
                .body(Body::empty())
                .unwrap();
            let options = responses::RequestOptions::capture(&request);
            let mut headers = options.headers;
            HeaderOverrides::parse(
                "native",
                &json!({
                    "User-Agent": "codex_cli_rs/0.87.0",
                    "originator": "codex_cli_rs"
                }),
            )
            .unwrap()
            .apply(&mut headers);
            assert_eq!(headers.get(header::USER_AGENT).unwrap(), "codex_cli_rs/0.87.0");
            assert_eq!(headers.get("originator").unwrap(), "codex_cli_rs");
        }
    }

    #[test]
    fn config_absent_extra_headers_keeps_existing_header_assembly() {
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, HeaderValue::from_static("souffle_proxy"));
        HeaderOverrides::default().apply(&mut headers);
        assert_eq!(headers.get(header::USER_AGENT).unwrap(), "souffle_proxy");
    }

    #[test]
    fn brotli_window_bits_curve() {
        assert_eq!(brotli_window_bits_for(100), 14);
        assert_eq!(brotli_window_bits_for(16 * 1024), 14);
        assert_eq!(brotli_window_bits_for(16 * 1024 + 1), 15);
        assert_eq!(brotli_window_bits_for(32 * 1024), 15);
        assert_eq!(brotli_window_bits_for(32 * 1024 + 1), 16);
        assert_eq!(brotli_window_bits_for(64 * 1024), 16);
        assert_eq!(brotli_window_bits_for(64 * 1024 + 1), 17);
        assert_eq!(brotli_window_bits_for(128 * 1024), 17);
        assert_eq!(brotli_window_bits_for(128 * 1024 + 1), 18);
        assert_eq!(brotli_window_bits_for(256 * 1024), 18);
        assert_eq!(brotli_window_bits_for(256 * 1024 + 1), 19);
        assert_eq!(brotli_window_bits_for(512 * 1024), 19);
        assert_eq!(brotli_window_bits_for(512 * 1024 + 1), 20);
        assert_eq!(brotli_window_bits_for(1024 * 1024), 20);
        assert_eq!(brotli_window_bits_for(1024 * 1024 + 1), 21);
        assert_eq!(brotli_window_bits_for(2 * 1024 * 1024), 21);
        assert_eq!(brotli_window_bits_for(2 * 1024 * 1024 + 1), 22);
        assert_eq!(brotli_window_bits_for(4 * 1024 * 1024), 22);
        assert_eq!(brotli_window_bits_for(8 * 1024 * 1024), 22);
    }

    #[test]
    fn upstream_payload_raw_serialize_and_rewrite() {
        // Out-of-order top-level keys: the Raw path alphabetizes top-level keys on serialize
        let json_body = r#"{"stream":true,"temperature":0.7,"model":"glm-5.3","messages":[{"role":"user","content":"hi"}]}"#;
        let m: BTreeMap<String, Box<RawValue>> = serde_json::from_str(json_body).unwrap();
        let mut p_raw = UpstreamPayload::new(m);

        let mut buf_raw = Vec::new();
        p_raw.serialize_into(&mut buf_raw).unwrap();

        // Semantic JSON round-trip: the serialized payload parses back cleanly
        let val_from_raw: Value = serde_json::from_slice(&buf_raw).unwrap();
        assert_eq!(val_from_raw["model"], "glm-5.3");
        assert_eq!(val_from_raw["stream"], true);

        // Raw path preserves nested keys verbatim (role before content, as sent by client)
        assert!(String::from_utf8(buf_raw)
            .unwrap()
            .contains(r#"{"role":"user","content":"hi"}"#));

        // Test model rewrite
        let new_model_raw =
            RawValue::from_string(serde_json::to_string("z-ai/glm-5.3-alt").unwrap()).unwrap();
        p_raw.rewrite_model(&new_model_raw);

        let mut buf_raw2 = Vec::new();
        p_raw.serialize_into(&mut buf_raw2).unwrap();
        let val2_from_raw: Value = serde_json::from_slice(&buf_raw2).unwrap();
        assert_eq!(val2_from_raw["model"], "z-ai/glm-5.3-alt");
        assert!(String::from_utf8(buf_raw2)
            .unwrap()
            .contains("z-ai/glm-5.3-alt"));

        // Verbatim preservation of client tokens in Raw path:
        // RawValue preserves \u0041 unescaped verbatim to avoid prompt drift
        let raw_body = r#"{"messages":[{"content":"\u0041"}]}"#;
        let m_verbatim: BTreeMap<String, Box<RawValue>> = serde_json::from_str(raw_body).unwrap();
        let p_verbatim = UpstreamPayload::new(m_verbatim);
        let mut buf_verbatim = Vec::new();
        p_verbatim.serialize_into(&mut buf_verbatim).unwrap();
        assert!(String::from_utf8(buf_verbatim)
            .unwrap()
            .contains(r#""\u0041""#));
    }

    #[test]
    fn retry_model_patch_is_byte_identical_to_full_reserialize() {
        // Client body whose messages embed an escaped `"model"` key: the patch
        // scanner must only touch the depth-1 member.
        let body = r#"{"messages":[{"role":"user","content":"{\"model\":\"evil\",\"a\":1}"}],"model":"model-a","stream":true,"temperature":0.7}"#;
        let map: BTreeMap<String, Box<RawValue>> = serde_json::from_str(body).unwrap();

        let mut first_buf = Vec::new();
        serde_json::to_writer(&mut first_buf, &map).unwrap();
        let mut patched = Bytes::from(first_buf);

        // 3 retries with rotation, mixed literal lengths.
        let rotation = [
            "\"z-ai/glm-5.3-alt\"",
            "\"m-b\"",
            "\"model-a-longer-name\"",
        ];
        for literal in rotation {
            // Reference body: what the pre-patch code emitted (map rewrite +
            // full re-serialize).
            let mut reference_map = map.clone();
            reference_map.insert(
                "model".to_string(),
                RawValue::from_string(literal.to_string()).unwrap(),
            );
            let mut ref_buf = Vec::new();
            serde_json::to_writer(&mut ref_buf, &reference_map).unwrap();

            match patch_serialized_model(&patched, literal) {
                ModelPatch::Replaced(next) => patched = next,
                _ => panic!("expected a model span patch for {literal}"),
            }
            assert_eq!(
                patched.as_ref(),
                ref_buf.as_slice(),
                "patched body diverged from full re-serialize for {literal}"
            );
        }

        let parsed: Value = serde_json::from_slice(&patched).unwrap();
        assert_eq!(parsed["model"], "model-a-longer-name");
        assert_eq!(parsed["messages"][0]["content"], r#"{"model":"evil","a":1}"#);
    }

    #[test]
    fn model_patch_reports_unchanged_and_not_found() {
        let body = r#"{"model":"m-a","stream":true}"#;
        let bytes = Bytes::from_static(body.as_bytes());
        assert!(matches!(
            patch_serialized_model(&bytes, "\"m-a\""),
            ModelPatch::Unchanged
        ));
        assert!(matches!(
            patch_serialized_model(&bytes, "\"m-b\""),
            ModelPatch::Replaced(_)
        ));

        // No top-level model (only a nested one): caller must re-serialize.
        let nested = Bytes::from_static(br#"{"messages":[{"model":"x"}]}"#);
        assert!(matches!(
            patch_serialized_model(&nested, "\"m-b\""),
            ModelPatch::NotFound
        ));
        // Malformed body: no panic, just NotFound.
        let junk = Bytes::from_static(br#"{"model":"#);
        assert!(matches!(
            patch_serialized_model(&junk, "\"m-b\""),
            ModelPatch::NotFound
        ));
    }

    #[test]
    fn spliced_messages_estimated_len_covers_emitted_bytes() {
        // 100 KB client array + prefix + suffix: the estimate must not collapse to
        // the ~4 bytes of the old `2 + body - inner` arithmetic, or `with_capacity`
        // under-allocates and the outbound Vec doubles once per request.
        let big = "x".repeat(100_000);
        let body = format!(
            r#"{{"messages":[{{"role":"user","content":"{big}"}},{{"role":"assistant","content":"ok"}}]}}"#
        );
        let prep = r#"{"role":"system","content":"sys"}"#;
        let app = r#"{"role":"assistant","content":"prefill"}"#;
        let mut map: BTreeMap<String, Box<RawValue>> = serde_json::from_str(&body).unwrap();
        let msgs = map.remove("messages").unwrap();
        let (splice, _, _, _) = plan_messages_splice(msgs, Some(prep), 1, Some(app), 1);
        let spliced = match splice {
            MsgsSplice::Spliced(s) => s,
            MsgsSplice::Verbatim(_) => panic!("expected a splice"),
        };

        let mut emitted = Vec::new();
        spliced.emit_into(&mut emitted);
        assert!(
            spliced.estimated_len() >= emitted.len(),
            "estimate {} must cover the {} emitted bytes",
            spliced.estimated_len(),
            emitted.len()
        );
        // ...and it must not be wildly oversized either (one allocation, no doubling).
        assert!(spliced.estimated_len() <= emitted.len() + 8);
    }

    #[test]
    fn spliced_payload_serializes_byte_identically_to_materialized_array() {
        let prep = r#"{"role":"system","content":"sys"}"#;
        let app = r#"{"role":"assistant","content":"prefill"}"#;
        let body = r#"{"stream":true,"temperature":0.7,"messages":[ {"role":"user","content":"hi"} ],"model":"m-a","max_tokens":32}"#;

        let mut map: BTreeMap<String, Box<RawValue>> = serde_json::from_str(body).unwrap();
        let msgs = map.remove("messages").unwrap();
        let (splice, count, p_add, a_add) =
            plan_messages_splice(msgs, Some(prep), 1, Some(app), 1);
        assert_eq!((count, p_add, a_add), (3, 1, 1));
        let payload = UpstreamPayload {
            map,
            spliced_messages: match splice {
                MsgsSplice::Spliced(s) => Some(s),
                MsgsSplice::Verbatim(_) => panic!("expected a splice"),
            },
        };
        let mut buf = Vec::new();
        payload.serialize_into(&mut buf).unwrap();
        // Byte-for-byte what the old copy-the-array implementation emitted:
        // top-level keys sorted, client whitespace inside the array preserved.
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            concat!(
                r#"{"max_tokens":32,"messages":[{"role":"system","content":"sys"},"#,
                r#" {"role":"user","content":"hi"} ,"#,
                r#"{"role":"assistant","content":"prefill"}],"#,
                r#""model":"m-a","stream":true,"temperature":0.7}"#
            )
        );

        // `messages` sorting last must still emit (tail branch), and the array
        // must stay parseable.
        let tail_body = r#"{"max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#;
        let mut tail_map: BTreeMap<String, Box<RawValue>> =
            serde_json::from_str(tail_body).unwrap();
        let tail_msgs = tail_map.remove("messages").unwrap();
        let (tail_splice, _, _, _) = plan_messages_splice(tail_msgs, Some(prep), 1, None, 0);
        let tail_payload = UpstreamPayload {
            map: tail_map,
            spliced_messages: match tail_splice {
                MsgsSplice::Spliced(s) => Some(s),
                MsgsSplice::Verbatim(_) => panic!("expected a splice"),
            },
        };
        let mut tail_buf = Vec::new();
        tail_payload.serialize_into(&mut tail_buf).unwrap();
        let tail_str = String::from_utf8(tail_buf).unwrap();
        assert_eq!(
            tail_str,
            concat!(
                r#"{"max_tokens":1,"messages":[{"role":"system","content":"sys"},"#,
                r#"{"role":"user","content":"hi"}]}"#
            )
        );
        let parsed: Value = serde_json::from_str(&tail_str).unwrap();
        assert_eq!(parsed["messages"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn log_timestamp_formatting_is_canonical() {
        let tz = SYSTEM_TZ.get_or_init(jiff::tz::TimeZone::system);
        let dt = jiff::Timestamp::now().to_zoned(tz.clone()).datetime();
        let formatted = format!(
            "[{:04}-{:02}-{:02} {:02}:{:02}:{:02}]",
            dt.year(),
            dt.month(),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        );
        assert_eq!(formatted.len(), 21); // "[YYYY-MM-DD HH:MM:SS]" is 21 bytes
        assert!(formatted.starts_with('['));
        assert!(formatted.ends_with(']'));
        assert_eq!(&formatted[11..12], " ");
    }

    #[test]
    fn preset_preserializes_raw_fields() {
        let v = json!({
            "name": "raw-test",
            "models": ["model-a", "model-b"],
            "upstream_bases": ["https://api.internal/v1"],
            "inject": {
                "thinking": { "type": "enabled" },
                "temperature": 0.7
            },
            "prepend_messages": [
                { "role": "system", "content": "system prompt" }
            ],
            "append_messages": [
                { "role": "assistant", "content": "prefill" }
            ]
        });
        let p = Preset::from_value("raw-test", &v).unwrap();
        assert_eq!(p.models_raw.len(), 2);
        assert_eq!(p.models_raw[0].get(), "\"model-a\"");
        assert_eq!(p.models_raw[1].get(), "\"model-b\"");

        assert!(p.inject_raw.contains_key("thinking"));
        assert!(p.inject_raw.contains_key("temperature"));
        assert_eq!(p.inject_raw.get("temperature").unwrap().get(), "0.7");

        assert_eq!(
            p.prepend_raw.as_deref(),
            Some(r#"{"content":"system prompt","role":"system"}"#)
        );
        assert_eq!(
            p.append_raw.as_deref(),
            Some(r#"{"content":"prefill","role":"assistant"}"#)
        );
    }

    /// Test-only view of the lazy splice: materialize what the serializer emits.
    fn splice_to_string(
        body: &str,
        prepend: Option<&str>,
        prepend_count: usize,
        append: Option<&str>,
        append_count: usize,
    ) -> (Option<String>, usize, usize, usize) {
        let boxed = RawValue::from_string(body.to_string()).unwrap();
        let (splice, count, p_add, a_add) =
            plan_messages_splice(boxed, prepend, prepend_count, append, append_count);
        let out = match splice {
            MsgsSplice::Verbatim(_) => None,
            MsgsSplice::Spliced(s) => {
                let mut buf = Vec::new();
                s.emit_into(&mut buf);
                Some(String::from_utf8(buf).unwrap())
            }
        };
        (out, count, p_add, a_add)
    }

    #[test]
    fn splice_messages_handles_empty_and_whitespace() {
        let prep = r#"{"role":"system","content":"sys"}"#;
        let app = r#"{"role":"assistant","content":"prefill"}"#;

        // Empty array with prepend
        let (res, count, p_add, a_add) = splice_to_string("[]", Some(prep), 1, None, 0);
        assert_eq!(count, 1);
        assert_eq!(p_add, 1);
        assert_eq!(a_add, 0);
        assert_eq!(res.unwrap(), r#"[{"role":"system","content":"sys"}]"#);

        // Empty array with whitespace and prepend
        let (res, count, p_add, a_add) = splice_to_string("  [  \n  ]  ", Some(prep), 1, None, 0);
        assert_eq!(count, 1);
        assert_eq!(p_add, 1);
        assert_eq!(a_add, 0);
        assert_eq!(res.unwrap(), r#"[{"role":"system","content":"sys"}]"#);

        // Empty array with append only: should NOT append because last role is not user
        let (res, count, p_add, a_add) = splice_to_string("[]", None, 0, Some(app), 1);
        assert_eq!(count, 0);
        assert_eq!(p_add, 0);
        assert_eq!(a_add, 0);
        assert!(res.is_none());
    }

    #[test]
    fn splice_messages_preserves_client_byte_verbatim() {
        let prep = r#"{"role":"system","content":"sys"}"#;
        let app = r#"{"role":"assistant","content":"prefill"}"#;

        // Client payload with unique whitespace, unicode escapes, and custom key ordering
        let client_msgs = r#"[  {"content": "Hello \u0041!", "role": "user", "custom": true}  ]"#;

        // Prepend and append together
        let (res, count, p_add, a_add) =
            splice_to_string(client_msgs, Some(prep), 1, Some(app), 1);
        assert_eq!(count, 3);
        assert_eq!(p_add, 1);
        assert_eq!(a_add, 1);

        let spliced_str = res.unwrap();

        // Exact verbatim client preservation: \u0041 unmutated, custom key order preserved
        assert!(
            spliced_str.contains(r#"{"content": "Hello \u0041!", "role": "user", "custom": true}"#)
        );
        assert!(spliced_str.starts_with(r#"["#));
        assert!(spliced_str.ends_with(r#"{"role":"assistant","content":"prefill"}]"#));

        // Semantic JSON parse verification
        let parsed: Value = serde_json::from_str(&spliced_str).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0]["role"], "system");
        assert_eq!(arr[1]["role"], "user");
        assert_eq!(arr[1]["content"], "Hello A!");
        assert_eq!(arr[2]["role"], "assistant");
    }

    #[test]
    fn splice_messages_respects_last_role_condition() {
        let app = r#"{"role":"assistant","content":"prefill"}"#;

        // Last message is assistant -> do NOT append
        let msgs_assistant =
            r#"[{"role":"user","content":"hi"},{"role":"assistant","content":"bye"}]"#;
        let (res, count, p_add, a_add) = splice_to_string(msgs_assistant, None, 0, Some(app), 1);
        assert_eq!(count, 2);
        assert_eq!(p_add, 0);
        assert_eq!(a_add, 0);
        assert!(res.is_none());

        // Last message is user -> append
        let msgs_user = r#"[{"role":"assistant","content":"bye"},{"role":"user","content":"hi"}]"#;
        let (res, count, p_add, a_add) = splice_to_string(msgs_user, None, 0, Some(app), 1);
        assert_eq!(count, 3);
        assert_eq!(p_add, 0);
        assert_eq!(a_add, 1);
        let spliced = res.unwrap();
        assert!(spliced.ends_with(r#"{"role":"assistant","content":"prefill"}]"#));

        // Malformed / non-array messages -> untouched
        let (res_none, count_none, _, _) = splice_to_string(
            r#""not an array""#,
            Some(r#"{"role":"system"}"#),
            1,
            Some(app),
            1,
        );
        assert_eq!(count_none, 0);
        assert!(res_none.is_none());
    }

    #[test]
    fn parse_args_collects_two_presets() {
        let args = parse_args_from(
            vec![
                "--preset".to_string(),
                "A".to_string(),
                "--preset".to_string(),
                "B".to_string(),
            ]
            .into_iter(),
        );
        assert_eq!(args.presets, vec!["A".to_string(), "B".to_string()]);
    }

    #[test]
    fn parse_args_collects_one_preset() {
        let args = parse_args_from(vec!["--preset".to_string(), "A".to_string()].into_iter());
        assert_eq!(args.presets, vec!["A".to_string()]);
    }

    #[test]
    fn parse_args_collects_inline_preset_form() {
        let args =
            parse_args_from(vec!["--preset=A".to_string(), "--preset=B".to_string()].into_iter());
        assert_eq!(args.presets, vec!["A".to_string(), "B".to_string()]);
    }

    #[test]
    fn slot_selection_routes_deepseek_sol_to_slot_2() {
        assert_eq!(select_slot_index("deepseek-sol", 2), 1);
    }

    #[test]
    fn slot_selection_falls_back_on_unknown() {
        // Unknown id: slot 1 (index 0), even in dual mode.
        assert_eq!(select_slot_index("gpt-4o", 2), 0);
    }

    #[test]
    fn slot_selection_single_mode() {
        // Any model (including deepseek-sol and unknown ids) routes to index 0
        // when only one slot exists.
        assert_eq!(select_slot_index("deepseek-sol", 1), 0);
        assert_eq!(select_slot_index("deepseek-souffle", 1), 0);
        assert_eq!(select_slot_index("gpt-4o", 1), 0);
        assert_eq!(select_slot_index("", 1), 0);
    }

    #[test]
    fn test_souffle_pout_basic_folding() {
        let raw = json!([
            {
                "role": "user",
                "content": "Why is the sky blue?"
            },
            {
                "role": "assistant",
                "content": "Rayleigh scattering causes the blue color.",
                "reasoning_content": "The user is asking about physics of light scattering."
            }
        ])
        .to_string();

        let folded = fold_in_content_cot(&raw).expect("should fold CoT");
        let parsed: Vec<Value> = serde_json::from_str(folded.get()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0]["role"], "user");
        assert_eq!(parsed[0]["content"], "Why is the sky blue?");
        assert_eq!(parsed[1]["role"], "assistant");
        assert_eq!(
            parsed[1]["content"],
            "<think>\nThe user is asking about physics of light scattering.\n</think>\n\nRayleigh scattering causes the blue color."
        );
        assert_eq!(parsed[1]["reasoning_content"], "");
    }

    #[test]
    fn test_souffle_pout_reasoning_fallback() {
        let raw = json!([
            {
                "role": "assistant",
                "content": "42 is the answer.",
                "reasoning": "Calculating deep thought..."
            }
        ])
        .to_string();

        let folded = fold_in_content_cot(&raw).expect("should fold with reasoning key fallback");
        let parsed: Vec<Value> = serde_json::from_str(folded.get()).unwrap();
        assert_eq!(
            parsed[0]["content"],
            "<think>\nCalculating deep thought...\n</think>\n\n42 is the answer."
        );
        assert_eq!(parsed[0]["reasoning"], "");
        assert!(
            parsed[0].get("reasoning_content").is_none(),
            "folding must not inject reasoning_content into a message that never carried it"
        );
    }

    #[test]
    fn test_souffle_pout_inner_tag_strip_guard() {
        let raw1 = json!([
            {
                "role": "assistant",
                "content": "Hello",
                "reasoning_content": "<think>\nInner reasoning\n</think>"
            }
        ])
        .to_string();

        let folded1 = fold_in_content_cot(&raw1).expect("should fold and strip inner tags");
        let parsed1: Vec<Value> = serde_json::from_str(folded1.get()).unwrap();
        assert_eq!(
            parsed1[0]["content"],
            "<think>\nInner reasoning\n</think>\n\nHello"
        );

        let raw2 = json!([
            {
                "role": "assistant",
                "content": "World",
                "reasoning_content": "<think>Prefix only"
            }
        ])
        .to_string();
        let folded2 = fold_in_content_cot(&raw2).expect("should fold and strip prefix <think>");
        let parsed2: Vec<Value> = serde_json::from_str(folded2.get()).unwrap();
        assert_eq!(
            parsed2[0]["content"],
            "<think>\nPrefix only\n</think>\n\nWorld"
        );
    }

    #[test]
    fn test_souffle_pout_escaped_think_tags_are_recognised() {
        // Differential repro: the model spells its tags as \u003c escapes, so the
        // byte compare against "<​think>" never matched. The whole tag block ended
        // up nested inside the freshly emitted one.
        let msgs = concat!(
            r#"[{"role":"assistant","reasoning_content":"\u003cthink\u003erc\u003c/think\u003e","#,
            r#""content":"Answer"}]"#
        );
        let folded = fold_in_content_cot(msgs).expect("escaped tags must still fold");
        let parsed: Vec<Value> = serde_json::from_str(folded.get()).unwrap();
        assert_eq!(
            parsed[0]["content"],
            format!("{FOLD_THINK_OPEN}\nrc\n{FOLD_THINK_CLOSE}\n\nAnswer"),
            "escaped tags in reasoning_content must be stripped, not nested"
        );
        assert_eq!(parsed[0]["reasoning_content"], "");

        // Uppercase hex spellings must be recognised too.
        let upper = concat!(
            r#"[{"role":"assistant","reasoning_content":"\u003Cthink\u003Edeep\u003C/think\u003E","#,
            r#""content":"ok"}]"#
        );
        let folded_upper = fold_in_content_cot(upper).expect("uppercase escapes must fold");
        let parsed_upper: Vec<Value> = serde_json::from_str(folded_upper.get()).unwrap();
        assert_eq!(
            parsed_upper[0]["content"],
            format!("{FOLD_THINK_OPEN}\ndeep\n{FOLD_THINK_CLOSE}\n\nok")
        );

        // Content that already starts with an escaped think block must not be
        // folded again: that is the double-wrap the harness caught.
        let already = concat!(
            r#"[{"role":"assistant","content":"\u003cthink\u003ealready folded\u003c/think\u003e\n\nAnswer","#,
            r#""reasoning_content":"duplicate reasoning"}]"#
        );
        assert!(
            fold_in_content_cot(already).is_none(),
            "an escaped think block already in content must trip the idempotency guard"
        );
    }

    #[test]
    fn test_souffle_pout_idempotency_guard() {
        let raw = json!([
            {
                "role": "assistant",
                "content": "<think>\nAlready wrapped reasoning\n</think>\n\nFinal answer",
                "reasoning_content": "Duplicate reasoning"
            }
        ])
        .to_string();

        let folded = fold_in_content_cot(&raw);
        assert!(folded.is_none(), "idempotency guard should skip folding and return None");
    }

    #[test]
    fn test_souffle_pout_noop_already_normalized() {
        let raw = json!([
            {
                "role": "assistant",
                "content": "Normal content",
                "reasoning_content": ""
            }
        ])
        .to_string();

        let folded = fold_in_content_cot(&raw);
        assert!(folded.is_none(), "already normalized payload should return None");
    }

    #[test]
    fn test_souffle_pout_tool_call_turn_null_content() {
        let raw = json!([
            {
                "role": "assistant",
                "content": null,
                "reasoning_content": "I should call get_weather",
                "tool_calls": [
                    {
                        "id": "call_123",
                        "type": "function",
                        "function": {"name": "get_weather", "arguments": "{\"city\":\"Hanoi\"}"}
                    }
                ]
            }
        ])
        .to_string();

        let folded = fold_in_content_cot(&raw).expect("should fold null content turn");
        let parsed: Vec<Value> = serde_json::from_str(folded.get()).unwrap();
        assert_eq!(
            parsed[0]["content"],
            "<think>\nI should call get_weather\n</think>"
        );
        assert_eq!(parsed[0]["reasoning_content"], "");
        assert!(parsed[0].get("tool_calls").is_some());
        assert_eq!(parsed[0]["tool_calls"][0]["id"], "call_123");
    }

    #[test]
    fn test_souffle_pout_array_multimodal_content() {
        let raw = json!([
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "Part 1 of message. "},
                    {"type": "image_url", "image_url": {"url": "https://example.test/cat.png"}},
                    {"type": "text", "text": "Part 2 of message."}
                ],
                "reasoning_content": "Multi-modal analysis"
            }
        ])
        .to_string();

        let folded = fold_in_content_cot(&raw).expect("should fold array content");
        let parsed: Vec<Value> = serde_json::from_str(folded.get()).unwrap();
        let parts = parsed[0]["content"]
            .as_array()
            .expect("array content must stay structured after folding");
        assert_eq!(parts[0]["type"], "text");
        let text = parts[0]["text"].as_str().unwrap();
        assert!(text.contains("Multi-modal analysis"));
        assert!(text.ends_with("Part 1 of message. Part 2 of message."));
        // Regression: non-text parts must survive folding verbatim.
        let media = parts
            .iter()
            .find(|p| p["type"] == "image_url")
            .expect("image part must not be dropped");
        assert_eq!(media["image_url"]["url"], "https://example.test/cat.png");
        assert_eq!(parsed[0]["reasoning_content"], "");
    }

    #[test]
    fn test_souffle_pout_lone_surrogate_is_not_folded() {
        // Unpaired surrogate: the element is already invalid JSON. Folding must not
        // claim it and must not re-emit it as a (still invalid) folded body.
        let raw = r#"[{"role":"assistant","content":"\ud800","reasoning_content":"thinking"}]"#;
        assert!(fold_in_content_cot(raw).is_none());
    }

    #[test]
    fn test_souffle_pout_non_string_content_is_normalized() {
        // Matches the pre-splice semantics: decode the value, then embed its text,
        // so 1e2 reaches the model as 100.0 rather than the client's literal.
        let raw = r#"[{"role":"assistant","content":1e2,"reasoning_content":"r"}]"#;
        let folded = fold_in_content_cot(raw).expect("numeric content should fold");
        let parsed: Vec<Value> = serde_json::from_str(folded.get()).unwrap();
        let text = parsed[0]["content"].as_str().expect("content is a string");
        assert!(text.ends_with("100.0"), "unexpected text: {text}");
    }

    #[test]
    fn test_souffle_pout_escaped_member_keys_are_recognized() {
        // "\u0063ontent" / "\u0072ole" are the same members as content/role. Missing
        // them used to append a second content member and drop the client's text.
        let raw = r#"[{"\u0072ole":"assistant","\u0063ontent":"hello","reasoning_content":"r"}]"#;
        let folded = fold_in_content_cot(raw).expect("escaped keys must still fold");
        let parsed: Vec<Value> = serde_json::from_str(folded.get()).unwrap();
        let text = parsed[0]["content"].as_str().expect("folded content is a string");
        assert!(text.contains("hello"), "client text lost: {text}");
        assert_eq!(parsed[0]["reasoning_content"], "");
        // Exactly one content member: the scanner rejects any element with a repeated
        // key, so a Some() here proves no duplicate was appended.
        let folded_arr = folded.get();
        let elem = &folded_arr[1..folded_arr.len() - 1];
        let spans = scan_message_spans(elem).expect("folded element must not contain duplicate keys");
        assert!(spans.content.is_some(), "content span missing after fold");
    }

    #[test]
    fn test_retryable_status_set_respects_the_feature() {
        assert!(is_retryable_upstream_status(429));
        assert!(is_retryable_upstream_status(500));
        assert!(is_retryable_upstream_status(504));
        assert!(is_retryable_upstream_status(522));
        assert!(is_retryable_upstream_status(529));
        assert!(!is_retryable_upstream_status(401));
        assert!(!is_retryable_upstream_status(404));
        // 400 is final unless the retry-400 feature is compiled in.
        assert_eq!(
            is_retryable_upstream_status(400),
            cfg!(feature = "retry-400"),
            "400 must be retryable only in the retry-400 build"
        );
    }

    #[test]
    fn test_souffle_pout_duplicate_keys_leave_element_untouched() {
        let raw = r#"[{"role":"assistant","content":"a","content":"b","reasoning_content":"r"}]"#;
        assert!(
            fold_in_content_cot(raw).is_none(),
            "a repeated member key must skip folding instead of leaving a duplicate"
        );
    }

    #[test]
    fn test_souffle_pout_unicode_whitespace_is_trimmed() {
        // Parity with the pre-splice code: content is start-trimmed with str::trim_start
        // (Unicode-aware), so leading NBSP disappears while trailing bytes are kept.
        let raw = "[{\"role\":\"assistant\",\"content\":\"\\u00a0padded\\u00a0\",\"reasoning_content\":\"r\"}]";
        let folded = fold_in_content_cot(raw).expect("should fold");
        let parsed: Vec<Value> = serde_json::from_str(folded.get()).unwrap();
        let text = parsed[0]["content"].as_str().unwrap();
        assert!(
            !text.trim_start_matches('\u{a0}').starts_with('\u{a0}'),
            "leading NBSP must be trimmed like str::trim_start: {text:?}"
        );
        assert!(text.contains("padded"), "unexpected text: {text:?}");
    }

    #[test]
    fn test_souffle_pout_non_string_content_is_escaped() {
        // Non-string content still folds into a *string*: the JSON text has to be
        // escaped when embedded, otherwise the spliced element is invalid JSON.
        let raw = r#"[{"role":"assistant","content":{"a":1},"reasoning_content":"why"}]"#;
        let folded = fold_in_content_cot(raw).expect("should fold object content");
        let parsed: Vec<Value> = serde_json::from_str(folded.get()).unwrap();
        assert_eq!(
            parsed[0]["content"],
            format!("{FOLD_THINK_OPEN}\nwhy\n{FOLD_THINK_CLOSE}\n\n{{\"a\":1}}")
        );
        assert_eq!(parsed[0]["reasoning_content"], "");
    }

    #[test]
    fn test_souffle_pout_reasoning_only_turn_gets_content_key() {
        // Assistant turn with no `content` member at all: the splice must append one.
        let raw = r#"[{"role":"assistant","reasoning_content":"pondering"}]"#;
        let folded = fold_in_content_cot(raw).expect("should fold content-less turn");
        let parsed: Vec<Value> = serde_json::from_str(folded.get()).unwrap();
        assert_eq!(
            parsed[0]["content"],
            format!("{FOLD_THINK_OPEN}\npondering\n{FOLD_THINK_CLOSE}")
        );
        assert_eq!(parsed[0]["reasoning_content"], "");
        assert_eq!(parsed[0]["role"], "assistant");

        // Empty reasoning_content falls back to `reasoning`; both end up blanked.
        let raw =
            r#"[{"role":"assistant","content":"ok","reasoning_content":"","reasoning":"deep"}]"#;
        let folded = fold_in_content_cot(raw).expect("should fall back to reasoning");
        let parsed: Vec<Value> = serde_json::from_str(folded.get()).unwrap();
        assert_eq!(
            parsed[0]["content"],
            format!("{FOLD_THINK_OPEN}\ndeep\n{FOLD_THINK_CLOSE}\n\nok")
        );
        assert_eq!(parsed[0]["reasoning"], "");
    }

    #[test]
    fn test_souffle_pout_scanner_ignores_braces_inside_strings() {
        // Tool arguments and reasoning carry braces and escaped quotes inside
        // strings; the span scanner must not mistake them for structure.
        let raw = json!([{
            "role": "assistant",
            "content": "done",
            "reasoning_content": "use {\"a\":1} here",
            "tool_calls": [{
                "id": "c1",
                "type": "function",
                "function": {"name": "f", "arguments": "{\"k\":\"v}\"}"}
            }]
        }])
        .to_string();
        let folded = fold_in_content_cot(&raw).expect("should fold");
        let parsed: Vec<Value> = serde_json::from_str(folded.get()).unwrap();
        assert_eq!(
            parsed[0]["content"],
            format!("{FOLD_THINK_OPEN}\nuse {{\"a\":1}} here\n{FOLD_THINK_CLOSE}\n\ndone")
        );
        assert_eq!(parsed[0]["reasoning_content"], "");
        assert_eq!(
            parsed[0]["tool_calls"][0]["function"]["arguments"],
            r#"{"k":"v}"}"#
        );
    }

    #[test]
    fn test_souffle_pout_fold_preserves_raw_escapes_byte_identically() {
        // Content body mixes an escaped quote, escaped newline, an escaped solidus
        // and raw multi-byte UTF-8. A body carrying escapes is decoded once (the
        // tag guards and str::trim need real text, FIX 7/9) and re-escaped on
        // output, which is what the pre-merge implementation emitted. Plain-ASCII
        // bodies never take that path and stay byte-identical.
        let body_raw = r#"He said \"hi\"\n\u00e9 中文 🦀 a\/b"#;
        let msgs_raw = format!(
            r#"[{{"role":"assistant","reasoning_content":"think \"x\"\nline 2","content":"{}"}}]"#,
            body_raw
        );

        let folded = fold_in_content_cot(&msgs_raw).expect("should fold escaped content");
        let out = folded.get();

        let parsed: Vec<Value> = serde_json::from_str(out).unwrap();
        let expected = format!(
            "{FOLD_THINK_OPEN}\nthink \"x\"\nline 2\n{FOLD_THINK_CLOSE}\n\nHe said \"hi\"\né 中文 🦀 a/b"
        );
        assert_eq!(parsed[0]["content"], expected);
        assert_eq!(parsed[0]["reasoning_content"], "");

        // The plain-ASCII fast path still splices client bytes verbatim.
        let plain = fold_in_content_cot(
            r#"[{"role":"assistant","reasoning_content":"think","content":"  plain ascii body"}]"#,
        )
        .expect("should fold plain content");
        let expected_plain = format!(
            r#""content":"{FOLD_THINK_OPEN}\nthink\n{FOLD_THINK_CLOSE}\n\nplain ascii body""#
        );
        assert!(
            plain.get().contains(&expected_plain),
            "plain-ASCII content must be spliced byte-for-byte, got: {}",
            plain.get()
        );
    }

    #[test]
    fn test_souffle_pout_multi_turn_folding() {
        let raw = json!([
            {"role": "user", "content": "Question 1"},
            {"role": "assistant", "content": "Answer 1", "reasoning_content": "Reason 1"},
            {"role": "user", "content": "Question 2"},
            {"role": "assistant", "content": "Answer 2", "reasoning_content": "Reason 2"}
        ])
        .to_string();

        let folded = fold_in_content_cot(&raw).expect("should fold multi-turn CoT");
        let parsed: Vec<Value> = serde_json::from_str(folded.get()).unwrap();
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[0]["content"], "Question 1");
        assert_eq!(
            parsed[1]["content"],
            "<think>\nReason 1\n</think>\n\nAnswer 1"
        );
        assert_eq!(parsed[1]["reasoning_content"], "");
        assert_eq!(parsed[2]["content"], "Question 2");
        assert_eq!(
            parsed[3]["content"],
            "<think>\nReason 2\n</think>\n\nAnswer 2"
        );
        assert_eq!(parsed[3]["reasoning_content"], "");
    }

    #[test]
    fn test_souffle_pout_user_message_non_interference() {
        let raw = json!([
            {
                "role": "user",
                "content": "Hello",
                "reasoning_content": "Should not be touched"
            }
        ])
        .to_string();

        let folded = fold_in_content_cot(&raw);
        assert!(folded.is_none(), "user message should not be folded");
    }

    #[test]
    fn test_souffle_pout_prescan_exit_returns_none() {
        let raw = json!([
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there!"}
        ])
        .to_string();

        assert!(!raw.contains("\"reasoning_content\""));
        assert!(!raw.contains("\"reasoning\""));
        let folded = fold_in_content_cot(&raw);
        assert!(folded.is_none(), "pre-scan should immediately return None");
    }

    #[test]
    fn test_preset_souffle_pout_parsing() {
        let v_true = json!({
            "model": "deepseek-sol",
            "key_env": "K",
            "upstream_bases": ["https://example.com"],
            "souffle_pout": true
        });
        let p_true = Preset::from_value("p_true", &v_true).unwrap();
        assert!(p_true.souffle_pout);

        let v_false = json!({
            "model": "deepseek-sol",
            "key_env": "K",
            "upstream_bases": ["https://example.com"],
            "souffle_pout": false
        });
        let p_false = Preset::from_value("p_false", &v_false).unwrap();
        assert!(!p_false.souffle_pout);

        let v_omitted = json!({
            "model": "deepseek-sol",
            "key_env": "K",
            "upstream_bases": ["https://example.com"]
        });
        let p_omitted = Preset::from_value("p_omitted", &v_omitted).unwrap();
        assert!(!p_omitted.souffle_pout);

        let v_invalid = json!({
            "model": "deepseek-sol",
            "key_env": "K",
            "upstream_bases": ["https://example.com"],
            "souffle_pout": "not_a_bool"
        });
        let err = Preset::from_value("p_invalid", &v_invalid).unwrap_err();
        assert!(err.contains("must be a boolean"));
    }

    #[test]
    fn test_config_souffle_pout_env_override() {
        let v = json!({
            "model": "deepseek-sol",
            "key_env": "TEST_KEY_POUT",
            "upstream_bases": ["https://example.com"],
            "souffle_pout": false
        });
        env::set_var("TEST_KEY_POUT", "test_secret");

        let preset_off = Preset::from_value("p_off", &v).unwrap();

        // 1. Unset: inherits preset (false)
        env::remove_var("SOUFFLE_POUT");
        let cfg = Config::from_preset(&preset_off);
        assert!(!cfg.souffle_pout);

        // 2. SOUFFLE_POUT=1 -> overrides to true
        env::set_var("SOUFFLE_POUT", "1");
        let cfg = Config::from_preset(&preset_off);
        assert!(cfg.souffle_pout);

        // 3. SOUFFLE_POUT=true -> overrides to true
        env::set_var("SOUFFLE_POUT", "true");
        let cfg = Config::from_preset(&preset_off);
        assert!(cfg.souffle_pout);

        let v_on = json!({
            "model": "deepseek-sol",
            "key_env": "TEST_KEY_POUT",
            "upstream_bases": ["https://example.com"],
            "souffle_pout": true
        });
        let preset_on = Preset::from_value("p_on", &v_on).unwrap();

        // 4. SOUFFLE_POUT=0 -> overrides to false
        env::set_var("SOUFFLE_POUT", "0");
        let cfg = Config::from_preset(&preset_on);
        assert!(!cfg.souffle_pout);

        // 5. SOUFFLE_POUT=false -> overrides to false
        env::set_var("SOUFFLE_POUT", "false");
        let cfg = Config::from_preset(&preset_on);
        assert!(!cfg.souffle_pout);

        env::remove_var("SOUFFLE_POUT");
        env::remove_var("TEST_KEY_POUT");
    }

    #[test]
    fn test_estimate_payload_capacity_cot_inactive() {
        let mut map = BTreeMap::new();
        let val1 = RawValue::from_string("\"gpt-4o\"".to_string()).unwrap();
        let val2 = RawValue::from_string("[{\"role\":\"user\",\"content\":\"hi\"}]".to_string()).unwrap();
        map.insert("model".to_string(), val1);
        map.insert("messages".to_string(), val2);

        let cap = estimate_payload_capacity(&map, false);
        let serialized = serde_json::to_string(&map).unwrap();

        let expected_base: usize = 2
            + ("model".len() + "\"gpt-4o\"".len() + 4)
            + ("messages".len() + "[{\"role\":\"user\",\"content\":\"hi\"}]".len() + 4)
            + 32;
        assert_eq!(cap, expected_base + 1024);
        assert!(cap >= serialized.len(), "Capacity {} must exceed serialized len {}", cap, serialized.len());
    }

    #[test]
    fn test_estimate_payload_capacity_cot_active() {
        let mut map = BTreeMap::new();
        let val = RawValue::from_string("\"test\"".to_string()).unwrap();
        map.insert("k".to_string(), val);

        let cap_inactive = estimate_payload_capacity(&map, false);
        let cap_active = estimate_payload_capacity(&map, true);

        assert_eq!(cap_active - cap_inactive, 16384 - 1024);
    }

    #[test]
    fn test_upstream_payload_helpers() {
        let mut map = BTreeMap::new();
        let val = RawValue::from_string("\"v\"".to_string()).unwrap();
        map.insert("k".to_string(), val);

        let payload = UpstreamPayload::new(map);
        let expected_base = 2 + ("k".len() + "\"v\"".len() + 4);
        assert_eq!(payload.estimated_len(), expected_base);
        assert_eq!(payload.estimated_capacity(false), expected_base + 32 + 1024);
        assert_eq!(payload.estimated_capacity(true), expected_base + 32 + 16384);
    }

    #[test]
    fn test_preset_http3_parsing() {
        let v_true = json!({
            "model": "deepseek-sol",
            "key_env": "K",
            "upstream_bases": ["https://example.com"],
            "http3": true
        });
        let p_true = Preset::from_value("p_true", &v_true).unwrap();
        assert_eq!(p_true.http3, Some(true));

        let v_false = json!({
            "model": "deepseek-sol",
            "key_env": "K",
            "upstream_bases": ["https://example.com"],
            "http3": false
        });
        let p_false = Preset::from_value("p_false", &v_false).unwrap();
        assert_eq!(p_false.http3, Some(false));

        let v_omitted = json!({
            "model": "deepseek-sol",
            "key_env": "K",
            "upstream_bases": ["https://example.com"]
        });
        let p_omitted = Preset::from_value("p_omitted", &v_omitted).unwrap();
        assert_eq!(p_omitted.http3, None);

        let v_invalid = json!({
            "model": "deepseek-sol",
            "key_env": "K",
            "upstream_bases": ["https://example.com"],
            "http3": "not_a_bool"
        });
        let err = Preset::from_value("p_invalid", &v_invalid).unwrap_err();
        assert!(err.contains("field 'http3' must be a boolean"));
    }

    #[test]
    fn test_config_http3_env_override() {
        let _guard = ADVERSARIAL_ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap();

        let v = json!({
            "model": "deepseek-sol",
            "key_env": "TEST_KEY_HTTP3",
            "upstream_bases": ["https://example.com"],
            "http3": false
        });
        env::set_var("TEST_KEY_HTTP3", "test_secret");

        let preset_off = Preset::from_value("p_off", &v).unwrap();

        // 1. Unset: inherits preset (false)
        env::remove_var("SOUFFLE_HTTP3");
        let cfg = Config::from_preset(&preset_off);
        assert!(!cfg.http3_enabled);

        // 2. SOUFFLE_HTTP3=1 -> overrides to true
        env::set_var("SOUFFLE_HTTP3", "1");
        let cfg = Config::from_preset(&preset_off);
        assert!(cfg.http3_enabled);

        // 3. SOUFFLE_HTTP3=true -> overrides to true
        env::set_var("SOUFFLE_HTTP3", "true");
        let cfg = Config::from_preset(&preset_off);
        assert!(cfg.http3_enabled);

        let v_on = json!({
            "model": "deepseek-sol",
            "key_env": "TEST_KEY_HTTP3",
            "upstream_bases": ["https://example.com"],
            "http3": true
        });
        let preset_on = Preset::from_value("p_on", &v_on).unwrap();

        // 4. SOUFFLE_HTTP3=0 -> overrides to false
        env::set_var("SOUFFLE_HTTP3", "0");
        let cfg = Config::from_preset(&preset_on);
        assert!(!cfg.http3_enabled);

        // 5. SOUFFLE_HTTP3=false -> overrides to false
        env::set_var("SOUFFLE_HTTP3", "false");
        let cfg = Config::from_preset(&preset_on);
        assert!(!cfg.http3_enabled);

        // 6. Unset on preset with true -> inherits true
        env::remove_var("SOUFFLE_HTTP3");
        let cfg = Config::from_preset(&preset_on);
        assert!(cfg.http3_enabled);

        env::remove_var("TEST_KEY_HTTP3");
    }

    #[tokio::test]
    async fn test_upstream_client_dispatch_prewarm() {
        let h2_client = H2Client::new(
            "https://127.0.0.1:65530",
            Duration::from_millis(50),
            Duration::from_secs(60),
            true,
        )
        .unwrap();
        let client_h2 = UpstreamClient::H2(h2_client);
        assert!(!client_h2.is_h3());
        assert_eq!(client_h2.transport_name(), "HTTP/2");
        assert_eq!(client_h2.current_target().base_url, "https://127.0.0.1:65530");
        assert!(client_h2.prewarm().await.is_err());

        let h3_client = H3Client::new(
            "https://127.0.0.1:65530",
            Duration::from_millis(50),
            true,
        )
        .unwrap();
        let client_h3 = UpstreamClient::H3(h3_client);
        assert!(client_h3.is_h3());
        assert_eq!(client_h3.transport_name(), "HTTP/3");
        assert_eq!(client_h3.current_target().base_url, "https://127.0.0.1:65530");
        assert!(client_h3.prewarm().await.is_err());
    }

    // -----------------------------------------------------------------------
    // Adversarial Challenges — Challenger 1 (Milestone 2)
    // -----------------------------------------------------------------------

    static ADVERSARIAL_ENV_LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();

    #[test]
    fn test_adversarial_preset_http3_all_permutations() {
        let _guard = ADVERSARIAL_ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap();

        let v_true = json!({
            "model": "deepseek-sol",
            "key_env": "ADV_TEST_KEY",
            "upstream_bases": ["https://example.com"],
            "http3": true
        });
        let v_false = json!({
            "model": "deepseek-sol",
            "key_env": "ADV_TEST_KEY",
            "upstream_bases": ["https://example.com"],
            "http3": false
        });
        let v_none = json!({
            "model": "deepseek-sol",
            "key_env": "ADV_TEST_KEY",
            "upstream_bases": ["https://example.com"]
        });

        env::set_var("ADV_TEST_KEY", "adv_secret");

        let p_true = Preset::from_value("p_true", &v_true).unwrap();
        let p_false = Preset::from_value("p_false", &v_false).unwrap();
        let p_none = Preset::from_value("p_none", &v_none).unwrap();

        // Matrix of test cases: (env_val_opt, expected_true_preset, expected_false_preset, expected_none_preset)
        let test_cases = [
            // Force true overrides
            (Some("1"), true, true, true),
            (Some("true"), true, true, true),
            (Some("TRUE"), true, true, true),
            (Some("TrUe"), true, true, true),
            // Force false overrides
            (Some("0"), false, false, false),
            (Some("false"), false, false, false),
            (Some("FALSE"), false, false, false),
            (Some("FaLsE"), false, false, false),
            // Fallback to preset: Some(true)->true, Some(false)->false, None->false
            (None, true, false, false),
            (Some(""), true, false, false),
            (Some("   "), true, false, false),
            (Some("invalid"), true, false, false),
            (Some("2"), true, false, false),
            (Some("yes"), true, false, false),
            (Some("no"), true, false, false),
        ];

        for (env_opt, exp_true, exp_false, exp_none) in test_cases {
            match env_opt {
                Some(val) => env::set_var("SOUFFLE_HTTP3", val),
                None => env::remove_var("SOUFFLE_HTTP3"),
            }

            let cfg_true = Config::from_preset(&p_true);
            assert_eq!(
                cfg_true.http3_enabled, exp_true,
                "Failed on p_true with env={:?}",
                env_opt
            );

            let cfg_false = Config::from_preset(&p_false);
            assert_eq!(
                cfg_false.http3_enabled, exp_false,
                "Failed on p_false with env={:?}",
                env_opt
            );

            let cfg_none = Config::from_preset(&p_none);
            assert_eq!(
                cfg_none.http3_enabled, exp_none,
                "Failed on p_none with env={:?}",
                env_opt
            );
        }

        env::remove_var("SOUFFLE_HTTP3");
        env::remove_var("ADV_TEST_KEY");
    }

    #[test]
    fn test_adversarial_preset_http3_invalid_json_types() {
        let invalid_cases = [
            json!({"model": "m", "key_env": "K", "upstream_bases": ["https://ex.com"], "http3": "true"}),
            json!({"model": "m", "key_env": "K", "upstream_bases": ["https://ex.com"], "http3": 1}),
            json!({"model": "m", "key_env": "K", "upstream_bases": ["https://ex.com"], "http3": 0}),
            json!({"model": "m", "key_env": "K", "upstream_bases": ["https://ex.com"], "http3": []}),
            json!({"model": "m", "key_env": "K", "upstream_bases": ["https://ex.com"], "http3": {}}),
            json!({"model": "m", "key_env": "K", "upstream_bases": ["https://ex.com"], "http3": null}),
        ];

        for (idx, v) in invalid_cases.iter().enumerate() {
            let res = Preset::from_value("test_invalid", v);
            assert!(
                res.is_err(),
                "Case {} should fail on non-bool 'http3': {:?}",
                idx,
                v
            );
            let err = res.unwrap_err();
            assert!(
                err.contains("field 'http3' must be a boolean"),
                "Case {} error unexpected: {}",
                idx,
                err
            );
        }
    }

    #[test]
    fn test_adversarial_upstream_error_predicates_exhaustive() {
        // --- is_refused_or_rejected ---
        // Expected TRUE: H2StreamReset(7), H3StreamReset(0x010b)
        assert!(UpstreamError::H2StreamReset { error_code: 7 }.is_refused_or_rejected());
        assert!(UpstreamError::H3StreamReset { error_code: 0x010b }.is_refused_or_rejected());

        // Expected FALSE: other stream reset codes
        for code in [0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11] {
            assert!(
                !UpstreamError::H2StreamReset { error_code: code }.is_refused_or_rejected(),
                "H2StreamReset({}) should not be refused/rejected",
                code
            );
        }
        for code in [0x0100, 0x0106, 0x0107, 0x010a, 0x010c, 0x010d, 0x010e] {
            assert!(
                !UpstreamError::H3StreamReset { error_code: code }.is_refused_or_rejected(),
                "H3StreamReset({:#x}) should not be refused/rejected",
                code
            );
        }
        // GOAWAY with same codes must NOT be refused_or_rejected
        assert!(!UpstreamError::H2GoAway { error_code: 7 }.is_refused_or_rejected());
        assert!(!UpstreamError::H3GoAway { error_code: 0x010b }.is_refused_or_rejected());
        assert!(!UpstreamError::Timeout.is_refused_or_rejected());
        assert!(!UpstreamError::Connect(std::io::Error::other("conn")).is_refused_or_rejected());

        // --- is_cancelled ---
        // Expected TRUE: H2StreamReset(8), H3StreamReset(0x010c)
        assert!(UpstreamError::H2StreamReset { error_code: 8 }.is_cancelled());
        assert!(UpstreamError::H3StreamReset { error_code: 0x010c }.is_cancelled());

        // Expected FALSE: other codes
        for code in [0, 1, 7, 11] {
            assert!(!UpstreamError::H2StreamReset { error_code: code }.is_cancelled());
        }
        for code in [0x0100, 0x0107, 0x010b, 0x010d] {
            assert!(!UpstreamError::H3StreamReset { error_code: code }.is_cancelled());
        }
        assert!(!UpstreamError::H2GoAway { error_code: 8 }.is_cancelled());
        assert!(!UpstreamError::H3GoAway { error_code: 0x010c }.is_cancelled());
        assert!(!UpstreamError::Timeout.is_cancelled());

        // --- is_enhance_your_calm ---
        // Expected TRUE: H2GoAway(11), H3StreamReset(0x0107), H3GoAway(0x0107)
        assert!(UpstreamError::H2GoAway { error_code: 11 }.is_enhance_your_calm());
        assert!(UpstreamError::H3StreamReset { error_code: 0x0107 }.is_enhance_your_calm());
        assert!(UpstreamError::H3GoAway { error_code: 0x0107 }.is_enhance_your_calm());

        // Expected FALSE: H2StreamReset(11) is not goaway calm
        assert!(!UpstreamError::H2StreamReset { error_code: 11 }.is_enhance_your_calm());
        for code in [0x0100, 0x0106, 0x0108, 0x010b, 0x010c] {
            assert!(!UpstreamError::H3StreamReset { error_code: code }.is_enhance_your_calm());
            assert!(!UpstreamError::H3GoAway { error_code: code }.is_enhance_your_calm());
        }
        assert!(!UpstreamError::H2GoAway { error_code: 0 }.is_enhance_your_calm());
        assert!(!UpstreamError::Timeout.is_enhance_your_calm());

        // --- is_goaway_clean ---
        // Expected TRUE: H2GoAway(0), H3GoAway(0x0100), H3GoAway(0)
        assert!(UpstreamError::H2GoAway { error_code: 0 }.is_goaway_clean());
        assert!(UpstreamError::H3GoAway { error_code: 0x0100 }.is_goaway_clean());
        assert!(UpstreamError::H3GoAway { error_code: 0 }.is_goaway_clean());

        // Expected FALSE: stream resets with 0 or 0x0100
        assert!(!UpstreamError::H2StreamReset { error_code: 0 }.is_goaway_clean());
        assert!(!UpstreamError::H3StreamReset { error_code: 0x0100 }.is_goaway_clean());
        assert!(!UpstreamError::H3GoAway { error_code: 0x0107 }.is_goaway_clean());
        assert!(!UpstreamError::H3GoAway { error_code: 0x0102 }.is_goaway_clean());
        assert!(!UpstreamError::H2GoAway { error_code: 11 }.is_goaway_clean());
        assert!(!UpstreamError::Timeout.is_goaway_clean());
    }

    #[test]
    fn test_adversarial_retry_loop_behavior_matrix() {
        // Models the exact dispatch decision logic in src/main.rs (lines 2246-2374 and 2604-2718)
        #[derive(Debug, PartialEq)]
        enum RetryAction {
            FreeRetry { delay_ms: u64 },
            BackoffRetry { multiplier: f64 },
            TerminalError(u16),
        }

        fn classify_retry(
            err: &UpstreamError,
            attempt: usize,
            max_retry: usize,
            free_retries: u32,
            max_free_retries: u32,
        ) -> RetryAction {
            match err {
                // Permanent for this request (oversized header block): answer now,
                // never retry, never evict a connection that is healthy.
                UpstreamError::HeaderTooBig { .. } => RetryAction::TerminalError(502),
                UpstreamError::H2StreamReset { error_code: 7 }
                | UpstreamError::H3StreamReset { error_code: 0x010b } => {
                    if free_retries < max_free_retries {
                        RetryAction::FreeRetry { delay_ms: 10 }
                    } else {
                        RetryAction::TerminalError(502)
                    }
                }
                UpstreamError::H2StreamReset { error_code: 8 }
                | UpstreamError::H3StreamReset { error_code: 0x010c } => {
                    if attempt < max_retry - 1 {
                        RetryAction::BackoffRetry { multiplier: 1.0 }
                    } else {
                        RetryAction::TerminalError(502)
                    }
                }
                UpstreamError::H2GoAway { error_code: 0, .. }
                | UpstreamError::H3GoAway { error_code: 0x0100 }
                | UpstreamError::H3GoAway { error_code: 0 } => {
                    if free_retries < max_free_retries {
                        RetryAction::FreeRetry { delay_ms: 0 }
                    } else {
                        RetryAction::TerminalError(502)
                    }
                }
                UpstreamError::H2GoAway { error_code: 11, .. }
                | UpstreamError::H3StreamReset { error_code: 0x0107 }
                | UpstreamError::H3GoAway { error_code: 0x0107 } => {
                    if attempt < max_retry - 1 {
                        RetryAction::BackoffRetry { multiplier: 2.0 }
                    } else {
                        RetryAction::TerminalError(502)
                    }
                }
                UpstreamError::H3GoAway { .. } | UpstreamError::H2GoAway { .. } => {
                    RetryAction::TerminalError(502)
                }
                _ => {
                    if attempt < max_retry - 1 {
                        RetryAction::BackoffRetry { multiplier: 1.0 }
                    } else {
                        RetryAction::TerminalError(502)
                    }
                }
            }
        }

        const MAX_FREE: u32 = 8;
        const MAX_RETRY: usize = 15;

        // 1. 0x010b free retry budget (0..8 -> FreeRetry, 8 -> 502)
        let err_010b = UpstreamError::H3StreamReset { error_code: 0x010b };
        for free in 0..MAX_FREE {
            assert_eq!(
                classify_retry(&err_010b, 0, MAX_RETRY, free, MAX_FREE),
                RetryAction::FreeRetry { delay_ms: 10 }
            );
        }
        assert_eq!(
            classify_retry(&err_010b, 0, MAX_RETRY, MAX_FREE, MAX_FREE),
            RetryAction::TerminalError(502)
        );

        // 2. 0x0100 clean GOAWAY free retry budget
        let err_0100 = UpstreamError::H3GoAway { error_code: 0x0100 };
        for free in 0..MAX_FREE {
            assert_eq!(
                classify_retry(&err_0100, 0, MAX_RETRY, free, MAX_FREE),
                RetryAction::FreeRetry { delay_ms: 0 }
            );
        }
        assert_eq!(
            classify_retry(&err_0100, 0, MAX_RETRY, MAX_FREE, MAX_FREE),
            RetryAction::TerminalError(502)
        );

        // 3. 0x010c CANCEL triggers normal backoff (1x)
        let err_010c = UpstreamError::H3StreamReset { error_code: 0x010c };
        assert_eq!(
            classify_retry(&err_010c, 0, MAX_RETRY, 0, MAX_FREE),
            RetryAction::BackoffRetry { multiplier: 1.0 }
        );
        assert_eq!(
            classify_retry(&err_010c, MAX_RETRY - 2, MAX_RETRY, 0, MAX_FREE),
            RetryAction::BackoffRetry { multiplier: 1.0 }
        );
        assert_eq!(
            classify_retry(&err_010c, MAX_RETRY - 1, MAX_RETRY, 0, MAX_FREE),
            RetryAction::TerminalError(502)
        );

        // 4. 0x0107 EXCESSIVE_LOAD triggers 2x backoff and enforces max_retry cap
        let err_0107_reset = UpstreamError::H3StreamReset { error_code: 0x0107 };
        let err_0107_goaway = UpstreamError::H3GoAway { error_code: 0x0107 };
        assert_eq!(
            classify_retry(&err_0107_reset, 0, MAX_RETRY, 0, MAX_FREE),
            RetryAction::BackoffRetry { multiplier: 2.0 }
        );
        assert_eq!(
            classify_retry(&err_0107_goaway, 2, MAX_RETRY, 0, MAX_FREE),
            RetryAction::BackoffRetry { multiplier: 2.0 }
        );
        assert_eq!(
            classify_retry(&err_0107_reset, MAX_RETRY - 1, MAX_RETRY, 0, MAX_FREE),
            RetryAction::TerminalError(502)
        );
        assert_eq!(
            classify_retry(&err_0107_goaway, MAX_RETRY - 1, MAX_RETRY, 0, MAX_FREE),
            RetryAction::TerminalError(502)
        );

        // 5. Unclean GOAWAY (0x0102 H3_INTERNAL_ERROR) -> terminal 502 immediately
        let err_dirty_goaway = UpstreamError::H3GoAway { error_code: 0x0102 };
        assert_eq!(
            classify_retry(&err_dirty_goaway, 0, MAX_RETRY, 0, MAX_FREE),
            RetryAction::TerminalError(502)
        );
    }

    #[test]
    fn test_header_too_big_dispatch_is_terminal() {
        // HeaderTooBig is permanent for this request: dispatch must answer 502 at
        // once instead of retrying up to max_retry and evicting the pooled
        // connection on every attempt.
        let e = UpstreamError::HeaderTooBig {
            actual_size: 65_536,
            max_size: 16_384,
        };
        assert!(
            is_terminal_upstream_error(&e),
            "HeaderTooBig must be dispatched on the terminal arm"
        );
        // ...and it must not take either invalidation path on the way out.
        assert!(
            !e.is_stream_scoped(),
            "HeaderTooBig must not evict a single stream"
        );
        assert!(
            !e.is_connection_closing(),
            "HeaderTooBig must not evict the pooled connection"
        );

        // Failures that stay retryable must not be swallowed by the terminal arm.
        for e in [
            UpstreamError::H2StreamReset { error_code: 0x0102 },
            UpstreamError::H3StreamReset { error_code: 0x0102 },
            UpstreamError::H2GoAway { error_code: 0 },
            UpstreamError::H3GoAway { error_code: 0x0100 },
            UpstreamError::Connect(std::io::Error::other("dial")),
            UpstreamError::Timeout,
            UpstreamError::Other("boom".into()),
        ] {
            assert!(
                !is_terminal_upstream_error(&e),
                "{e} must keep its existing retry behaviour"
            );
        }
    }

    #[test]
    fn test_adversarial_from_h3_stream_and_connection_errors() {
        // Direct conversion testing from h3::error types into UpstreamError
        let stream_err_reject = h3::error::StreamError::RemoteTerminate {
            code: h3::error::Code::H3_REQUEST_REJECTED,
        };
        let upstream_reject = UpstreamError::from(stream_err_reject);
        assert!(upstream_reject.is_refused_or_rejected());
        assert!(!upstream_reject.is_cancelled());

        let stream_err_cancel = h3::error::StreamError::RemoteTerminate {
            code: h3::error::Code::H3_REQUEST_CANCELLED,
        };
        let upstream_cancel = UpstreamError::from(stream_err_cancel);
        assert!(upstream_cancel.is_cancelled());
        assert!(!upstream_cancel.is_refused_or_rejected());

        let stream_err_load = h3::error::StreamError::RemoteTerminate {
            code: h3::error::Code::H3_EXCESSIVE_LOAD,
        };
        let upstream_load = UpstreamError::from(stream_err_load);
        assert!(upstream_load.is_enhance_your_calm());

        let stream_err_closing = h3::error::StreamError::RemoteClosing;
        let upstream_closing = UpstreamError::from(stream_err_closing);
        assert!(upstream_closing.is_goaway_clean());

        let conn_err_close = h3::error::ConnectionError::Remote(
            h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code: 0x0100 },
        );
        let upstream_conn_close = UpstreamError::from(conn_err_close);
        assert!(upstream_conn_close.is_goaway_clean());

        let conn_err_timeout = h3::error::ConnectionError::Timeout;
        let upstream_timeout = UpstreamError::from(conn_err_timeout);
        assert!(matches!(upstream_timeout, UpstreamError::Timeout));
    }

    #[tokio::test]
    async fn test_b1_sse_done_line_and_static_endpoints() {
        // B1: [DONE] inside content text or response.completed must NOT mark seen_done
        assert!(is_sse_done_line(b"data: [DONE]\r"));
        assert!(is_sse_done_line(b"data:[DONE]"));
        assert!(!is_sse_done_line(
            br#"data: {"choices":[{"delta":{"content":"Literal [DONE] here"}}]}"#
        ));
        assert!(!is_sse_done_line(br#"data: {"type":"response.completed"}"#));
        assert!(!is_sse_done_line(br#"data: {"type":"response.done"}"#));

        // O7: static /health and /v1/models preserve JSON + nocache headers
        let h_resp = handle_health().await;
        assert_eq!(h_resp.status(), StatusCode::OK);
        assert_eq!(
            h_resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-cache, no-store, must-revalidate, max-age=0"
        );
        let h_bytes = axum::body::to_bytes(h_resp.into_body(), 4096).await.unwrap();
        let h_json: Value = serde_json::from_slice(&h_bytes).unwrap();
        assert_eq!(h_json["status"], "ok");
        assert_eq!(h_json["provider"], "souffle_proxy");

        let m_resp = handle_models().await;
        assert_eq!(m_resp.status(), StatusCode::OK);
        let m_bytes = axum::body::to_bytes(m_resp.into_body(), 4096).await.unwrap();
        let m_json: Value = serde_json::from_slice(&m_bytes).unwrap();
        assert_eq!(m_json["object"], "list");
        assert_eq!(m_json["data"].as_array().unwrap().len(), 2);

        // Unknown routes fall through to the 404 fallback. Mounted native
        // routes are exercised separately through build_router.
        let fb_req = Request::builder()
            .method(Method::POST)
            .uri("/v1/not-an-endpoint")
            .body(Body::empty())
            .unwrap();
        let fb_resp = handle_fallback(fb_req).await;
        assert_eq!(fb_resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_b2_b3_empty_sse_and_usage_without_space() {
        // B2: aggregate across ALL lines + data: without space + delta.reasoning + message equivalents
        let content_then_stop = b"data:{\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\ndata:{\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n";
        assert!(!is_empty_sse_response(content_then_stop));

        let reasoning_then_stop = b"data:{\"choices\":[{\"delta\":{\"reasoning\":\"thought\"}}]}\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n";
        assert!(!is_empty_sse_response(reasoning_then_stop));

        let msg_content = b"data:{\"choices\":[{\"message\":{\"content\":\"hi\"},\"finish_reason\":\"stop\"}]}\n";
        assert!(!is_empty_sse_response(msg_content));

        let truly_empty = b"data:{\"choices\":[{\"delta\":{\"content\":\"\"},\"finish_reason\":\"stop\"}]}\n";
        assert!(is_empty_sse_response(truly_empty));

        // B3: extract_usage_from_sse_line without space after data:
        let usage = extract_usage_from_sse_line(
            r#"data:{"usage":{"prompt_tokens":12,"completion_tokens":5,"reasoning_tokens":3}}"#,
        )
        .unwrap();
        assert_eq!(usage.prompt_tokens, Some(12));
        assert_eq!(usage.completion_tokens, Some(5));
        assert_eq!(usage.reasoning_tokens(), 3);
        assert!(extract_usage_from_sse_line("data:[DONE]").is_none());
    }

    #[test]
    fn test_o3_fold_in_content_cot_preserves_non_assistant_verbatim() {
        let msgs_raw = r#"[  {"custom_key":true,"role":"user","content":"Hello \u0041"}, {"role":"assistant","content":"plain"}, {"role":"assistant","reasoning_content":"step 1","content":"answer"} ]"#;
        let folded = fold_in_content_cot(msgs_raw).unwrap();
        let out = folded.get();
        // Exact non-matching user & plain assistant JSON slices stay verbatim
        assert!(out.contains(r#"{"custom_key":true,"role":"user","content":"Hello \u0041"}"#));
        assert!(out.contains(r#"{"role":"assistant","content":"plain"}"#));

        let parsed: Vec<Value> = serde_json::from_str(out).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[2]["content"], "<think>\nstep 1\n</think>\n\nanswer");
        assert_eq!(parsed[2]["reasoning_content"], "");
    }

    #[tokio::test]
    async fn test_b4_e2e_stream_fast_disconnect_after_done_credits_prompt_tokens() {
        let (addr, _attempts, _chunks_sent, _reset) = spawn_mock_h2_server(vec![
            MockUpstreamReply::StreamChunks {
                chunks: vec![
                    Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"),
                    Bytes::from("data: {\"usage\":{\"prompt_tokens\":42,\"completion_tokens\":7,\"reasoning_tokens\":3}}\n\n"),
                    Bytes::from("data: [DONE]\n\n"),
                    // Upstream lingers after [DONE]; client will drop body immediately
                    Bytes::from("data: {\"choices\":[]}\n\n"),
                ],
                delay_ms: 2500,
            },
        ])
        .await;

        let state = make_test_app_state(&format!("http://{addr}/v1"), false, 2);
        let resp = handle_chat_completions(State(state.clone()), make_chat_req(true)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let mut data_stream = resp.into_body().into_data_stream();
        let mut buf = Vec::new();
        while let Some(Ok(chunk)) = data_stream.next().await {
            buf.extend_from_slice(&chunk);
            if memchr::memmem::find(&buf, b"data: [DONE]").is_some() {
                break;
            }
        }
        drop(data_stream);

        let mut ok = false;
        for _ in 0..40 {
            if state.stats.total_tokens_prompt.load(Ordering::Relaxed) == 42
                && state.stats.total_tokens_completion.load(Ordering::Relaxed) == 7
                && state.stats.total_tokens_reasoning.load(Ordering::Relaxed) == 3
                && state.stats.success_count.load(Ordering::Relaxed) == 1
            {
                ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(ok, "StreamDisconnectGuard must credit prompt/completion/reasoning tokens on fast close after [DONE]");
    }

    #[tokio::test]
    async fn test_b8_e2e_nonstream_body_error_and_timeout_retry() {
        let good_json = Bytes::from(
            r#"{"id":"ok","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
        );

        // 1. Mid-body RST_STREAM retries and succeeds
        let (addr_rst, attempts_rst, _, _) = spawn_mock_h2_server(vec![
            MockUpstreamReply::BufferedReset,
            MockUpstreamReply::BufferedJson(good_json.clone()),
        ])
        .await;
        let state_rst = make_test_app_state(&format!("http://{addr_rst}/v1"), false, 3);
        let resp_rst = handle_chat_completions(State(state_rst), make_chat_req(false)).await;
        assert_eq!(resp_rst.status(), StatusCode::OK);
        assert_eq!(attempts_rst.load(Ordering::SeqCst), 2);

        // 2. Non-stream body read timeout retries and succeeds
        let (addr_tmo, attempts_tmo, _, _) = spawn_mock_h2_server(vec![
            MockUpstreamReply::BufferedDelay {
                body: good_json.clone(),
                delay: Duration::from_millis(300),
            },
            MockUpstreamReply::BufferedJson(good_json),
        ])
        .await;
        let mut cfg = (*make_test_app_state(&format!("http://{addr_tmo}/v1"), false, 3).slots[0]
            .config)
            .clone();
        cfg.read_timeout = Duration::from_millis(80);
        let client = UpstreamClient::H2(
            H2Client::new(
                &cfg.upstream_bases,
                cfg.connect_timeout,
                cfg.keepalive_expiry,
                true,
            )
            .unwrap(),
        );
        let state_tmo = Arc::new(AppState {
            slots: vec![Arc::new(PresetRuntime {
                config: Arc::new(cfg),
                client,
                model_index: AtomicUsize::new(0),
                key_index: AtomicUsize::new(0),
            })],
            semaphore: Arc::new(Semaphore::new(20)),
            stats: Arc::new(ProxyStats::new()),
            stripped_headers: HashSet::new(),
        });
        let resp_tmo = handle_chat_completions(State(state_tmo), make_chat_req(false)).await;
        assert_eq!(resp_tmo.status(), StatusCode::OK);
        assert_eq!(attempts_tmo.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn e2e_multi_model_retry_bodies_match_full_serialization() {
        // Every attempt must ship exactly what the old full-serialize path sent:
        // only the model literal changes between retries.
        let good_json = Bytes::from(
            r#"{"id":"ok","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
        );
        let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (addr, attempts, _, _) = spawn_mock_h2_server_with_bodies(
            vec![
                MockUpstreamReply::BufferedReset,
                MockUpstreamReply::BufferedReset,
                MockUpstreamReply::BufferedJson(good_json),
            ],
            bodies.clone(),
        )
        .await;

        let prep = r#"{"role":"system","content":"sys"}"#;
        let app = r#"{"role":"assistant","content":"prefill"}"#;
        let mut cfg = (*make_test_app_state(&format!("http://{addr}/v1"), false, 3).slots[0]
            .config)
            .clone();
        cfg.models = vec![
            "model-a".to_string(),
            "model-b".to_string(),
            "z-ai/model-c-long".to_string(),
        ];
        cfg.models_raw = models_to_raw(&cfg.models).unwrap();
        cfg.prepend_raw = Some(prep.to_string());
        cfg.prepend_messages = vec![json!({"role": "system", "content": "sys"})];
        cfg.append_raw = Some(app.to_string());
        cfg.append_messages = vec![json!({"role": "assistant", "content": "prefill"})];
        let client = UpstreamClient::H2(
            H2Client::new(
                &cfg.upstream_bases,
                cfg.connect_timeout,
                cfg.keepalive_expiry,
                true,
            )
            .unwrap(),
        );
        let state = Arc::new(AppState {
            slots: vec![Arc::new(PresetRuntime {
                config: Arc::new(cfg),
                client,
                model_index: AtomicUsize::new(0),
                key_index: AtomicUsize::new(0),
            })],
            semaphore: Arc::new(Semaphore::new(20)),
            stats: Arc::new(ProxyStats::new()),
            stripped_headers: HashSet::new(),
        });
        let resp = handle_chat_completions(State(state.clone()), make_chat_req(false)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);

        // Reference: old implementation = materialized messages array + full
        // re-serialize of the payload map per rotation.
        let client_body = json!({
            "model": "deepseek-souffle",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": false
        })
        .to_string();
        let mut client_map: BTreeMap<String, Box<RawValue>> =
            serde_json::from_str(&client_body).unwrap();
        let client_msgs = client_map.remove("messages").unwrap();
        let spliced = {
            let (splice, count, _, _) =
                plan_messages_splice(client_msgs.clone(), Some(prep), 1, Some(app), 1);
            assert_eq!(count, 3);
            let mut out = Vec::new();
            match splice {
                MsgsSplice::Spliced(s) => s.emit_into(&mut out),
                MsgsSplice::Verbatim(_) => panic!("expected a splice"),
            }
            String::from_utf8(out).unwrap()
        };

        let captured = bodies.lock().unwrap();
        assert_eq!(captured.len(), 3, "each attempt must send a body");
        // The real serialized body (spliced messages included) must be patchable,
        // otherwise dispatch would quietly fall back to a full re-serialize.
        assert!(matches!(
            patch_serialized_model(&Bytes::copy_from_slice(&captured[0]), "\"model-b\""),
            ModelPatch::Replaced(_)
        ));
        for (idx, model) in ["model-a", "model-b", "z-ai/model-c-long"]
            .iter()
            .enumerate()
        {
            let mut reference = client_map.clone();
            reference.insert(
                "messages".to_string(),
                RawValue::from_string(spliced.clone()).unwrap(),
            );
            reference.insert(
                "model".to_string(),
                RawValue::from_string(format!("\"{model}\"")).unwrap(),
            );
            let mut reference_buf = Vec::new();
            serde_json::to_writer(&mut reference_buf, &reference).unwrap();

            assert_eq!(
                captured[idx],
                reference_buf,
                "attempt {idx} body differs from the full-serialize reference"
            );
            let parsed: Value = serde_json::from_slice(&captured[idx]).unwrap();
            assert_eq!(parsed["model"], *model);
            assert_eq!(parsed["messages"].as_array().unwrap().len(), 3);
            assert_eq!(parsed["messages"][0]["role"], "system");
            assert_eq!(parsed["messages"][2]["role"], "assistant");
        }
    }

    #[tokio::test]
    async fn test_b9_e2e_huge_sse_line_over_1mb_passes_through_intact() {
        let huge_payload = "x".repeat(1_150_000);
        let huge_line = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{}\"}}}}]}}\n\n",
            huge_payload
        );
        let split_at = huge_line.len() / 2;
        let part1 = Bytes::from(huge_line[..split_at].to_string());
        let part2 = Bytes::from(huge_line[split_at..].to_string());
        let done = Bytes::from_static(b"data: [DONE]\n\n");

        let (addr, _, _, _) = spawn_mock_h2_server(vec![MockUpstreamReply::StreamChunks {
            chunks: vec![part1, part2, done],
            delay_ms: 0,
        }])
        .await;

        let state = make_test_app_state(&format!("http://{addr}/v1"), false, 2);
        let resp = handle_chat_completions(State(state.clone()), make_chat_req(true)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(body.len(), huge_line.len() + "data: [DONE]\n\n".len());
        assert_eq!(state.stats.success_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_o1_o2_e2e_burst_coalescing_and_idle_timeout() {
        // O1: burst frames coalesce cleanly preserving exact payload & stats
        let chunks = vec![
            Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n"),
            Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"b\"}}]}\n\n"),
            Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"c\"}}]}\n\n"),
            Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"d\"}}]}\n\n"),
            Bytes::from_static(b"data: {\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4}}\n\n"),
            Bytes::from_static(b"data: [DONE]\n\n"),
        ];
        let expected: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        let (addr, _, _, _) = spawn_mock_h2_server(vec![MockUpstreamReply::StreamChunks {
            chunks,
            delay_ms: 0,
        }])
        .await;
        let state = make_test_app_state(&format!("http://{addr}/v1"), false, 2);
        let resp = handle_chat_completions(State(state.clone()), make_chat_req(true)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), expected.as_slice());
        assert_eq!(state.stats.total_tokens_completion.load(Ordering::Relaxed), 4);

        // O2: short read_timeout (<2s) resets Sleep accurately and triggers idle_read_timeout
        let (addr_tmo, _, _, _) =
            spawn_mock_h2_server(vec![MockUpstreamReply::StreamStallAfterFirst {
                first: Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"),
                stall: Duration::from_millis(350),
            }])
            .await;
        let mut cfg = (*make_test_app_state(&format!("http://{addr_tmo}/v1"), false, 1).slots[0]
            .config)
            .clone();
        cfg.read_timeout = Duration::from_millis(100);
        let client = UpstreamClient::H2(
            H2Client::new(
                &cfg.upstream_bases,
                cfg.connect_timeout,
                cfg.keepalive_expiry,
                true,
            )
            .unwrap(),
        );
        let state_tmo = Arc::new(AppState {
            slots: vec![Arc::new(PresetRuntime {
                config: Arc::new(cfg),
                client,
                model_index: AtomicUsize::new(0),
                key_index: AtomicUsize::new(0),
            })],
            semaphore: Arc::new(Semaphore::new(20)),
            stats: Arc::new(ProxyStats::new()),
            stripped_headers: HashSet::new(),
        });
        let resp_tmo = handle_chat_completions(State(state_tmo.clone()), make_chat_req(true)).await;
        let mut s = resp_tmo.into_body().into_data_stream();
        let mut saw_err = false;
        while let Some(item) = s.next().await {
            if item.is_err() {
                saw_err = true;
                break;
            }
        }
        assert!(saw_err, "mid-stream idle timeout must abort downstream stream");
        assert_eq!(state_tmo.stats.error_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_o2_e2e_throttled_reset_preserves_full_read_timeout() {
        // read_timeout = 2.0s enables the >=2s 1Hz Sleep::reset throttle.
        // Chunk 1 arrives at 700ms (reset skipped due to <1s throttle), then chunk 2 arrives
        // 1.45s later (at t=2.15s, past the initial 2.0s deadline). Because the inter-chunk gap
        // (1.45s) is strictly < read_timeout (2.0s), the stream MUST NOT prematurely time out.
        let (addr, _, _, _) = spawn_mock_h2_server(vec![MockUpstreamReply::StreamDelayedSchedule {
            steps: vec![
                (Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n"), Duration::ZERO),
                (Bytes::from_static(b"data: {\"choices\":[{\"delta\":{\"content\":\"b\"}}]}\n\n"), Duration::from_millis(700)),
                (Bytes::from_static(b"data: [DONE]\n\n"), Duration::from_millis(1450)),
            ],
        }])
        .await;

        let mut cfg = (*make_test_app_state(&format!("http://{addr}/v1"), false, 1).slots[0].config).clone();
        cfg.read_timeout = Duration::from_secs(2);
        let client = UpstreamClient::H2(
            H2Client::new(
                &cfg.upstream_bases,
                cfg.connect_timeout,
                cfg.keepalive_expiry,
                true,
            )
            .unwrap(),
        );
        let state = Arc::new(AppState {
            slots: vec![Arc::new(PresetRuntime {
                config: Arc::new(cfg),
                client,
                model_index: AtomicUsize::new(0),
                key_index: AtomicUsize::new(0),
            })],
            semaphore: Arc::new(Semaphore::new(20)),
            stats: Arc::new(ProxyStats::new()),
            stripped_headers: HashSet::new(),
        });
        let resp = handle_chat_completions(State(state.clone()), make_chat_req(true)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("stream with 1.45s gap under 2s read_timeout must complete without premature timeout");
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(body_str.contains("[DONE]"));
        assert_eq!(state.stats.success_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_b5_e2e_enhance_your_calm_exhaustion_in_dispatch() {
        // 1. Pre-header ENHANCE_YOUR_CALM with max_retry = 1 -> immediate 502, no infinite retry
        let (addr_pre, attempts_pre, _, _) =
            spawn_mock_h2_server(vec![MockUpstreamReply::GoAwayEnhanceYourCalmPreHeader]).await;
        let state_pre = make_test_app_state(&format!("http://{addr_pre}/v1"), false, 1);
        let resp_pre = handle_chat_completions(State(state_pre.clone()), make_chat_req(true)).await;
        assert_eq!(resp_pre.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(attempts_pre.load(Ordering::SeqCst), 1);
        assert_eq!(state_pre.stats.error_count.load(Ordering::Relaxed), 1);

        // 2. First-chunk ENHANCE_YOUR_CALM with max_retry = 1 -> immediate 502, no infinite retry
        let (addr_fc1, attempts_fc1, _, _) =
            spawn_mock_h2_server(vec![MockUpstreamReply::GoAwayEnhanceYourCalmFirstChunk]).await;
        let state_fc1 = make_test_app_state(&format!("http://{addr_fc1}/v1"), false, 1);
        let resp_fc1 = handle_chat_completions(State(state_fc1.clone()), make_chat_req(true)).await;
        assert_eq!(resp_fc1.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(attempts_fc1.load(Ordering::SeqCst), 1);
        assert_eq!(state_fc1.stats.error_count.load(Ordering::Relaxed), 1);

        // 3. First-chunk ENHANCE_YOUR_CALM with max_retry = 2 -> retries once (2x backoff), then 502
        let (addr_fc2, attempts_fc2, _, _) =
            spawn_mock_h2_server(vec![MockUpstreamReply::GoAwayEnhanceYourCalmFirstChunk]).await;
        let state_fc2 = make_test_app_state(&format!("http://{addr_fc2}/v1"), false, 2);
        let resp_fc2 = handle_chat_completions(State(state_fc2.clone()), make_chat_req(true)).await;
        assert_eq!(resp_fc2.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(attempts_fc2.load(Ordering::SeqCst), 2);
        assert_eq!(state_fc2.stats.error_count.load(Ordering::Relaxed), 1);
    }
}


