# souffle_proxy

A high-performance local OpenAI-compatible reverse proxy in Rust. It sits between your client
and an upstream relay, force-injects reasoning/thinking knobs, manages HTTP/2 keep-alives and failovers,
retries retryable failures with exponential backoff, translates upstream edge errors into standard JSON,
and operates with zero disk persistence.

One rule governs the whole design: **the proxy always wins.** If a key is in the
preset's `inject`, the client's value for it is overwritten. You
run this proxy precisely so "thinking on, effort max, trace preserved" is a
guarantee instead of a hope.

## What it does

- **Forces the model.** Whatever model string the client sends, the request
  becomes the preset's `model` before it leaves. Browser clients hard-code arbitrary strings;
  an unknown model id is a guaranteed `model_not_found`. This turns that into a
  200.
- **Force-injects body params.** `inject` is raw JSON from `config.json`, spliced
  onto every request body. The binary contains **zero model-family logic** — no
  hardcoded vendor branches. You configure the params in `config.json`, the proxy stamps them.
- **Retries like it means it.** 15 attempts (default, tunable via `SOUFFLE_MAX_RETRY`), 1→16s exponential backoff with
  jitter, plus a capped budget of 8 free h2 reconnects for REFUSED_STREAM /
  GOAWAY. The retryable status set: 429, 500–504, and Cloudflare's transient
  edge codes 522, 524, 529. Any 520–527 that survives the budget is
  translated to a standard `504 {"type":"upstream_timeout"}` instead of
  an HTML error page.
- **Fails loudly, never silently.** Mid-stream, three possible endings, all
  logged:

| Log line | Meaning | Client sees |
|---|---|---|
| `DONE [OK]` | Clean stream, `[DONE]` sentinel seen | normal completion |
| `DONE [TRUNCATED(<reason>)]` | Upstream died mid-stream (reset / timeout / GOAWAY) | **broken connection** so the client retries |
| `Client disconnected mid-stream` | Client dropped connection; proxy releases upstream slot immediately | n/a |

- **Accurate stream accounting.** Every chunk and byte transferred across the wire is faithfully credited to `/stats` (`total_chunks`, `total_bytes`), even when a stream terminates prematurely due to upstream reset, idle timeout, or client disconnection.
- **Strict routing with clear errors.** Unmatched endpoints or invalid methods return standard OpenAI-format `404 Not Found` JSON errors instead of swallowing typos with 200 OK health checks. Dead routes (`/v1/responses`, `/responses`) are pruned.
- **Knows when the client walked away.** A thread-safe (`Send + Sync`) atomic Drop guard inside the stream generator logs the
  disconnect, credits stats, frees the concurrency slot, and moves on.
- **Caps everything that can grow.** Request bodies (64 MB default), upstream error bodies
  (64 KB), free retries (8), idle reads (`SOUFFLE_READ_TIMEOUT`).
- **AVX-512 Brotli Upload Engine (`mbrotli`).** Outbound request bodies can be compressed via `mbrotli` with AVX-512 `fearless_simd` vectorization, clamped to maximum quality 10 (`q9` base for <256KB, `q10` for >=256KB) with adaptive sliding window sizing (`14..22` bits / 16KB..4MB) dynamically matched to payload length. Achieves ~28.3% wire footprint on real-world multi-turn conversational payloads in 12.8 ms.
- **SIMD SSE Stream Scanner (`memchr::memmem`).** SSE event chunk parsing utilizes vector substring search (`\ndata: `, `\r\ndata: `, `data: `), eliminating scalar sliding overhead across high-throughput token streams.
- **SIMD Array Scanner (`memchr::memchr2`).** Delimiter and quote scanning for request message arrays executes at ~30 GB/s, skipping full character AST parsing.
- **Owned RawValue Pipeline & Verbatim Byte Preservation.** All `/v1/chat/completions` traffic operates on `BTreeMap<String, Box<RawValue>>`, preserving exact client message bytes, whitespace, and Unicode formatting verbatim.
- **Opt-in HTTP/3 (QUIC / RFC 9114) upstream transport.** Presets that set `"http3": true`
  talk to the upstream over HTTP/3 instead of HTTP/2 — QUIC 1-RTT with ALPN `h3`, brotli,
  splicing and retry semantics unchanged. Presets without `"http3"` keep the HTTP/2 engine
  untouched as the default; the feature is strictly per-preset opt-in.
- **Zero-AST Structural Message Splicing.** `prepend_messages` and `append_messages` are pre-serialized at startup and spliced at the byte boundary with 0 AST nodes allocated, verifying the final element's `role == "user"` with zero heap bloat.
- **Dual-preset slot routing.** Launch with two presets (`souffle_proxy --preset alpha --preset beta`) and the proxy
  runs both: the client's requested model string picks the slot, so two relays live behind one port. Two slots max —
  a third `--preset` is a hard error, not a silent ignore. Unknown models fall back to slot 1 with a logged warning.
- **IPv6 upstreams, first-class.** Bracketed hosts (`[::1]`, `2001:db8::1`) are handled everywhere: TCP connect,
  TLS SNI, and QUIC SNI all dial the bare address (never a bracket-wrapped one), and the HTTP/3 UDP socket binds the
  IPv6 wildcard (`[::]:0`) when the upstream is v6 — IPv4 keeps `0.0.0.0:0`. The QUIC socket also gets 1 MB
  send/receive buffers so big SSE bursts don't drop on the kernel floor.

## Quickstart

### Build It Yourself (BIY)

Compile from source on the machine you run it on (requires Rust toolchain):

```bash
cargo build --release
```

`.cargo/config.toml` pins `-C target-cpu=native` so the binary uses your CPU's own SIMD/AVX2/AVX-512 instructions out of the box. No Windows prebuilt binaries or tailored support are offered here—build it yourself, inspect the source, and adjust `config.json` to match your own setup.

`config.json` and `.env` live **beside the exe** (using `std::env::current_exe()`):

```
exe-dir/
  souffle_proxy(.exe)
  config.json      ← preset definitions (no secrets, safe to commit)
  .env             ← API secrets (gitignored)
```

1. Copy `config.json.example` to `config.json`.
2. Put your API key in `.env` under the name specified by `key_env` in your preset.
3. Launch:

```bash
souffle_proxy                                # interactive: menu of presets (+ create new)
souffle_proxy --preset deepseek-sol         # pick preset directly
souffle_proxy --headless --preset deepseek-sol # unattended service mode
souffle_proxy --preset alpha --preset beta  # dual-slot: client model picks the slot
```

No `config.json` yet? Launch interactively once and an interactive wizard guides you to build the
first preset.

## Configuration & Tunables

Tunable via environment variables:
- `SOUFFLE_PROXY_HOST` (default: `127.0.0.1`)
- `SOUFFLE_PROXY_PORT` (default: `8799`)
- `SOUFFLE_MAX_CONCURRENCY` (default: `20`)
- `SOUFFLE_CONNECT_TIMEOUT` (default: `30.0`s)
- `SOUFFLE_WRITE_TIMEOUT` (deprecated, ignored; outbound send/TTFT timeout uses `SOUFFLE_READ_TIMEOUT`)
- `SOUFFLE_READ_TIMEOUT` (default: `600.0`s; idle stream read cap & TTFT deadline)
- `SOUFFLE_MAX_RETRY` (default: `15`)
- `SOUFFLE_MAX_BODY_BYTES` (default: `67108864` / 64MB)
- `SOUFFLE_KEEPALIVE_EXPIRY` (default: 60s; h2 PING keepalive on the pooled upstream connection; 0 = disabled)
- `SOUFFLE_INSECURE_TLS=1` (for self-signed test environments only)
- `SOUFFLE_HTTP3=1` / `true` forces HTTP/3 (QUIC) on every preset; `0` / `false` forces it
  off. Unset leaves the decision to each preset's `http3` field (default: `false`).
- `SOUFFLE_BROTLI=1` / `0` force the outbound brotli compressor on/off for every preset;
  unset defers to each preset's `brotli` field (default: off — raw passthrough).
- `SOUFFLE_BROTLI_LEVEL` (default: `9`; 0..=10. Bodies ≥256KB escalate automatically to q10).
- `SOUFFLE_BROTLI_MIN` (default: `1024` bytes; bodies smaller than this skip compression).
- `SOUFFLE_LOG_LEVEL` (default: quiet — verbose log lines suppressed; `verbose` restores them).

Per-preset in `config.json`:
- `model`: upstream model ID or array of model IDs for round-robin rotation. Also answers to
  `models` and the alias fields (`alias`, `aliases`, `model_alias`, `model_aliases`) — all merged.
- `key_env`: env var name or array of env var names for round-robin key rotation
  (default when absent: `SOUFFLE_API_KEY`).
- `upstream_bases`: ordered failover array of base URLs. Bracketed IPv6 hosts (`[2001:db8::]:443`)
  are supported on both transports.
- `inject`: raw JSON object merged onto every request body.
- `prepend_messages`: array of message objects prepended to the conversation.
- `append_messages`: array of message objects appended to the conversation.
- `degen_repeat`: opt-in boolean; `true` aborts/retries exact verbatim repetition loops mid-stream or in buffered responses across `reasoning_content` and `content`. Absent or `false` = off (no env override).
- `brotli`: opt-in boolean; `true` compresses outbound request bodies (`Content-Encoding: br`)
  with the size-escalating quality curve. Absent or `false` = raw passthrough, no compression.
- `souffle_pout`: opt-in boolean; `true` folds assistant `reasoning_content` into
  an `<think>` block prepended to `content` — for clients that can't render a separate
  reasoning channel. Absent or `false` = off.
- `http3`: opt-in boolean; `true` switches this preset's upstream transport from HTTP/2 to
  HTTP/3 (QUIC, RFC 9114). Absent or `false` keeps the HTTP/2 engine — HTTP/2 remains the
  untouched default for presets without it. QUIC is TLS-only, so point `upstream_bases` at
  `https://` origins. The connection is tuned for long SSE reasoning stalls: 15s QUIC
  keep-alive PINGs against a 60s idle timeout, 1MB stream receive window, 4MB connection
  receive window. On Windows the UDP socket disables `SIO_UDP_CONNRESET`
  (`0x9800000C`) so a transient ICMP port-unreachable cannot kill the QUIC socket with
  `WSAECONNRESET` (10054). RFC 9114 resets and GOAWAYs map into the standard retry loop:
  `0x010b` (`H3_REQUEST_REJECTED`) retries immediately like `REFUSED_STREAM` from the
  8-retry free budget, `0x010c` (`H3_REQUEST_CANCELLED`) retries with normal exponential
  backoff, and `0x0107` (`H3_EXCESSIVE_LOAD`) backs off 2x like `ENHANCE_YOUR_CALM`.

## Runtime Architecture & Memory Optimization

The proxy is engineered to operate with minimal resident memory (~9–15 MB Working Set) and zero operational memory leaks during long-lived SSE streaming sessions:

- **`mimalloc` v3 Global Allocator, Stock Configuration**: Powered by Microsoft Research's `mimalloc` (vendored v3). No `mi_option_*` tuning calls are made: the two options this proxy once set (`arena_eager_commit = 2`, `purge_decommits = 1`) are exactly the vendored v3 defaults — verified value no-ops that additionally clobbered operator `MIMALLOC_*` env overrides (read at process load, before `main`), so the mimalloc FFI was removed. The codebase keeps exactly one `unsafe` block — the Windows `SIO_UDP_CONNRESET` ioctl in `upstream.rs` that hardens the QUIC socket against spurious `WSAECONNRESET` — audited and platform-necessary. `purge_delay` stays at the v3 default (1000 ms): immediate purge measured below the noise floor and mimalloc's own docs say it "decreases performance". Rationale recorded in the operator notes (soufflotheque lib, `llm-inference/souffle-proxy-operator.md`).
- **Right-Sized Tokio Runtime**: Bounded to 3 worker threads (`worker_threads = 3`) — the workload is I/O-bound streaming, so the concurrency ceiling (`SOUFFLE_MAX_CONCURRENCY = 20`) needs only a handful of pollers (measured linear at C=100 in-tree). This saves ~29 OS thread stacks (~4.8 MB idle RAM on 32-core systems) and eliminates L1/L2 cache line bouncing and context switching.
- **Thread-Safe Atomic Guard**: `StreamDisconnectGuard` utilizes atomic synchronizations (`AtomicBool`, `AtomicU64`) guaranteeing complete `Send + Sync` safety across async generator drop lifecycles.
- **Owned RawValue Invariant (Zero-Copy Avoidance & Zero-AST Hot Path)**: The proxy operates on owned `BTreeMap<String, Box<RawValue>>`:
  - *Buffer Retention Trap Avoidance*: Avoids borrowed slices (`&RawValue`) that pin 64 MB backing buffers in RAM across async await points.
  - *Zero Recursive AST Bloat*: Eliminates recursive `Value` trees, cutting JSON memory and allocation overhead by up to 60%.
  - *Zero-AST Structural Splicing*: `prepend_messages` and `append_messages` splice pre-serialized raw fragments directly at array brackets, preserving client conversation tokens 100% bit-for-bit verbatim.
- **Zero-Reallocation Serialization**: Serialization writes directly into a pre-allocated `Vec::with_capacity(raw_len + 512)` buffer via `serde_json::to_writer`, performing 0 vector reallocations and eliminating the 44% CPU bistable page decommit/recommit churn under `mimalloc`.
- **Cached Timezone Formatting (`jiff 0.2`)**: Log timestamps cache `SYSTEM_TZ` in a static `OnceLock<jiff::tz::TimeZone>` and format civil datetime components directly, eliminating per-log-line Windows OS timezone registry queries.
- **Native Target Codegen (`.cargo/config.toml`)**: Source builds deliberately pin `rustflags = ["-C", "target-cpu=native"]` so `cargo build --release` emits host AVX2/AVX-512 instructions (`mbrotli`, SIMD `memchr::memmem` / `memrchr`) out of the box without extra flags. `README.md` already documents AVX-512 / modern SIMD support; stripping or deferring `target-cpu=native` in `.cargo/config.toml` just because someone might compile from source on a modern CPU and copy that binary onto an older CPU—despite what the README states—would handicap source builds for a mythical workflow. If you genuinely need a portable binary for a different machine, override `RUSTFLAGS="-C target-cpu=x86-64-v3"` yourself when building.

## House rules & Licensing

- **No SSD logging, ever (Security & Privacy Invariant).** All output is strictly directed to `stdout`/`stderr` (streaming O(1) memory). Because this proxy handles high-velocity raw token streams, confidential prompts, and upstream bearer credentials 24/7, serializing logs to persistent non-volatile storage (SSD/NVMe/HDD) creates unacceptable forensic traces and credential exposure.
- **Stock h2 flow control.** Tuned for reliable long-lived SSE streaming over WAN connections.

### License

Licensed under the [GNU General Public License v3.0](LICENSE) (`GPL-3.0-only`).
