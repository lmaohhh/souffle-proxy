# PROGRESS — transport slice (branch hardening-transport)

Scope: `src/upstream.rs` only. Four defects, highest first.

- [x] (1) H3 stream-level invalidation must not close the shared QUIC connection
      New `invalidate_stream_if_same(conn_id)` on `H2Client` / `H3Client` /
      `UpstreamClient`. H3 body is intentionally empty: the request stream is
      already dead and the pooled QUIC connection stays healthy. H2 keeps its
      existing pool-drop (no collateral there). `invalidate_if_same` remains the
      connection-level path (GOAWAY / protocol / connect / TTFT wedge).
      `UpstreamError::is_stream_scoped()` classifies which callers use which.
      **CALLER CHANGE REQUIRED (main.rs, dispatch slice):** at the stream-reset
      arms (H2 RST 7/8, H3 0x010b/0x010c/0x0107 stream resets, both the
      first-chunk and send-error branches) call `invalidate_stream_if_same(conn_id)`
      instead of `invalidate_if_same(conn_id)`; leave GOAWAY / `other` arms on
      `invalidate_if_same`. Until then the new methods carry `#[allow(dead_code)]`.
- [x] (2) H3 `send_stream` retried every error and dropped the real one.
      Retries only when `is_connection_closing()`; `HeaderTooBig` is now its own
      `UpstreamError` variant (`actual_size`/`max_size`) and is returned directly.
- [x] (3) H2 `connect_raw`: one deadline for TCP + TLS + h2 handshake.
- [x] (4) `h3_handshake_budget()` gives the h3 control handshake a floor
      (`H3_HANDSHAKE_FLOOR` 2s, capped by `connect_timeout`). H3 DNS now spends
      from the attempt deadline instead of a fresh `connect_timeout`.

Tests added: `test_error_classification_stream_scoped_vs_connection_closing`,
`test_h3_handshake_budget_has_floor_and_stays_bounded`,
`test_h3_stream_invalidation_preserves_concurrent_response` (real loopback h3;
also asserts the connection-level path *does* abort the in-flight response).

Gates: `cargo test` 76 passed / 0 failed; `cargo clippy --all-targets -- -D warnings` clean.
