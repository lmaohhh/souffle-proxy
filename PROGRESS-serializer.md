# PROGRESS — serializer slice (retry-path + splice zero-copy)

Worktree: `C:/Users/souffle/.gemini/scratch/souffle-proxy-wt-serializer`, branch `hardening-serializer`.
Files: `src/main.rs` only. Gate: `verify-wt.bat` (cargo test + clippy -D warnings).

## Status

- [x] (1) Retry model-rotation span patch — done, gate green (75 tests, clippy 0).
      `patch_serialized_model` + `find_top_level_value_span` alongside `scan_json_array`.
      Retry no longer re-serializes the payload; brotli re-encode only when the
      literal actually changed (see deviation note below).
- [x] (2) Lazy prepend/append splice — done, gate green (77 tests, clippy 0).
      `plan_messages_splice` returns `MsgsSplice::Spliced(SplicedMessages{body, inner, prefix, suffix})`;
      `UpstreamPayload` emits the array from those ranges at the map's sorted key slot.
      No array copy, no `RawValue::from_string` re-validation.
- [x] Tests: 3-retry byte-identity (unit), payload-level byte identity (unit),
      e2e capture of 3 rotated outbound bodies from the mock upstream.

## Measurements (release, 3MB body, 20 iters, one-off probe, probe removed)

- retry: span patch 0.173ms vs clone+full re-serialize 0.357ms.
- splice: lazy emit 0.203ms vs copy array + re-validate 0.460ms.

## Deviation

Brief said "recompress only if brotli is enabled and the model bytes actually
changed length". Length equality does not preserve a brotli stream — any content
change invalidates the encode — so the gate is "literal actually changed"
(`ModelPatch::Unchanged` skips both the patch and the re-encode). Re-encoding is
unavoidable when the rotated literal differs; only the re-serialize is gone.
