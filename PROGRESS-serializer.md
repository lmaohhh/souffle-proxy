# PROGRESS — serializer slice (retry-path + splice zero-copy)

Worktree: `C:/Users/souffle/.gemini/scratch/souffle-proxy-wt-serializer`, branch `hardening-serializer`.
Files: `src/main.rs` only. Gate: `verify-wt.bat` (cargo test + clippy -D warnings).

## Status

- [x] (1) Retry model-rotation span patch — done, gate green (75 tests, clippy 0).
      `patch_serialized_model` + `find_top_level_value_span` alongside `scan_json_array`.
      Retry no longer re-serializes the payload; brotli re-encode only when the
      literal actually changed (see deviation note below).
- [ ] (2) Lazy prepend/append splice (byte ranges instead of a copied array).
