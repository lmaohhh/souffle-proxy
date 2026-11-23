# PROGRESS — slice: fold (zero-AST fold_in_content_cot)

Worktree: `C:/Users/souffle/.gemini/scratch/souffle-proxy-wt-fold` (branch `hardening-fold`)
Base: `bc587f5`

## Plan
- Replace `serde_json::Map` DOM round-trip in `fold_in_content_cot` with quote/escape-aware
  byte-span splicing of top-level element members.
- Reuse `memchr::memchr2` string scanning (same trick as `scan_json_array`).
- Array content: text parts concatenated raw, non-text parts carried verbatim.
- Raw trim/trim_start that understands `\n`/`\t`/`\r`/`\u00XX` escapes so rc stays esc

## Log
- (start) read brief, located fn at src/main.rs:2018, tests at 5826-6060 + 6750.
- impl: replaced Map round-trip with span scanner (`for_each_object_member`,
  `scan_json_value_end`, `scan_json_string_end` using memchr2) + value splicing.
  Raw trim helpers understand `\n`/`\t`/`\r`/`\u00XX` so rc stays escaped.
- fix: emitted array text part was missing its closing `}` (caught by
  test_souffle_pout_array_multimodal_content). clippy needless_lifetimes on
  raw_string_body.
- gate: `cargo test` 74 passed / 0 failed; clippy `-D warnings` clean -> commit cf9346e.
- added tests: raw-escape byte-identity (\" \n \u00e9 中文 🦀 \/), plus
  content-key-absent insert path and empty-reasoning_content fallback.
- gate: `cargo test` 75 passed / 0 failed; clippy clean.
- found+fixed via differential harness (legacy DOM vs new splice over 25 shapes):
  non-string `content` (object/number) was spliced unescaped -> invalid JSON -> fold
  silently disabled. Now escaped through `serde_json::to_string`. Harness removed;
  regression locked by `test_souffle_pout_non_string_content_is_escaped`.
- final gate: `cargo test` 77 passed / 0 failed; clippy `-D warnings` clean.
