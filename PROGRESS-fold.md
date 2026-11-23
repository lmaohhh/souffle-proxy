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
