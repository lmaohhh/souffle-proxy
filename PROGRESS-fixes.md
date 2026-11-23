# fixes slice — reviewer findings 1-9

Worktree `souffle-proxy-wt-fixes`, branch `hardening-fixes`, base `821716f`.

- FIX 1 (catch-alls tear down shared H3 conn): both catch-alls in `dispatch_upstream`
  now branch on the pre-computed `stream_scoped` before invalidating.
- FIX 2 (HeaderTooBig never matched): terminal arm (guarded by
  `is_terminal_upstream_error`) in both match blocks — log + 502, no retry, no eviction.
- FIX 3 (buffered body-read error ignores scope): `e.is_stream_scoped()` branch.
