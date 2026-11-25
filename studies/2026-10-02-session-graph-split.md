# Session graph split — 274 MB → ~13 MB stored session (v0.27)

Date: 2026-10-02 · Branch: feat/session-graph-split · Author: Aliph
(Fatah/Anam-approved "proceed" — production-shaped input closing the session
storage gap the P16 real-pipeline e2e surfaced.)

## Gap this closes

The P16 real-pipeline e2e (v0.26) ran the full gateway on the real F-Droid APK
and produced a **274 MB stored session**. Two structural problems, both only
visible at production scale (a KB fixture never shows them):

1. **The Vibe IR graph was stored INLINE in the session.** The graph engine's
   output (nodes + calls; 163 MB for the real APK) was embedded verbatim in
   `session-<sha16>.json`.
2. **Every `/deepdive` / `/investigate` re-ran the engine and `upsert()`
   re-embedded the whole graph + re-serialized the 274 MB session** (indent=2).
   A single `/investigate MainActivity.onCreate` = 64.8 s, of which a large
   share was JSON re-dump of 163 MB that was already on disk.

A second 226 MB file (`reports/vibe-graph-<ts>.json`) is the per-run **evidence
artifact** (intentional, separate from the session) — disclosed, not the target.

## The fix (structural, backward-compatible)

The graph is the big, **stable, per-artifact** payload — it depends only on the
artifact bytes (sha256), not on which command last ran. So it belongs in one
stable file, referenced by the session:

- **`SessionStore.graph_path(sha256)`** → `sessions/graph-<sha16>.json`
  (stable per artifact; replaced on `/apk` re-runs, never a timestamped dup).
- **`SessionStore.upsert()`** — when the engine returns a `structural.graph`,
  it is written to the stable graph file and the session stores a small
  **reference** `structural.graph = {"$ref": <path>, "$sha256": <fingerprint>}`
  instead of the 163 MB inline copy.
- **`SessionStore.load_graph(session)`** — the single accessor every consumer
  uses. Resolves `$ref` → file **with a SHA-256 integrity check** (a tampered
  or missing graph file is rejected, never silently trusted), and **falls back
  to the inline copy** for pre-v0.27 sessions. Returns `None` honestly when a
  session has no graph layer.
- **`SessionStore.save()`** — compact JSON (no `indent=2`) + atomic write
  (tmp + rename), so the (now small) session is cheap to rewrite.
- **Consumers rewired** to `load_graph()`: gateway `_map` / `_xref_common`
  (`/xref`,`/callees`,`/callers`) / `_falsify` (live-fallback), and
  `core.record_deepdive` → `core.deepdive(resolved_graph=…)` (the dive itself
  stays a pure function over a session dict; the store resolves the ref and
  injects it).

## Back-compat (real, not assumed)

The existing 274 MB session is **inline** (pre-v0.27). `load_graph()` must
still resolve it. Probed against the real artifact (scratch, not in repo):
- inline 274 MB session loads, `load_graph()` returns the full graph
  (129,118 method nodes) — the old sessions keep working unchanged.

## Production proof (real F-Droid APK, new code)

`/apk F-Droid.apk` through the new `upsert()`:

- ingest: 178.4 s
- stored session: **11.19 MB** (was 274 MB — 24× smaller) — graph split out
- graph file: **163.53 MB** (stable `sessions/graph-83d3fe52….json`)
- session body carries a `$ref` (no `nodes` inline)
- `load_graph()` resolves the `$ref` → 129,118 method nodes (1.47 s)
- `/deepdive org.fdroid.MainActivity.onCreate --sha …` on the new `$ref`
  session: **28 matches, target found** (no rescan)

## Tests (+8 unit checks)

`tools/vibebot_test.py` P3a v0.27 block, all on the real graph fixture through
the production `SessionStore`:
- upsert stores a `$ref` in the session (not the inline graph)
- the `$ref` is a **portable file name** (`graph-<sha16>.json`), not an
  absolute path — the session dir can move without breaking the ref
- the stable `graph-<sha16>.json` exists on disk
- `load_graph()` resolves the `$ref` byte-identical to the job's own graph
- a **tampered** graph file is **REJECTED** (integrity check), restored file
  resolves again
- a pre-v0.27 **inline** graph still resolves (back-compat)
- a session with no graph layer → `None` (honest, no crash)

Also rewired 2 existing consumers in the suite (`session merge: graph layer
intact after /dex`, the P7 xref block) to go through `load_graph()`.

Full-host / CI-shape: 514 / 504 ALL PASS (zero real FAILs). redteam 32/32. apkmod ALL PASS.

## Honest limits / not changed
- The **226 MB `reports/vibe-graph-<ts>.json`** is still written per run as the
  evidence artifact (by design). It is a separate file, not the session; if
  Fatah wants the report deduped against `graph-<sha16>.json` that is a
  follow-up (report already has a stable per-artifact home now).
- Back-compat is read-only: old inline sessions are never migrated in place
  (read path handles both shapes).
- `__version__` → 0.27.0.
