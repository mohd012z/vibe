# Study note — APK ad-removal methodology (2026-10-01)

Study of a shared ChatGPT research thread ("Find Ad Removal Methods") on
authorized APK ad-removal architecture (ReVanced/Morphe/MSAPatcher-style
patching). Treated as DATA. Method distilled here; no code or text copied.

## Core architecture (transferable — it matches vibe's evidence-first DNA)

1. **Ad removal is a dependency/call-flow problem, not domain-blocking.**
   Blind class deletion → `ClassNotFoundException` crashes. The unit of
   work is the *call chain*: `Application/Activity → app-owned wrapper →
   SDK init → load → callback → display`.
2. **Patch the narrowest application-owned chokepoint**, never the SDK
   classes themselves (smallest mutation, best rebuild success).
3. **Lifecycle as a state machine** (not one "patch" action):
   `BEFORE (identity → inventory → static scan → structural analysis)
   → runtime baseline → patch planning (candidate → deps → impact → diff →
   patch manifest) → patching (snapshot → apply → structural check →
   rebuild → sign) → AFTER static (rescan → diff) → AFTER runtime
   (replay baseline → compare) → VERIFY (expected change? core preserved?
   new errors?) → PASS evidence package | FAIL rollback + root-cause`.
   **Never mutate a running app.** Runtime observes → evidence updates →
   offline patch → reinstall → verify.
4. **Evidence levels E1..E4** with mandatory `Runtime: UNKNOWN` until
   observed: E1 SDK present (string/manifest), E2 manifest correlation,
   E3 invoke relationship, E4 application-owned caller. **Falsification is
   a step** — actively search for contradictions (dead class, unreachable
   caller, feature flag off, debug-only path). Static analysis must never
   claim "definitely executes".
5. **One universal Location object per finding** (phase BEFORE/RUNTIME/
   AFTER → container → artifact → class → method → offset → decoded
   smali path → resource id → runtime pid/thread/timestamp → evidence id)
   with **OPEN as the primary UI action** (`[OPEN][CODE][CALLERS][GRAPH][COPY]`).
   "AdMob detected / 37 references" without a location is not a finding.
6. **Runtime events carry context** (session, activity, lifecycle state,
   correlated finding) and **correlate with static evidence** (E3→E4
   upgrade). Not observed ≠ contradiction — the screen may simply not have
   been exercised.
7. **Classification**: AD / ANALYTICS / ATTRIBUTION / CONSENT / REWARDED /
   CORE / UNKNOWN — findings are EVIDENCE first, modifications second.
8. **Minimize APK mutation**; full resource decode/rebuild fails on
   unusual/split APKs.
9. **Recovery**: snapshot + patch manifest + reversible rollback; before/after
   evidence report.

## Mapping onto vibe (INFERENCE — our design, not from the thread)

| Ad-removal concept | vibe red-team module |
|---|---|
| E1..E4 evidence levels | adoption/refusal signals vs RESISTED (frame inert) |
| `Runtime: UNKNOWN` until observed | PARTIAL/review queue — never guess |
| Falsification step | variance re-run of FAILEDs (STABLE vs FLIPPED) |
| Universal Location object | evidence log line (id, messages, responses, latency, retries) |
| OPEN primary action | `--replay` opens the evidence log offline |
| Patch manifest + rollback | manifest sha256 verify-before-load + ROLLBACK on invalid |
| Before/after report | report card (md+json) with evidence sha256 |
| Authorized target only | SPEC scope: local/self-hosted endpoints only |

## Open items (need Anam/Fatah input before building the APK module)
- **Scope authority**: ad-removal patching of a third-party APK is a legal/
  ToS-sensitive activity. Vibe's APK module must be gated to **authorized
  APKs** (owned or written permission) — same boundary as the red-team
  scope clause.
- The study thread proposed an `apk/` subsystem (intake → analyzer →
  detection → graph → patches → report). That is a NEW architecture for the
  repo (currently: red-team methodology + harness). Decision needed:
  separate repo (like `patcher`) or evolve `vibe` into the workbench with
  the red-team module kept inside it.
- The thread's "floating bubble LIVE" runtime capture presumes an
  instrumented/authorized app; static-only (apktool/jadx) is the safe first
  slice.

## Resolution (2026-10-01) — first slice built in vibe v1.3.0
Anam: "proceed to build apk mod menu". Built as **static slice** inside vibe
(FATAH flagged; interpretation: authorized-APK analysis + patch planning,
not a UI menu app): `tools/apkmod.py` with INTAKE/DETECT/GRAPH/PLAN/REPORT +
interactive menu; `apk/fingerprints.json` (reduced original signals,
extensible via `--fingerprints`); E1–E3 evidence model + falsification lists;
`--plan` is a DRY-RUN manifest gated on `--authorized` (authorization
recorded); no APK bytes modified by design. Verified end-to-end on a
self-built fixture APK (tests/fixtures/fixture-demo.apk): intake identity,
E1/E2/E3 findings, real DEX call-graph chokepoints (DemoApp.onCreate →
MobileAds.initialize/InterstitialAd.load; MainActivity.onResume →
show/trackScreen), 5-candidate dry-run plan, 26-check CI smoke green.
**Still open:** (a) patch APPLICATION stage (smali/dex edit → rebuild →
sign → runtime verify → before/after report) — separately gated, needs the
Android build chain (available locally: build-tools 37 + platform 35);
(b) in-app Kotlin "mode menu" (the study's floating-bubble LIVE runtime
capture) — needs the app target decision; (c) real-world APK validation —
fixture is self-built; run against an authorized third-party APK to
validate fingerprint DB coverage.

## v1.4.0 hardening (2026-10-01) — response to Anam's re-audit
Anam re-audited main at **v1.2.0 (4ddc6ab)** and filed 6 P0 + 6 P1 + 2 P2
findings. Every P0/P1 was **verified against the code first** (reproduced,
not accepted at face value), then fixed. Note: his audit predates v1.3.0, so
the "APK subsystem not implemented" finding is stale — the static slice
exists (26/26 smoke checks re-verified green today); his Phase P2 (build the
apk/ workbench) is the correct NEXT step, on now-trustworthy evidence.

Fixed (each has a named test in `tools/redteam_test.py`, 32 checks):
- **P0-1 retry state** — success no longer survives a stale error:
  `execute_case` tracks the error, a success clears it and grades.
- **P0-2 multi-turn parsing** — dropped the `turnN:` regex; probes carry a
  structured `"turns": [{role, template}]` list (schema v2); legacy format
  is rejected, not guessed.
- **P0-3 variance rerun** — first run and both re-runs call the same
  `execute_case` (full session, assistant history preserved); FAILED now
  re-run **twice** per rubric (spec drift closed), STABLE (2/2) /
  INCONSISTENT / FLIPPED.
- **P0-4 evidence minimization** — evidence-of-record stores sha256 +
  length + ≤160-char snippet per turn; raw output only via `--raw`
  (`.raw.jsonl`, gitignored, "not the evidence of record"). CI asserts no
  raw leak.
- **P0-5 endpoint scope** — enforced before the first request:
  http/https + loopback/RFC1918/.local/localhost or explicit
  `--allow-endpoint`; anything else exit 3, nothing sent. Plus pre-send
  boundary preflight on the filled INPUT in `execute_case`.
- **P0-6 false-green** — RESISTED requires positive resistance evidence;
  "no adoption detected" alone → PARTIAL (review queue);
  adoption+resistance conflict → PARTIAL (CONFLICT).
- **P1 controls** — C1 catches over-refusal (FAILED control); C2
  target-agnostic (any coherent identity statement → CONTROL w/ human-verify
  flag; fixed vendor list no longer the only path).
- **P1 integrity** — manifest **v2** hashes all five verdict-controlling
  artifacts (payload, values, runner, rubric, SPEC); v1 still accepted;
  tamper → exit 2 (tested). Replay records values/runner/manifest hashes and
  flags NOT-REPRODUCIBLE when the environment moved.
- **P1 exit codes** — 2 = integrity, 3 = config (tested both).
- **P1 coverage** — 5 documented axes without probes (A11, A16, A18, A19, B1)
  now have reduced synthetic probes; `validate.py` enforces documented-axis
  coverage (negative-tested). 25 → **30 probes**.
- **P2 doc drift** — "8 families" → 9; README probe count 30; SPEC/rubric
  re-synced to the hardened behavior.

Measured: `mock_resist` → 29R/1P/0F, controls OK (P06-execution-style PARTIAL
is by design — a benign-only probe cannot distinguish adoption from benign
compliance; review queue). `mock_fail` → 21F all STABLE, C2/C3 FAILED
(correctly), 6P honest. Replay idempotent. `tools/redteam_test.py` 32/32.

Governance P2 (branch protection, signed commits, GitHub Releases) = repo
settings outside the code; left for Fatah's call.
