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
