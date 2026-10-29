# Study note — morluto/rea (REA "Reverse Engineer Anything") (2026-10-28)

Anam's input: "study and learn deeper and find useful method that can
implement into vibe ai" → https://github.com/morluto/rea.
Treated as DATA. Cloned 2026-10-28 (v6.8.0, MIT), built from source
(Node 24.22.1 user-space) and run on our own samples.

## What it is (one line)

A local Node.js (22.23+/24.22+/26.12+) CLI + MCP server that wraps many RE
engines (Hopper/Ghidra/IDA/JEB providers for native; JADX for Android;
Binwalk/Unblob for firmware; tshark for packets; pwntools for ELF; ADB)
behind one **Evidence contract**: every result = `evidence_id` + `subject`
(artifact digest + format) + `provider` + `normalized_result` +
`confidence` ("observed" | …) + `authority` ("shipped-artifact" | …) +
`limitations[]` (always honest: what the check does NOT establish).
MIT; heavy but clean architecture (domain → providers → application →
cli/mcp adapters; fail-closed integration rule).

## What was actually readable / run (access level)

- Full repo cloned + built (`npm install` + `npm run build:cached`, 269 s on
  Node 24.22.1 in scratch). CLI entry = `scripts/rea.mjs` (bin `rea`).
- Three command families executed on REAL team samples (below). Everything
  else (Hopper/Ghidra/IDA/JEB/firmware/pcap/ADB) = source + docs read, NOT
  executed (no engine on host).

## Verified mechanisms (the useful parts)

### 1. `identify_flutter_build` / `inspect_dart_aot` — pure static Flutter ID
No engine, no tool install: parses the APK zip + ELF + Dart AOT snapshot
headers directly.
- `flutter_detected` = any `lib/<abi>/libapp.so` (negatives report complete
  coverage — "absence is an answer").
- **Snapshot hash = 20 bytes after the `f5 f5 dc dc` magic** in the AOT
  payload (byte-scanned for identification; read from the exported
  `_kDart*Snapshot*` dynamic symbols for AOT inspection). Disagreeing
  sources → `snapshot_hash: null` + candidates, coverage partial (never
  silently pick one).
- Per-ABI libflutter facts: size, SHA-256, **GNU build-id from ELF
  PT_NOTE/SHT_NOTE** (bounded: 64 IDs, 1024 note ranges), labeled version
  strings (grammar-validated; stripped release strings → `null`, not
  guessed), toolchain line verbatim.
- **String-pool projection** from the isolate data section: `package:` URIs
  (dependency inventory), `dart:` URIs, `class_like_tokens` — bounded with
  `coverage: "partial"` when truncated. Deliberately NOT deserialized
  clusters (layout is per-SDK-version — which is exactly why the snapshot
  hash is the key to a real parser like blutter).
- **Evidence: same sample, two independent tools agree** (Trudido 2026,
  Dart 3.9.2): REA `snapshot_hash 97ff04a728735e6b6b098bdf983faaba`
  == blutter `extract_dart_info.py` hash; REA per-ABI libapp sha
  `96df46ce…` matches our extracted file; REA engine build-id
  `506c3de6db0ff95417a19593f8bc95a6eb58610b`; REA package-URI sample
  (`package:audioplayers/…`, `package:archive/…`) matches blutter's `asm/`
  decompile dirs (85 packages).
- **Portable subset (implementable in VibeBot, stdlib):** magic+hash byte
  scan, ELF note build-id extraction, labeled-string grammar check, zip
  libapp/libflutter inventory, bounded string-pool projection. That is our
  `/flutter` L0 detection layer — no Node, no blutter, no C++ build.
  REA's full AOT header walk (PT_LOAD overlap resolution, kind-3 FullAOT
  layout, dynamic-symbol export walk) is the reference for the L1 layer.

### 2. `inspect_apk_signature` — static v1/v2/v3/v3.1 decoder, ZERO deps
Pure JS zip + ASN.1 + signature-block reader. Verified on our own
**MT-2.26.10-LaylaClone-VIP.apk** (the 2026-10-11 delivery):
- v1 absent; **v2 present, 1 signer**: certificate subject
  `C=MY/L=MY/O=Layla/OU=CSM/CN=Layla VIP Module`, serial 8DBCDD4C33B1D2D5,
  notBefore 2026-10-11, notAfter 2054-02-26, RSA; digest sha256
  `51a3b578…d44` with **`matches_apk: true`** — REA recomputes the content
  digest and compares (that's the self-consistency check we currently only
  get from `apksigner verify`).
- Mechanics worth copying (source of record: `src/domain/apkSignature/
  apkSigningBlock.ts` + `src/apkSignature/ApkSignatureProvider.ts`):
  the signing block's magic is the ASCII string **"APK Sig Block 42"**
  (NOT a hex constant), located by walking the ZIP tail (EOCD →
  optional ZIP64 locator 0x07064b50 / EOCD64 0x06064b50 with the
  0xffffffff sentinel); per-scheme block IDs: **v2 = 0x7109871a,
  v3 = 0xf05368c0, v3.1 = 0x1b93ad61, sourceStampV1 = 0x2b09189e,
  sourceStampV2 = 0x6dff800d**. Digest recomputation per algorithm
  (lazily, once per algo; fs-verity Merkle digests NOT recomputed →
  honest "not computable"), certificate facts as decoded X.509 (not hex
  dump), v1 JAR signer posture fingerprint, per-signer
  `uninterpreted_bytes` counter (anything it can't interpret is counted,
  never dropped).
- **VibeBot slot:** a stdlib `/sigs` command (or folded into `/apk`
  overview) — today our cert info comes from androguard + external
  apksigner; REA's approach makes signature SELF-CONSISTENCY (digest
  recomputation) a first-class evidence row without apksigner on the
  machine. This is also the verifier for every patched APK we ship
  (pair with the 2026-10-23 r2-patch→repack→sign pipeline).

### 3. JADX headless wrapping (our decompile-chain item #7)
`src/android/` drives a commit-pinned headless JADX **submodule**
(`third_party/`, unmodified) through a session + operation-timeout +
doctor + failure-class taxonomy (`JadxFailure.ts` classifies: java probe,
workspace root, interruption, operation timeout) and an MCP transport
variant. Manifest component projection is meticulous: declared vs resolved
names, `permission_source` (local/inherited/none/omitted-because-token),
`exported_default` only where the documented default is provable (API 31+
filters omitting it → limitation, not a guess), DEX-character-legal
segment checks.
- **VibeBot slot:** the `/decompile` chain (APK↔DEX↔smali↔Java) should
  treat JADX exactly like our native providers: subprocess-isolated,
  wall-capped, doctor-probed, honest-degrade — and the manifest
  component-inventory projection is a ready design for our `/apk`
  overview (we currently list components without the exported-default /
  permission-source nuance).

### 4. Evidence contract shape (the meta-lesson)
`confidence`/`authority`/`coverage`/`limitations[]`/`evidence_id` on EVERY
result + `inspect_analysis_view` paging for retained big results (offsets
count code units; exhausting pages never upgrades partial→complete;
`*_at_least` counts stay lower bounds). This is the same DNA as our
claims/E-levels/NOT-OBSERVED vocabulary — REA is the strongest
external confirmation of the design. The one thing we can still adopt
verbatim: **`uninterpreted_bytes` counters** — when a parser meets bytes
it can't explain, count + carry them, don't drop or guess (our DEX/ELF
walkers already do this in places; make it universal).

### 5. Boundaries as first-class data
REA budgets everything and reports `resource_constraint` when exceeded:
APK snapshot ≤2 GiB, library extraction ≤768 MiB cumulative, per-library
read ≤256 MiB, ZIP metadata ≤8 MiB, 32 ABIs max, 1024 note ranges, 64
build-id candidates, 500 retained strings per pool facet. A refusal is a
RESULT (typed), not an exception. Our `MAX_UPLOAD_BYTES`/job budgets do
this per-job; REA shows the same discipline at the READER level (before
any engine starts) — adopt for the URL-ingest + /flutter extraction paths.

## What is NOT useful to copy (honest gaps)

- MCP/agent setup machinery, Hopper/IDA/JEB bridges, firmware/pcap/BEAM/
  Go/Rust/PE/EVM families — wrong domain for VibeBot's Telegram-bot shape.
- Node runtime itself: a Node dependency in our stdlib-first bot is a
  license/runtime tax; the mechanisms above are all portable to Python.
- REA does NOT patch (read-only analysis); our patch side (r2 oo+ →
  repack → apksigner, proven 2026-10-23) stays as-is.

## VibeBot backlog mapping (concrete)

1. `/flutter` (tiered): L0 = REA-style static ID in pure stdlib (magic
   scan + hash + build-id + lib inventory + bounded pool projection) —
   ~stdlib-only, CI-runnable. L1 = blutter decompile + pp.txt keyword
   search (engine present? build per Dart version). L2 = PPTool offset→
   functions (already in the bot venv). L3 = r2 patch + repack + sign.
   Honest-degrade per tier. (Feeds items: VIP-premium #6, so-patch #9.)
2. `/sigs` (stdlib, REA mechanics): v1/v2/v3(+v3.1) presence, cert facts,
   digest RECOMPUTATION (`matches_apk`), uninterpreted-byte counters.
   Doubles as the verifier for our own patched-APK deliveries.
3. Manifest component projection upgrade in `/apk` overview:
   `permission_source`, `exported_default` (only where provable),
   declared-vs-resolved names — port REA's projection rules.
4. Reader-level budgets + typed refusals on the URL-ingest path
   (extend v0.33 `download_url` bounds to declared-extraction budgets).
5. Universal `uninterpreted_bytes` convention for our format walkers.

## Provenance

- Repo: github.com/morluto/rea @ v6.8.0 (main, 2026-10-28), MIT;
  THIRD_PARTY_NOTICES.md lists engine licenses (JADX = its own; Hopper/IDA/
  JEB are caller-supplied and REA grants no license for them).
- Samples: F-Droid com.trudido.app 1.3.5 (32,332,511 B, sha256
  `80a173a967…`), MT-2.26.10-LaylaClone-VIP.apk (40,219,653 B, sha256
  `4e374917…` — matches the 2026-10-11 Pages delivery byte-for-byte).
- Run environment: Node 24.22.1 user-space (scratch), built from source;
  REA performed no hash→SDK lookup and no network analysis (local-only,
  as documented).
- No verbatim REA code copied into vibe (MIT allows it; mechanism writeups
  kept, per the standing rule for studied sources).
