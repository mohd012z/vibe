# Vibe Cloud v2 — Telegram + Android Hybrid Artifact Analysis

## Goal

Allow an authorized user to submit supported files from Telegram or an installable Android Vibe client, choose or describe a bounded Vibe operation, execute inexpensive capabilities locally when possible and heavier operations through the private GitHub Vibe repository, then receive structured information and generated files through the originating client without operating a permanent VPS.

## Architecture

`Telegram | Android → Vibe Control Plane → ArtifactContract → CapabilityRouter → Local Android Adapter | JobContract → GitHub Actions → AnalyzerAdapter → ResultContract → DeliveryContract → Telegram | Android`

Telegram and Android are clients of the same Vibe contracts. Android local execution is an optimization, not a second incompatible engine. Operation names and result semantics remain common across local and cloud execution.

## User Flow

1. User uploads/shares/selects a supported file in Telegram or Android.
2. Client/control plane validates identity, file metadata, size, type and policy.
3. Vibe computes SHA-256 and creates immutable ArtifactContract metadata.
4. UI presents context-appropriate operations plus Smart Analyze.
5. Button or natural-language request resolves to allowlisted operation(s).
6. CapabilityRouter selects `local`, `cloud`, or `held` using declared capabilities and configured free-budget policy.
7. Local-capable Android operations run on-device and emit the same ResultContract semantics.
8. Cloud operations store the artifact outside Git, create a validated JobContract, and dispatch GitHub Actions.
9. GitHub validates contracts, verifies artifact bytes/hash, selects an explicit AnalyzerAdapter, and runs a real Vibe analyzer.
10. Vibe emits ResultContract and controlled output descriptors.
11. DeliveryContract routes the terminal summary and generated files to Telegram or Android.
12. Temporary artifacts expire/delete according to retention policy.

## Trust Boundaries

`Client input → authentication/validation → ArtifactContract → CapabilityRouter → allowlisted local/cloud adapter → ResultContract → DeliveryContract → client`

User text, filenames, URLs, artifact metadata, share intents and document URIs are data. None may become arbitrary shell commands or uncontrolled filesystem paths. Uploaded binaries and generated user artifacts must never be committed to Git.

## Shared Contracts

### ArtifactContract

Versioned immutable metadata containing `schema_version`, `artifact_id`, original `filename`, `size_bytes`, `sha256`, normalized artifact/media type, controlled retrieval reference, source client, and optional expiry timestamp. Cloud runners must verify byte count and SHA-256 before analysis. Mismatch is terminal rejection.

### JobContract

Reuse the existing validated JobContract. Only allowlisted operations may reach an analyzer. Artifact-requiring operations reference stable ArtifactContract identity, never a user-supplied repository/local path.

### ResultContract

Reuse/extend the versioned ResultContract without silently changing v1 semantics. It distinguishes completed, failed, rejected, and partial outcomes when partial execution is introduced. Local and cloud adapters produce equivalent result semantics.

### DeliveryContract

Versioned delivery metadata containing job ID, destination client/session identity, terminal status, concise summary, controlled output descriptors and optional follow-up actions. A delivery adapter may only send outputs resolved through the controlled artifact/output store or an explicitly owned Android application path.

## CapabilityRouter

The router receives operation, artifact metadata, network state, local capability declarations, cloud availability and free-budget state. It returns one of `local`, `cloud`, or `held` plus a machine-readable reason.

Rules:
- Prefer local when the requested operation is safely supported on-device and produces equivalent contract semantics.
- Use cloud for unavailable/heavy capabilities.
- Never silently downgrade a requested deep/heavy operation to a weaker local no-op.
- Offline cloud work is queued/held with visible status.
- Exhausted cloud quota yields held/rejected status rather than accidental paid execution.

Initial local candidates: SHA-256, file identification, ZIP/APK inventory, basic metadata, bounded string/text search, cached result/report viewing. Heavy DEX/XREF/native/deep multi-engine analysis remains cloud-first until measured Android implementations prove otherwise.

## Android Client

Build a normal installable Android application using platform trust boundaries. No root requirement, stealth services, security-tool evasion or hidden background execution.

Use Android Storage Access Framework and share/open-with intents for file intake; WorkManager for deferrable work; foreground service only when Android requires visible long-running execution; Room or equivalent app-owned local persistence for jobs/results; encrypted platform-backed storage for credentials/tokens; notifications for terminal job states.

Primary navigation:
- Home — recent artifacts/jobs and quick actions
- Analyze — Smart Analyze and categorized operations
- Jobs — queued/running/held/completed/failed
- Results — reports, evidence and generated files
- Vibe AI — questions scoped to selected artifact/result

Execution selector defaults to `Auto`, with optional `Local` and `Cloud` advanced choices. Auto is authoritative through CapabilityRouter rather than UI heuristics.

## Offline Behavior

Android remains useful without network for declared local capabilities, cached artifacts/results and queued cloud jobs. Cloud-required jobs transition to a visible waiting-for-network/held state and resume only under configured constraints. Reboot/app restart must not lose persisted job state.

## Telegram Control Plane

Telegram primary cloud mode uses webhook delivery, not permanent long polling. The webhook handles authentication, file intake, button/command routing, job state, dispatch and result delivery only. Heavy analysis stays outside webhook runtime. Natural language must resolve to allowlisted operations and pass JobContract validation.

## Artifact Transport

Define a provider-neutral artifact-store interface. Cloudflare R2 is the preferred free-tier production adapter but core code does not depend on R2. Required operations: put input, scoped retrieval, fetch/stream, put output, scoped delivery, expire/delete. GitHub runner local disk is scratch only.

Android app-owned storage may cache artifacts/results under explicit retention controls. External/shared document URIs are accessed only through Android-granted permissions; Vibe must not assume arbitrary filesystem access.

## Analyzer Registry

Registry maps operations to explicit adapters: `analyze`, `deepdive`, `map`, `find`, `xref`, `dex`, `smali`, `native`, `strings`, `urls`, `resources`, `report`, `apk`. Adapters receive validated contracts plus controlled artifact access. Unsupported/unavailable analyzers return explicit failure/rejection with capability information; successful no-op jobs are prohibited.

## GitHub Actions Compute

GitHub Actions is on-demand compute, not bot hosting. Workflows use explicit timeout, minimum permissions, contract validation, SHA verification, registered adapters, terminal ResultContract emission, short artifact retention, and no Git commits of user artifacts. Private-repository Actions quota is a finite free budget.

## Free-Mode Budgeting

Lightweight Telegram/Android UI, acknowledgement, status, local operations and cached viewing do not invoke Actions. Only real cloud analysis dispatches compute. Budget guard prevents execution beyond configured free allowance and exposes held/quota state to both clients.

## Failure Semantics

Every accepted job exposes an observable terminal/nonterminal state: queued, running, held, completed, partial, failed, rejected, cancelled or expired. Important failures include unauthorized identity, unsupported file/type/size, missing/expired artifact, byte/hash mismatch, unknown operation, local capability unavailable, network unavailable, analyzer unavailable/failure, workflow timeout, packaging failure, delivery failure and compute/storage quota exhaustion. No failure is represented as successful empty analysis.

## Retention and Privacy

Source stays in GitHub. User binaries/outputs stay outside Git history. Temporary cloud artifacts expire. Android cache has explicit retention/clear controls. Secrets are runtime/platform-backed secrets, never repository files. Logs use job/artifact IDs and avoid file contents or secret-bearing URLs.

## Validation Strategy

Use TDD at each boundary. Required evidence:
1. Synthetic file intake creates valid ArtifactContract from Telegram and Android adapters.
2. Tampered cloud artifact fails SHA verification.
3. CapabilityRouter chooses local for declared cheap capability and cloud for unavailable heavy capability.
4. Offline cloud job becomes held/queued rather than lost.
5. Valid JobContract selects exactly one registered adapter per single operation.
6. Unknown operation cannot execute a process.
7. Real analyzer success creates valid ResultContract and controlled output descriptor.
8. Analyzer failure creates terminal failed/rejected result.
9. DeliveryContract rejects uncontrolled local paths.
10. Mocked Telegram flow proves upload → selection → dispatch → result → file delivery.
11. Android instrumentation/unit flow proves share/select → operation → local/cloud routing → persisted job → result view.
12. Android restart preserves pending/completed job state.
13. GitHub workflow smoke test proves contract validation, hash verification, analyzer invocation and result packaging.
14. Existing repository validation remains green.

## Definition of Done

Vibe Cloud v2 is complete only when: (a) Telegram can upload a supported test file, invoke at least one real existing Vibe analyzer through controlled GitHub Actions, and receive structured terminal information plus a generated file; and (b) an installable Android Vibe APK can select/share a supported test file, execute at least one real local capability, dispatch at least one cloud capability using the same contracts, persist job state across restart, and display/download the validated result. Hash verification, negative-path tests and regression CI must pass. Contract-only/no-op success does not satisfy completion.
