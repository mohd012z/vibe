# Vibe Cloud v2 — Artifact Analysis and Telegram Delivery

## Goal

Allow an authorized user to upload a supported file in Telegram, choose or describe a bounded Vibe analysis operation, execute that operation through the private GitHub Vibe repository, and receive useful information and generated output files back in Telegram without operating a permanent VPS.

## User Flow

1. User uploads a file to the Telegram bot.
2. Control plane authenticates the Telegram identity and validates file metadata.
3. The bot acknowledges the upload and presents context-appropriate Vibe operations.
4. A button or natural-language request is converted into an allowlisted operation.
5. Control plane creates an immutable ArtifactContract and validated JobContract.
6. The artifact is stored outside Git and made available to the analysis runner through a temporary scoped reference.
7. GitHub Actions validates the contracts and invokes the matching AnalyzerAdapter.
8. Vibe produces a ResultContract plus zero or more output artifacts.
9. The control plane validates the result and creates a DeliveryContract.
10. Telegram receives a terminal status message and any deliverable files.

## Trust Boundaries

`Telegram input → authentication/validation → ArtifactContract → JobContract → allowlisted AnalyzerAdapter → ResultContract → DeliveryContract → Telegram`

User text, filenames, URLs, and artifact metadata are data. None may be interpolated into arbitrary shell commands. GitHub workflow permissions remain least-privilege. Uploaded binaries must never be committed to the Vibe repository.

## Contracts

### ArtifactContract

Versioned immutable metadata containing:

- `schema_version`
- `artifact_id`
- original `filename`
- `size_bytes`
- `sha256`
- normalized artifact/media type
- temporary scoped retrieval reference
- optional expiry timestamp

The runner must verify the downloaded byte count and SHA-256 before analysis. A mismatch is a terminal rejection, not a warning.

### JobContract

Reuse the existing validated cloud JobContract. Only its allowlisted operations may reach an analyzer. Operations that require an artifact must reference an ArtifactContract by stable artifact identity rather than a repository path supplied by the user.

### ResultContract

Reuse and extend the existing versioned ResultContract without silently changing v1 semantics. It must distinguish completed, failed, rejected, and partial outcomes when partial execution is introduced. Output descriptors must identify generated files without trusting arbitrary runner paths.

### DeliveryContract

Versioned delivery metadata containing:

- `job_id`
- destination Telegram chat identity
- terminal status
- concise user-facing summary
- output descriptors eligible for delivery
- optional follow-up actions

The delivery layer must not send files merely because a runner named them. Every output must resolve through the controlled artifact/output store.

## Artifact Transport

Define a provider-neutral artifact-store interface before implementing a provider adapter. Cloudflare R2 is the preferred free-tier production adapter, but core Vibe code must not depend directly on R2 APIs.

Required operations:

- put input artifact
- obtain scoped/expiring retrieval reference
- fetch/stream artifact
- put generated output
- obtain scoped delivery reference
- expire/delete artifact

Temporary local filesystem storage may be used inside a GitHub runner as scratch space only. It is not durable state.

## Analyzer Adapter

Add a registry mapping JobContract operations to explicit Vibe analyzer adapters. Initial operations are the existing allowlist: `analyze`, `deepdive`, `map`, `find`, `xref`, `dex`, `smali`, `native`, `strings`, `urls`, `resources`, `report`, and `apk`.

Each adapter receives validated contracts and a controlled local artifact path and returns structured result/output metadata. It must not receive raw Telegram updates or GitHub API credentials.

Unsupported/unavailable analyzers return an explicit rejected/failed result with capability information; they must never be reported as successful no-op jobs.

## Telegram Control Plane

Telegram uses webhook delivery rather than permanent long polling for the primary cloud mode. The webhook layer is responsible only for authentication, file intake, command/button routing, job state, dispatch, and result delivery. Heavy analysis remains outside the webhook runtime.

Natural-language requests may map to one or more allowlisted Vibe operations, but the mapping output must pass the same JobContract validation as button commands. Unknown intent must ask for clarification or present valid operations; it must never fall through to shell execution.

## GitHub Actions Compute

GitHub Actions is on-demand compute, not the always-running bot host. Workflows must:

- use explicit timeouts;
- use minimum repository permissions;
- validate all contracts before retrieval/execution;
- verify artifact SHA-256 before analysis;
- invoke only registered adapters;
- always attempt to emit a terminal ResultContract;
- keep diagnostic/result artifacts on short retention;
- avoid committing user uploads or analysis outputs to Git.

The design must remain usable after the repository becomes private. Private-repository Actions quota is treated as a finite free budget rather than unlimited compute.

## Free-Mode Budgeting

The control plane should avoid Actions for `/start`, `/help`, button rendering, upload acknowledgement, status lookup, and other lightweight operations. Only analysis jobs dispatch compute.

A budget guard may hold/reject new analysis when the configured free allowance is exhausted or deliberately reserved. Quota exhaustion must produce a Telegram-visible terminal/held state rather than silent failure.

## Failure Semantics

Every accepted job must eventually expose one of these observable states: completed, partial, failed, rejected, cancelled/expired, or held for quota when implemented. Important failures include:

- unauthorized Telegram identity;
- unsupported file type or size;
- expired/missing artifact;
- size/hash mismatch;
- unknown operation;
- analyzer unavailable;
- analyzer non-zero failure;
- workflow timeout;
- output packaging failure;
- Telegram delivery failure;
- compute/storage quota exhaustion.

No failure may be represented as a successful empty analysis.

## Retention and Privacy

- Source code remains in GitHub.
- User binaries and generated analysis artifacts remain outside Git history.
- Temporary artifacts have explicit expiry/deletion behavior.
- Secrets are runtime secrets, never repository files.
- Logs should identify jobs by job/artifact IDs and avoid dumping file contents or secret-bearing URLs.

## Validation Strategy

Use TDD at each contract/adapter boundary. Required end-to-end evidence before calling V2 usable:

1. Synthetic test artifact upload creates a valid ArtifactContract.
2. Tampered artifact is rejected by SHA-256 verification.
3. Valid JobContract selects exactly one registered adapter for a single operation.
4. Unknown operation cannot execute a process.
5. Analyzer success produces a valid ResultContract and controlled output descriptor.
6. Analyzer failure produces a terminal failed/rejected result.
7. DeliveryContract cannot reference an uncontrolled local path.
8. A mocked Telegram flow proves upload → selection → dispatch → result → file delivery.
9. GitHub workflow smoke test proves contract validation and result packaging.
10. Existing repository validation remains green.

## Definition of Done

Vibe Cloud v2 is complete only when a Telegram user can upload a supported test file, invoke at least one real existing Vibe analyzer through the controlled GitHub Actions path, and receive both a structured terminal response and generated output file back through the Telegram delivery adapter, with hash verification, negative-path tests, and regression CI passing. Contract-only/no-op success does not satisfy completion.
