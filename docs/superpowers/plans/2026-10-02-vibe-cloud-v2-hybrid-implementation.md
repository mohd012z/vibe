# Vibe Cloud v2 Hybrid Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a no-VPS Vibe path where Telegram and an installable Android APK share contracts, cheap work can execute locally, real heavy analysis executes on-demand in GitHub Actions, and validated results/files return to the originating client.

**Architecture:** Preserve Vibe's existing `Gateway`/engine boundary, but put immutable artifact/job/result/delivery contracts around remote execution. A provider-neutral CapabilityRouter selects Android-local or GitHub-cloud execution. Telegram moves from primary long polling to webhook/control-plane semantics; existing polling remains a fallback until webhook acceptance passes.

**Tech Stack:** Python 3.12, pytest, existing VibeBot engines/Gateway, GitHub Actions, provider-neutral object-store interface (R2 adapter later), Kotlin Android app, Jetpack Compose, Room, WorkManager, Storage Access Framework.

**Spec:** `docs/superpowers/specs/2026-10-02-vibe-cloud-v2-artifact-delivery.md`

## Global Constraints

- No permanent VPS is required for the primary architecture.
- User binaries and generated user artifacts never enter Git history.
- Telegram/user text never becomes an arbitrary shell command.
- Cloud jobs execute only allowlisted operations.
- SHA-256 and byte count are verified before cloud analysis.
- Free-mode budget exhaustion must hold/reject jobs rather than cause paid execution.
- Android requires no root, stealth service, hidden execution, or security-tool evasion.
- Local and cloud paths use compatible ResultContract semantics.
- A no-op/contract-only result cannot be reported as successful analysis.

## Review Focus

1. **Cloud runner import drift:** current `tools/cloud/job_runner.py` and `.github/workflows/vibe-job.yml` import `tools.cloud.job_contract`, but that file does not exist; the real JobContract is `tools/vibebot/cloud_job.py`. Pin this with an import/smoke test before adding features.
2. **CI false green:** current `validate.yml` does not execute `tests/test_vibe_cloud_job_contract.py` or `tests/test_cloud_result_contract.py`; add them so cloud regressions cannot pass unseen.
3. **Telegram upload side effect:** current polling runtime immediately calls `/analyze` after any document upload; V2 must acknowledge/select first and analyze only after an explicit operation.
4. **Artifact tampering/expiry:** downloaded bytes must match ArtifactContract size/hash and expired retrieval references must fail closed.
5. **Android restart/offline:** queued/held/completed jobs and artifact metadata must survive process/reboot boundaries without silently duplicating cloud dispatch.

---

### Task 1: Repair the Cloud v1 Baseline and Make CI Honest

**Files:**
- Modify: `tools/cloud/job_runner.py`
- Modify: `.github/workflows/vibe-job.yml`
- Modify: `.github/workflows/validate.yml`
- Create: `tests/test_cloud_job_runner.py`
- Existing tests: `tests/test_vibe_cloud_job_contract.py`, `tests/test_cloud_result_contract.py`

**Interfaces:**
- Consumes: `tools.vibebot.cloud_job.JobContract`
- Produces: importable `run(job: JobContract, ...) -> ResultContract` baseline and CI coverage for all cloud contract tests.

- [ ] Write a failing test importing `tools.cloud.job_runner` and asserting it accepts the existing string-valued `JobContract.operation` without `.value`.
- [ ] Run `python -m pytest -q tests/test_cloud_job_runner.py tests/test_vibe_cloud_job_contract.py tests/test_cloud_result_contract.py`; verify RED from the missing `tools.cloud.job_contract` import/current operation mismatch.
- [ ] Change runner/workflow imports to `tools.vibebot.cloud_job.JobContract`; use `job.operation` as the canonical operation string.
- [ ] Add the three cloud tests to `validate.yml`.
- [ ] Run the focused tests and full existing validation suite; require GREEN.
- [ ] Commit `fix(cloud): align Actions runner with canonical job contract`.

### Task 2: ArtifactContract + Verified Artifact Store Boundary

**Files:**
- Create: `tools/cloud/artifact_contract.py`
- Create: `tools/cloud/artifact_store.py`
- Create: `tests/test_cloud_artifact_contract.py`
- Create: `tests/test_cloud_artifact_store.py`

**Interfaces:**
- Produces: `ArtifactContract.create(filename, size_bytes, sha256, media_type, retrieval_ref, source_client, expires_at=None)`; `ArtifactStore` protocol; `verify_artifact(path, contract) -> Path`.

- [ ] Write failing tests for round-trip schema, filename/path isolation, invalid SHA, wrong size, tampered bytes, and expired artifact.
- [ ] Verify RED.
- [ ] Implement immutable v1 ArtifactContract and store protocol with no provider-specific SDK.
- [ ] Implement streaming size/SHA verification before an artifact can reach an analyzer.
- [ ] Verify focused tests GREEN and regression suite GREEN.
- [ ] Commit `feat(cloud): add verified artifact contract boundary`.

### Task 3: Result/Delivery Contracts with Controlled Outputs

**Files:**
- Modify: `tools/cloud/result_contract.py`
- Create: `tools/cloud/delivery_contract.py`
- Modify: `tests/test_cloud_result_contract.py`
- Create: `tests/test_cloud_delivery_contract.py`

**Interfaces:**
- Produces: `OutputDescriptor(id, filename, sha256, size_bytes, media_type)`; ResultContract output descriptors; `DeliveryContract(job_id, destination, status, summary, outputs, followups)`.

- [ ] Write failing tests for controlled output descriptors, partial status, invalid failed result, and rejection of raw `/tmp/...`/runner paths as deliverable outputs.
- [ ] Verify RED.
- [ ] Extend ResultContract compatibly; preserve parsing of existing v1 string outputs only through an explicit compatibility path if needed.
- [ ] Implement DeliveryContract validation.
- [ ] Run contract tests and full suite GREEN.
- [ ] Commit `feat(cloud): add controlled result and delivery contracts`.

### Task 4: CapabilityRouter and Free-Mode Guard

**Files:**
- Create: `tools/cloud/capability_router.py`
- Create: `tests/test_cloud_capability_router.py`
- Reuse: `tools/vibe_capabilities.py`

**Interfaces:**
- Produces: `ExecutionMode = LOCAL|CLOUD|HELD`; `RouteDecision(mode, reason)`; `route(operation, local_caps, network_available, cloud_available, budget_available)`.

- [ ] Write failing tests: SHA/file inventory route LOCAL; `dex`/`native`/`deepdive` route CLOUD; offline heavy operation HELD; exhausted budget HELD; forced unsupported LOCAL rejected.
- [ ] Verify RED.
- [ ] Implement deterministic router without network calls or billing APIs.
- [ ] Run tests GREEN.
- [ ] Commit `feat(cloud): add free-mode capability router`.

### Task 5: Real Analyzer Registry and End the No-Op Runner

**Files:**
- Create: `tools/cloud/analyzer_registry.py`
- Modify: `tools/cloud/job_runner.py`
- Create: `tests/test_cloud_analyzer_registry.py`
- Modify: `tests/test_cloud_job_runner.py`
- Reuse: `tools/apk_pipeline.py`, `tools/vibebot/gateway.py`, `tools/vibebot/engines.py`

**Interfaces:**
- Produces: `AnalyzerAdapter.run(job, artifact_path, work_dir) -> AnalyzerOutcome`; registry `resolve(operation)`.
- Initial real acceptance adapter: `apk`/`analyze` over committed `tests/fixtures/fixture-demo.apk`, generating at least `inventory.json` or a report output.

- [ ] Write failing test proving `analyze` invokes a registered real adapter and produces a non-empty controlled output.
- [ ] Write failing tests proving unknown/unavailable operations return REJECTED/FAILED and cannot spawn arbitrary commands.
- [ ] Verify RED.
- [ ] Implement registry and first read-only APK analyzer adapter using existing Vibe pipeline/engine code.
- [ ] Replace current "validated job accepted" COMPLETED no-op with actual artifact verification + adapter execution.
- [ ] Run focused and full tests GREEN.
- [ ] Commit `feat(cloud): execute real Vibe analyzers from job contracts`.

### Task 6: GitHub Actions Artifact Execution Smoke Path

**Files:**
- Modify: `.github/workflows/vibe-job.yml`
- Create: `tests/test_vibe_job_workflow_contract.py`

**Interfaces:**
- Workflow inputs: validated `job_json` plus controlled artifact retrieval metadata/contract; outputs: `result.json` and controlled output bundle with 1-day retention.

- [ ] Write failing static workflow contract tests for canonical imports, least privilege, timeout, SHA verification step, runner invocation, terminal result upload, and no Git commit/push step.
- [ ] Verify RED.
- [ ] Update workflow to materialize both contracts, retrieve artifact through the adapter boundary, verify, run analyzer, and package result/output bundle.
- [ ] Run static tests GREEN.
- [ ] Dispatch a fixture-only workflow smoke job and inspect artifact/result; do not call it complete unless the result proves a real analyzer ran.
- [ ] Commit `feat(actions): run verified Vibe artifact jobs on demand`.

### Task 7: Telegram Webhook Control Plane + Explicit Selection

**Files:**
- Create: `tools/cloud/telegram_webhook.py`
- Create: `tools/cloud/telegram_delivery.py`
- Modify: `tools/vibebot/telegram_runtime.py` only to share pure intake/render helpers and preserve fallback polling.
- Modify: `tools/vibebot/telegram_ui.py`
- Create: `tests/test_cloud_telegram_webhook.py`
- Modify: `tests/test_vibe_telegram_runtime.py`

**Interfaces:**
- Produces: `handle_update(update) -> ControlPlaneActions`; delivery adapter `send_result(DeliveryContract)`.

- [ ] Write failing test proving upload creates/acknowledges artifact but does **not** automatically analyze.
- [ ] Write failing tests for unauthorized user, callback operation mapping, held/quota response, terminal result message, and generated-file delivery.
- [ ] Verify RED.
- [ ] Implement webhook handler as transport/control plane only; heavy work never executes inline.
- [ ] Change fallback polling upload behavior to selection-first for parity.
- [ ] Run Telegram/cloud tests GREEN.
- [ ] Commit `feat(telegram): add webhook artifact job control plane`.

### Task 8: Android App Foundation and Shared Contract Models

**Files:**
- Create: `android/settings.gradle.kts`, `android/build.gradle.kts`, `android/gradle.properties`
- Create: `android/app/build.gradle.kts`, `android/app/src/main/AndroidManifest.xml`
- Create: `android/app/src/main/java/.../contract/{ArtifactContract,JobContract,ResultContract}.kt`
- Create: `android/app/src/test/java/.../ContractCompatibilityTest.kt`
- Modify: `.gitignore`

**Interfaces:**
- Android contract JSON must round-trip against committed Python fixture JSON/schema examples.

- [ ] Add failing JVM tests for Python/Android contract compatibility and unknown schema rejection.
- [ ] Verify RED with Gradle test.
- [ ] Scaffold minimal installable app and Kotlin contract models; no secrets in source.
- [ ] Verify JVM tests and `assembleDebug` GREEN.
- [ ] Commit `feat(android): scaffold Vibe client with shared contracts`.

### Task 9: Android Local Analyzer + Capability Routing

**Files:**
- Create: `android/app/src/main/java/.../analysis/LocalArtifactAnalyzer.kt`
- Create: `android/app/src/main/java/.../analysis/CapabilityRouter.kt`
- Create tests under `android/app/src/test/.../analysis/`

**Interfaces:**
- Local analyzer produces ResultContract-compatible output for SHA-256, file type and ZIP/APK inventory.

- [ ] Write failing tests using a small APK/ZIP fixture for SHA and inventory.
- [ ] Write failing routing tests for Auto/Local/Cloud and offline heavy jobs.
- [ ] Verify RED.
- [ ] Implement bounded streaming hash and ZIP inventory; do not implement DEX/native heavy analysis locally yet.
- [ ] Verify GREEN.
- [ ] Commit `feat(android): add offline local artifact analysis`.

### Task 10: Android Persistence, File Intake and Five-Tab UI

**Files:**
- Create Room entities/DAO/database under `android/app/src/main/java/.../data/`
- Create WorkManager cloud dispatch worker under `.../work/`
- Create Compose screens/navigation under `.../ui/`
- Modify AndroidManifest for SAF/share intents only as required.
- Add unit/instrumentation tests.

**Interfaces:**
- Persists artifact metadata, jobs, route decisions and results; cloud dispatch is idempotent by job ID.

- [ ] Write failing persistence test: queued and completed jobs survive repository/database recreation.
- [ ] Write failing test: offline cloud job remains HELD/QUEUED and is not duplicated.
- [ ] Implement SAF/open-with intake and app-owned cached copy only when required.
- [ ] Implement Home, Analyze, Jobs, Results, Vibe AI navigation and Auto/Local/Cloud selector.
- [ ] Implement WorkManager constraints and terminal notifications.
- [ ] Run JVM/instrumentation tests and `assembleDebug` GREEN.
- [ ] Commit `feat(android): add persistent hybrid Vibe workflow UI`.

### Task 11: End-to-End Acceptance and Regression Gate

**Files:**
- Create: `tests/test_vibe_cloud_v2_e2e.py`
- Modify: `.github/workflows/validate.yml`
- Add Android CI build/test job or steps.

**Interfaces:**
- Acceptance proves contracts, real analyzer, delivery, Android build/local route and existing Vibe regressions together.

- [ ] Add mocked Telegram E2E: upload → explicit operation → ArtifactContract → JobContract → real fixture analyzer → ResultContract → DeliveryContract → file send.
- [ ] Add negative E2E for tampered artifact and quota-held job.
- [ ] Add Android contract/local analyzer tests to CI and build debug APK.
- [ ] Run all Python tests, `tools/vibebot_test.py`, validation, Android unit tests and `assembleDebug`.
- [ ] Dispatch one GitHub fixture workflow smoke test and inspect `result.json` plus generated output.
- [ ] Re-run full suite after fixes; no skipped cloud contract tests.
- [ ] Only then mark V2 behavior verified; disclose live Telegram/R2 configuration still required if credentials/provider bindings are not present.
- [ ] Commit `test(v2): gate Telegram Android hybrid end-to-end behavior`.

## Execution Order

`Task 1 baseline repair → 2 artifact trust → 3 result/delivery → 4 routing/budget → 5 real analyzer → 6 Actions → 7 Telegram → 8 Android foundation → 9 local analyzer → 10 persistence/UI → 11 E2E acceptance`

Do not parallelize Tasks 1–7 because they establish shared contracts sequentially. Android UI work may branch after Task 4 only if contract schemas are frozen, but merge acceptance remains gated on Tasks 5–7 and contract compatibility.
