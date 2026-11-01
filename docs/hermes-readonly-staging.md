# Hermes read-only analyzer — isolated Vibe staging branch

This branch adds `tools/vibe_hermes.py` and `tests/test_vibe_hermes.py`, without altering production bot commands, APKs, manifests, signing, cloud endpoints, or existing CI configuration.

## Scope and use

```sh
python tools/vibe_hermes.py /path/to/authorized-sample.apk
python -m unittest discover -s tests -p 'test_vibe_hermes.py' -v
```

The inspector detects Hermes magic/version and registered HBC versions 59–100, inventories DEX/Flutter/React Native markers, bounds ZIP metadata, rejects duplicate or traversal member names, and reads only metadata/first 64 bytes of bundle candidates. No extraction of target code, code execution, patching, signing, deployment, or third-party service is involved.

## Validation status

- Static source review of the upstream Kirlif/HBC-Tool 0.1.7 release identified a HBC100 `getVersion()` defect and unsafe string replacement lengths. Those bugs are **not** modified upstream by this staging branch.
- Local offline study had passing regression tests for an independently packaged extended toolkit. These **must not** be represented as GitHub Actions checks for this branch.
- The new remote tests have **not been executed** on GitHub Actions; no PR was created to avoid automated workflow activity and unintended billing.
- Real-bundle disassembly and rebuild across all 22 versions remain unverified. This branch only provides header/version identification, not a decompiler.
- Android installation and physical-device checks remain unverified.

## Release gates

Before exposing this in a Vibe production command, run exact-commit Python tests in a free local environment, test representative genuine Hermes bundles, review malformed APK cases, and explicitly authorize any additional code or deployment changes. Preserve branch-only review until verified.
