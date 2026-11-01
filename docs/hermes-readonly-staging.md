# Hermes read-only analysis — Vibe Draft PR #34

**Updated: 1 November 2026.** Staging branch: `feature/read-only-hermes-inspector-20261101`.
Production `main` remains unchanged. No APK mutation, app deployment, new billing settings, secrets, public network service or Telegram gateway edits are part of this branch.

## Tools and documented boundaries

- `tools/vibe_hermes.py`: identifies APK technologies and registered HBC versions, with ZIP path/duplicate/inflation limits, header-only bundle identification, and controlled malformed archive errors.
- `tools/vibe_hermes_mobile.py`: read-only localhost browser UI, file chooser, 50-row accessible pagination, bounded 96 MiB upload, 30-second upload deadline, Host/Origin/session-token validation, and only one active analysis. Optional local `hbctool` runs in a disposable directory.
- `tools/vibe_hermes_index.py`: bounded function index and **explicit string-operand annotation** references. It does **not** infer call graph edges.
- Separate source patch prototypes: all-versions string-byte safeguards and BitWriter accounting; experimental BigInt and FunctionSource section codecs; malformed opcode error normalization. They operate on SHA-verified temporary checkouts of Kirlif/HBC-Tool `eaf70a8700380f35e39e1bdbcaac01a3c49a63b0`. The published upstream wheel and the user-facing read-only APK scanner are **not** silently rewritten.
- `docs/hermes-termux-checklist.md`: phone-first local setup directions. **Termux and physical Android operation remain unverified.**

## Reproducible evidence

- `python3 -m unittest discover -s tests -p 'test_vibe_hermes*.py' -v`: exact PR CI regression suite. Current evidence includes deterministic ZIP/header mutations, adversarial HASM annotation tests, localhost security, and mobile markup/pagination checks.
- Pinned public Talaria corpus (10 versions: 59, 62, 74, 76, 84, 85, 90, 94, 96, 98): **10/10 byte-identical** reconstruction. See Actions run [41271618419](https://github.com/mohd012z/vibe/actions/runs/41271618419).
- Independent P1sec/hermes-dec corpus (84, 94, 99): **3/3 byte-identical** reconstruction and zero function-level opcode-name sequence mismatches after fixing the test parser's handling of unpadded long mnemonic names. Saved official Hermes `hbcdump` outputs for 94 and 99 agree. See Actions run [41272820449](https://github.com/mohd012z/vibe/actions/runs/41272820449).
- The unique genuine version coverage is **11 of 22**; 11 more still lack a verified fixture. This does not prove operand/semantic equivalence or real Android behavior.
- All 22 version modules: getters, UTF-8/UTF-16 same-encoded-length replacement and BitWriter alignment tested in a SHA-pinned checkout; experimental BigInt table/storage codec covers 14 versions and 98 synthetic cases. A forced mid-replacement failure recovered the original parser bytes. See [41272020056](https://github.com/mohd012z/vibe/actions/runs/41272020056).
- A bounded opcode-fuzz gate generated **3,960 random streams** against 22 isolated translators; **zero unexpected exceptions**, with 3,698 malformed streams rejected as controlled ValueErrors. See [41272329461](https://github.com/mohd012z/vibe/actions/runs/41272329461).

## Critical correction in differential analysis

An earlier comparison falsely claimed HBC-Tool decoded numerous instructions incorrectly. The comparison regex had skipped opcodes with names 20 characters or longer (e.g. `CreateFunctionEnvironment`), which are not padded in HBC-Tool's HASM format. The regression test now covers these opcodes. After correcting the harness, official/independent comparisons find **zero opcode-name sequence mismatches** for all three genuine P1sec fixtures. The earlier HBC-Tool decoder-defect conclusion is withdrawn.

## Current release blockers

Genuine fixtures are missing for 11 registered versions. No genuine nonempty BigInt sample was validated, so the read-only UI intentionally refuses nonempty BigInt layouts even though an experimental source codec exists. Real Termux and Android browser tests (file picking, rotation, low-memory use and background lifetime) have not been executed. Full operand-level parity and runtime semantics have not been established. Source patch tools must not be merged into an automated production editing path until those gates are satisfied.

## Commands

```sh
python3 -m unittest discover -s tests -p 'test_vibe_hermes*.py' -v
python3 tools/vibe_hermes_mobile.py --port 8765
python3 tools/vibe_hermes.py /path/to/authorized-sample.apk
```

**Keep PR #34 DRAFT and UNMERGED.** An existing CI runner executing under repository settings does not prove billing-free account-level usage; no billing settings were modified by these changes.
