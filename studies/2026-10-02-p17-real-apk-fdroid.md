# P17 real production APK — F-Droid e2e + decoder DEX-glue bug (v0.24, PR #12)

Date: 2026-10-02 · Branch: feat/p17b-real-r8 (PR #12) · Author: Aliph
(Anam-directed "proceed" sweep; real production sample gap)

## Gap this closes

Every P17 Kotlin-metadata verification to date ran on **synthetic-but-real**
builds (genuine kotlinc/d8/R8 output, tiny payloads). The last disclosed
limit: **no real production (non-synthetic) APK/DEX sample.** This round
downloaded a real R8'd production app — the F-Droid client — and ran the
production decoder on it. That immediately surfaced a **real bug** in the
decoder's DEX glue, plus a correction to a P17b finding.

## The sample (real, non-synthetic)

- `https://f-droid.org/F-Droid.apk` — the actual F-Droid store client,
  12,537,183 bytes, **3 DEX** (~24,500 classes), real R8 obfuscation
  (visible `L_COROUTINE/`, `$$ExternalSyntheticThrowCCEIfNotNull0`,
  short mangled names), 5 native libs.
- SHA-256 recorded at download (see repo fixture note for the small DEX).
- F-Droid has no live API (`/api/v1` 404, `index-v1.xml` 404, `index.xml`
  serves HTML) — package URLs come from the `/packages/<pkg>/` web page.

## Finding 1 — the production decoder CRASHED on the real APK

First run of `kotlinmeta.extract_kotlin_metadata` on the real DEX raised
`IndexError` in `_varint` while reading a `d1`/`d2` string element. The
production code path, never before fed a large real string table, was broken.

### Root cause (authoritative: DEX encoded_value layout)

`_string_of` read a string element's index as a **ULEB128 varint**:

```python
sid = _varint(bytes(el.raw_value))[0]   # WRONG
```

But DEX `encoded_value` string indices are **fixed-width little-endian**,
width = `value_arg + 1` (from the annotation's element encoding) — **not**
varints. androguard's own `_getintvalue` confirms: it reads
`raw_value` as little-endian of width `value_arg + 1`.

Why it was masked: on a small string table every index is `< 128`, i.e.
**one byte**, where fixed-LE and ULEB128 happen to produce the same value.
My synthetic 6-class fixture (and every earlier P17 check) sat entirely in
that 1-byte regime, so the two encodings agreed and the bug was invisible.
A real R8'd app has a large string table: indices reach **2+ bytes**
(e.g. `b'\xaf\xe0'` = 0x80af) and a 1-byte high-bit value, where the varint
read either walks off the end of `raw_value` (→ `IndexError`) or lands on a
**wrong string** (silent). Both failure modes were observed.

### The fix (correct by construction)

```python
def _string_of(dex, el):
    v = el.value
    if isinstance(v, str):
        return v                        # androguard already resolved it
    sid = int.from_bytes(bytes(el.raw_value), "little")   # fixed-width LE
    return dex.get_cm_string(sid)
```

androguard 4.x resolves a `VALUE_STRING` EncodedValue to the raw DEX string
at parse time, so `el.value` **is** the string — correct for any index
width. The fixed-width little-endian read is the faithful fallback. Verified
`int.from_bytes(raw,'little') == el.value`'s index for 1-, 2-, and 3-byte
widths on the real DEX.

### Authoritative corroboration (AOSP runtime, fetched 2026-10-02)

The DEX format's reference runtime (AOSP `art/libdexfile/dex/dex_file.cc`)
decodes `kEncodedValueString` with `DexFile::ReadUnsignedInt(ptr, value_arg)`
where `value_arg = value_type >> kEncodedValueArgShift` and
`width = value_arg + 1`. `ReadUnsignedInt` (dex_file.cc:623) is a
fixed-width LITTLE-ENDIAN read (`val = (val >> 8) | (*ptr++ << 24)` per
byte, right-justified) — **not** a varint. The fix matches the AOSP
runtime byte-for-byte in semantics; the old varint read contradicted it.
(Three independent oracles now agree: AOSP runtime source, androguard's
resolved value, and the whole-APK 0-exception run.)

## Finding 2 — a real production R8'd app KEEPS @Metadata

P17b concluded "default R8 config strips `@Metadata` entirely," validated on
my own synthetic R8 build (default config, `classes-stripped.dex`). The real
F-Droid client **does not** follow that: it carries `@kotlin.Metadata` on
**1,544 classes** across the 3 DEX. So P17's Kotlin name-recovery is a live
real-world capability on this app, and the P17b ceiling is a property of
*that specific R8 config*, not of R8 generally. The decoder's value on a
real obfuscated production target is confirmed.

## Verification (real data, production code path, no monkeypatch)

Fixed `extract_kotlin_metadata` + `decode_class_metadata` run on all 3 real
DEX, through the real code path:

```
classes.dex : total= 183  decoded_with_props= 168  empty_d1= 15  exc=0
classes2.dex: total= 723  decoded_with_props= 594  empty_d1=129  exc=0
classes3.dex: total= 638  decoded_with_props= 346  empty_d1=292  exc=0
TOTAL       : 1544 metadata classes, 1108 decoded with original property
              names, 436 honest empty-d1 (R8 dropped the d1 payload — the
              P17b ceiling, now seen on real production data), 0 exceptions
```

Real name recovery examples: `org.froid.database.MinimalApp` →
`repoId, packageName, name, summary`; `AddRepoError` → `errorType,
exception`. Zero `IndexError`, zero wrong-string.

## Regression guard (committed)

A real kotlinc/d8 DEX (`tests/fixtures/ktmeta_multibyte/classes.dex`, 19KB,
`com.reg.Target` data class + 60 filler objects so the string table passes
the 1-byte regime) reproduces the bug: **15/25** `@Metadata` string items
misread by the old varint code, 0 by the fixed code. 8 new checks in
`vibebot_test.py`:

- synthetic unit: fixed `_string_of` reads 1/2/3-byte fixed-LE indices
  correctly, and prefers androguard's resolved `el.value`;
- real fixture: old varint read provably gets a string **wrong** on this
  exact DEX; fixed read resolves **every** `@Metadata` string to
  androguard's value; `Target` decodes with its original property names.

These 8 are **pinned in CI-shape** too (they need only androguard + the
committed fixture, not the optional toolchain), so the bug cannot resile on
a host without r2/kotlinc.

## Honest limits (after this round)

- Real production R8'd app now exercised E2E on the Kotlin path — the
  biggest "synthetic-only" gap is closed for P17.
- P17b "R8 strips @Metadata by default" remains true *for that R8 config*;
  it is now scoped as config-specific, not universal (Finding 2).
- The 436 empty-d1 classes are an honest ceiling (R8 dropped d1) — the
  decoder correctly reports "no recoverable name," not a fabricated one.
- F-Droid.apk itself is large (12.5MB, 3 DEX) — committed only the small
  19KB regression DEX to the repo; the APK is a local scratch artifact, not
  a repo fixture.
- Native path on the real APK (5 .so, incl. libwebview etc.) not yet run
  through P18/P19 in this round — Kotlin decoder fix is the focus; the real
  native e2e is the natural next slice.

## Methodology note (why this is trustworthy)

- Root cause from the **authoritative** DEX `encoded_value` layout
  (androguard `_getintvalue`), not from guessing at the crash.
- Fix verified against androguard's own resolved string (independent oracle)
  for every width, and against the whole real APK (1544 classes, 0 exc).
- Regression is a **real toolchain output** (kotlinc + d8), not a hand-built
  byte blob, and the test *asserts the old code fails on it* — so the guard
  is self-proving, not just "no crash."
