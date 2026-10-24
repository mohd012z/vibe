# Study — t.me/fileshare_tg (TDOhex Files Share) + DexDumper (2026-10-24)

Anam: "please study and learn deeper from this https://t.me/fileshare_tg, find
useful code and implement".

## Access (honest, per source)

| Source | Access level | What was read |
|---|---|---|
| `t.me/s/fileshare_tg` | member-restricted (0 message widgets; verified via curl + widget count, per re-source-study protocol) | Header only: 521 members, helper group for `@TDOhex_Discussion`; files are "meant to be referenced in" the discussion group |
| `t.me/s/TDOhex` (main channel) | member-restricted (0 widgets) | Header via TGStat: "Dimension of TDO" — technical knowledge, mods, team of @MuhammadRidwan87 |
| `tgstat.com/channel/@tdohex` | **public cache of 20 posts (#474–#495)** | Full post text incl. smali regex patterns (see below) |
| `github.com/muhammadrizwan87/dexdumper` | full repo, cloned, read all 12 .c + 10 .h (2,923 lines) | The "useful code" — team's own MIT pure-C runtime memory DEX dumper |

The fileshare group itself cannot be read anonymously (files live in it), so
the study used the team's public channel cache + the DexDumper repo that the
group's posts reference. The discussion-group posts referenced from the
cache (e.g. `fileshare_tg/86` "Patched Version", `TDOhex_Discussion/71020`
"Terminal Crash Fix") are the actual files — to study a specific one it must
be forwarded/exported (Anam's group, one tap).

## Methods read (TDOhex channel, posts #477–#494)

- **SSL pinning (okhttp3) — the invariant-regex family** (posts 479/480/481):
  locate obfuscated `check()`/`check$okhttp()` by *signature + body invariants*
  rather than name: `.method public (final )?<S>\(Ljava/lang/String;L[^;]+;\)V`
  + `check-cast … Ljava/security/cert/X509Certificate;` +
  `Ljavax/net/ssl/SSLPeerUnverifiedException;` inside the method boundary
  (`(?:(?!\.end\smethod)[\s\S])*?`). Replace with `$1\n\t.registers 3\n\n\treturn-void\n.end method`.
  Tested by the team on 40+ banking/OTT apps. **Already in our toolchain**:
  r2ai v1.7 shipped exactly this as its SSL-Pin button (see r2ai_apk_study)
  — so this post family is the *source* of a method we already own, not a gap.
- **HostnameVerifier.verify() bypass** (post 483): same technique, signature
  `(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z` → replace with
  `const/4 v0, 0x1; return v0`. Static-side twin: our `/scan` TLS section
  already surfaces custom `X509TrustManager` subclasses + CertificatePinner
  refs + `networkSecurityConfig` presence (implemented today).
- **FLAG_SECURE / SurfaceView.setSecure** (484/487): regex anchored on the
  `setSecure(Z)V` invoke or the `0x2000` flag constant flowing into
  `addFlag`/`setFlag` — screen-recording bypass. (r2ai v1.9 SCAN ALL family.)
- **Geo-spoof smali patches** (492): overwrite the `move-result-object`
  register after `TelephonyManager.getNetwork/Sim*` with a const-string.
  Pattern = the smali-books "insert const after invoke" rule already in
  `/smali guide`.
- **Spck NodeJS (React Native) subscription/JWT analysis** (485): the JS
  bundle is the logic layer (Uv subscription check, JWT terminal-launch
  gating); patched version + crash fix live in the fileshare group.
  (Our hybridscan already routes logic-layer verdicts; RN bundle is a
  `assets/index.android.bundle` marker it detects.)
- **DexDumper** (490/491/493): the team's runtime memory DEX dumper — see below.

## The useful code: DexDumper → `/dexdump` (IMPLEMENTED)

DexDumper (MIT, the TDOhex team's own) dumps DEX from a *running* app's
memory, non-root: `System.loadLibrary("dexdumper")` in the app's `<clinit>`
→ background thread waits 8 s → parses `/proc/self/maps` → for each
readable region (size 1 KB–200 MB, system paths filtered) scans in 4-byte
increments for `dex\n035..039` → **structural header validation**
(file_size @0x20 within 1 KB–50 MB and ≤ buffer; header_size @0x24 == 0x70;
endian_tag @0x28 == 0x12345678; string_ids count @0x38 / offset @0x3C with
off + count*4 ≤ file_size) → SHA1 exclusion list + inode-based duplicate
prevention → dump to `/data/data/<pkg>/files/dex_dump/` with SIGSEGV/SIGBUS
signal-protected reads (`sigsetjmp`/`siglongjmp` on a per-thread alt stack).
OAT containers (`oat\n`) get a first-64 KB embedded-DEX pass. Runtime `.conf`
system (2.0.0): region filtering, second scan, SHA1 exclusions, output dirs.

**What we implemented** (the portable half, static side — no root/device
needed): `tools/vibebot/dexdump.py` + `/dexdump <path>` (stdlib-only, sync,
no androguard — sits with /dexcheck):

1. Signature hunt for `dex\n` (4-byte stride) over **every decompressed ZIP
   entry** and the **raw tail after the EOCD** — the dex-shell layout
   (stub classes.dex in the zip + real DEX appended at the file end).
   Tail is read from the file END (last 64 KB window), so files bigger than
   the 256 MB scan cap still work.
2. The same structural validation (file_size/header_size/endian_tag/
   string-table bounds) — offsets cross-checked against the repo's existing
   source of record (`dexutil.check_header`: sha1@12 over bytes[32:],
   adler@8 over bytes[12:], size@0x20).
3. Complete hits additionally get the repo's sha1+adler integrity
   (`dexutil.check_header`), so a hit is `VALID DEX` /
   `INTEGRITY-FAIL (sha1/adler mismatch)` / `STRUCTURAL-FAIL` /
   `INCOMPLETE` — never silently dropped, never promoted (E1 signature →
   E2 integrity).
4. OAT markers reported in place; honest ceiling stated on zero hits:
   "packed-at-runtime DEX is NOT OBSERVED — needs a memory dump"
   (that's what DexDumper itself is for, on-device).

**What we did NOT copy**: the C source (MIT, but the repo invariant is
mechanism write-ups for channel-derived material; DexDumper's C stays in
their repo). The smali regex patterns from the channel are already in r2ai
v1.7/v1.9's scanner set — recorded here as provenance, not re-ported.

## Backlog (from this study, value × feasibility)

1. **DONE** — `/dexdump` static DEX discovery (this PR).
2. **Runtime dex dump** — port DexDumper's C as a bundled lib r2ai can
   `loadLibrary` (their GitHub Actions build already produces all-arch .so;
   smali stub injection is a 6-line patch). Device-side; needs a test APK.
3. **RN/JS-bundle logic layer** — for Spck-type apps, extract
   `assets/index.android.bundle`, locate the subscription-gate function
   (Uv pattern: JWT check → terminal launch) and emit a patch plan against
   the JS, not the smali. hybridscan detects; the patch-plan text is the gap.
4. **FLAG_SECURE / geo-spoof** regex families into r2ai's SCAN ALL
   (already partially there — verify coverage, add `HostnameVerifier`
   `.verify(Z)` family if missing).
