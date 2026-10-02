"""vibebot.dexutil — DEX header validation + repair (stdlib only, no androguard).

Implements the /dexcheck and /dexrepair functions of the RevEngi live menu.
The repair algorithm is reimplemented from public DEX format facts (magic
prefix "dex\\n" + 4-byte null-padded version, SHA-1 signature over bytes[32:],
Adler-32 checksum over bytes[12:], both little-endian at fixed offsets) — it
is ORIGINAL code, not copied from any RevEngi/revengi-app source (which is
Dart; the algorithm is a ~15-line standard reconstruction).

Evidence model: this is direct byte-level evidence — each check reports the
stored value vs the recomputed value, so a repair is verifiable, not a claim.

Read-only with respect to the input: repair() returns new bytes + a report;
it never writes the input path. (The gateway writes the repaired COPY to the
work dir under a new name.)
"""

from __future__ import annotations

import hashlib
import struct
import zlib

MAGIC = b"dex\n"
# DEX version strings are 4 bytes, null-padded (e.g. b"035\x00").
VALID_VERSIONS = (b"035\x00", b"037\x00", b"038\x00", b"039\x00", b"040\x00")

CHECKSUM_OFF = 8     # u32 little-endian, adler32 over bytes[12:]
SHA1_OFF = 12        # 20 bytes, sha1 over bytes[32:]
SHA1_LEN = 20


def _version_of(b: bytes) -> bytes:
    return b[4:8]


def check_header(b: bytes) -> dict:
    """Validate a DEX header. Pure — returns a report, never mutates.

    Report fields:
      magic_ok, version (str), version_ok
      file_size_stored, file_size_actual, size_ok
      checksum_stored, checksum_computed, checksum_ok
      sha1_ok, sha1_stored (hex), sha1_computed (hex)
      valid (all of the above), details (list of human-readable lines)
    """
    if len(b) < 32:
        return {"valid": False, "error": f"too short for a DEX header ({len(b)} < 32)",
                "details": [f"file is {len(b)} bytes; a DEX header is 112"]}
    magic_ok = b[0:4] == MAGIC
    version = _version_of(b)
    version_ok = magic_ok and version in VALID_VERSIONS
    size_stored = struct.unpack("<I", b[32:36])[0]
    size_ok = size_stored == len(b)
    ck_stored = struct.unpack("<I", b[CHECKSUM_OFF:CHECKSUM_OFF + 4])[0]
    ck_computed = zlib.adler32(b[12:]) & 0xFFFFFFFF
    sha_stored = b[SHA1_OFF:SHA1_OFF + SHA1_LEN]
    sha_computed = hashlib.sha1(b[32:]).digest()
    _ver_disp = version.decode("latin1").replace("\x00", "")
    details = []
    details.append("magic " + ("OK" if magic_ok else f"MISMATCH (got {b[0:4]!r}, want b'dex\\n')"))
    details.append(f"version {_ver_disp!r} " + ("OK" if version_ok else "UNKNOWN (want 035..040)"))
    details.append(f"file_size stored={size_stored} actual={len(b)} " + ("OK" if size_ok else "MISMATCH"))
    details.append(f"adler32 stored=0x{ck_stored:08x} computed=0x{ck_computed:08x} " + ("OK" if ck_stored == ck_computed else "MISMATCH"))
    details.append("sha1 " + ("OK" if sha_stored == sha_computed else f"MISMATCH stored={sha_stored.hex()[:16]}… computed={sha_computed.hex()[:16]}…"))
    return {
        "magic_ok": magic_ok,
        "version": version.decode("latin1"),
        "version_ok": version_ok,
        "file_size_stored": size_stored,
        "file_size_actual": len(b),
        "size_ok": size_ok,
        "checksum_stored": f"0x{ck_stored:08x}",
        "checksum_computed": f"0x{ck_computed:08x}",
        "checksum_ok": ck_stored == ck_computed,
        "sha1_stored": sha_stored.hex(),
        "sha1_computed": sha_computed.hex(),
        "sha1_ok": sha_stored == sha_computed,
        "valid": magic_ok and version_ok and size_ok
                 and ck_stored == ck_computed and sha_stored == sha_computed,
        "details": details,
    }


def repair(b: bytes) -> tuple[bytes, dict]:
    """Return (repaired_bytes, report). Never mutates the input.

    Repairs, in order (each only if broken):
      1. magic prefix  — "dex\\n" (whole 8-byte header if prefix missing)
      2. version       — force b"035\\x00" if not a known version (035-040)
      3. SHA-1         — recompute over bytes[32:]
      4. Adler-32 ck   — recompute over bytes[12:] (AFTER the sha fix, since
                         the checksum covers the signature field)
    file_size is left as-is (the tool cannot know the intended size); the
    report flags it so the caller can decide.

    Report (the fields the gateway renders):
      changed (bool), version (str), magic_changed (str|None),
      sig_recomputed (bool), chk_recomputed (bool),
      sha1_ok / checksum_ok (post-repair), fixes_applied (list).
    """
    if len(b) < 32:
        raise ValueError(f"too short to repair ({len(b)} < 32)")
    out = bytearray(b)
    fixes: list[str] = []
    magic_changed = None

    if out[0:4] != MAGIC:
        old_magic = out[0:4]
        # Preserve a still-valid version byte (4:8); force 035 only if the
        # version itself is also broken — avoids downgrading a healthy 037
        # DEX whose magic prefix alone was corrupted.
        if out[4:8] in VALID_VERSIONS:
            out[0:4] = MAGIC
            magic_changed = (f"magic prefix {old_magic!r} -> b'dex\\n' "
                             f"(version kept {out[4:8].decode('latin1').strip()!r})")
            fixes.append("magic prefix restored (version preserved)")
        else:
            out[0:8] = MAGIC + b"035\x00"
            magic_changed = f"header {out[0:8]!r} -> b'dex\\n035\\x00'"
            fixes.append("magic+version (prefix missing -> dex\\n035)")
    else:
        old_version = out[4:8]
        if old_version not in VALID_VERSIONS:
            out[4:8] = b"035\x00"
            magic_changed = f"version {old_version!r} -> b'035\\x00'"
            fixes.append(f"version forced to 035")

    # SHA-1 over bytes[32:] (recomputed after any magic/version change)
    sha_now = hashlib.sha1(bytes(out[32:])).digest()
    sig_recomputed = False
    if out[SHA1_OFF:SHA1_OFF + SHA1_LEN] != sha_now:
        out[SHA1_OFF:SHA1_OFF + SHA1_LEN] = sha_now
        sig_recomputed = True
        fixes.append("sha1 signature recomputed over bytes[32:]")

    # Adler-32 over bytes[12:] (covers the signature field, so AFTER sha fix)
    ck_now = zlib.adler32(bytes(out[12:])) & 0xFFFFFFFF
    chk_recomputed = False
    if struct.unpack("<I", out[CHECKSUM_OFF:CHECKSUM_OFF + 4])[0] != ck_now:
        out[CHECKSUM_OFF:CHECKSUM_OFF + 4] = struct.pack("<I", ck_now)
        chk_recomputed = True
        fixes.append("adler32 checksum recomputed over bytes[12:]")

    post = check_header(bytes(out))
    report = {
        "changed": bool(fixes),
        "version": post["version"],
        "magic_changed": magic_changed,
        "sig_recomputed": sig_recomputed,
        "chk_recomputed": chk_recomputed,
        "sha1_ok": post["sha1_ok"],
        "checksum_ok": post["checksum_ok"],
        "size_ok": post["size_ok"],
        "fixes_applied": fixes or ["none (already valid)"],
    }
    return bytes(out), report


def check_file(path: str) -> dict:
    b = open(path, "rb").read()
    r = check_header(b)
    r["path"] = path
    r["bytes"] = len(b)
    return r
