"""vibebot.dexdump — static DEX discovery in packed / tampered artifacts.

Ports the detection core of the team's DexDumper (github.com/muhammadrizwan87/
dexdumper, MIT; the TDOhex team's own runtime memory dumper) to the STATIC
side: instead of scanning /proc/self/maps at runtime, we scan the artifact's
"regions" — every decompressed ZIP entry plus the raw bytes after the ZIP
central directory (the classic dex-shell packer layout: a stub classes.dex in
the zip + the REAL dex appended at the tail of the file).

Per DexDumper's mechanism (mechanism write-up only; the C code is MIT but the
invariant is zero verbatim copy):
  * DEX signature = magic "dex\\n" (dex\\n035..040 versions).
  * A signature is NOT a DEX until the STRUCTURAL header validates:
      file_size  @0x20 within min/max AND <= remaining buffer
      header_size @0x24 == 0x70
      endian_tag @0x28 == 0x12345678
      string_ids @0x38 (count) / @0x3C (offset): off + count*4 <= file_size
  * OAT containers (magic "oat\\n") are scanned for embedded DEX.
  * SHA1 + Adler-32 (the integrity half) is delegated to dexutil.check_header
    — the repo's existing source of record for those offsets.

Evidence: each hit is E1 (signature at offset) + structural verdict; the
sha1/adler integrity is E2 when the slice is complete. A signature whose
header fails structural validation is reported as such — never dropped,
never promoted.
"""

from __future__ import annotations

import os
import struct
import zipfile

from typing import Union

from . import dexutil

Buffer = Union[bytes, bytearray]

MAGIC = b"dex\n"
OAT_MAGIC = b"oat\n"

HEADER_SIZE = 0x70
ENDIAN_TAG = 0x12345678
OFF_FILE_SIZE = 0x20
OFF_HEADER_SIZE = 0x24
OFF_ENDIAN_TAG = 0x28
OFF_STRING_IDS_SIZE = 0x38
OFF_STRING_IDS_OFF = 0x3C

DEX_MIN_SIZE = 1024
DEX_MAX_SIZE = 50 * 1024 * 1024
MAX_SCAN_BYTES = 256 * 1024 * 1024
MAX_HITS = 128


def _find_all(buf: Buffer, magic: bytes, cap: int) -> list[int]:
    """All (possibly overlapping) magic offsets, bounded."""
    out: list[int] = []
    i = buf.find(magic)
    while i != -1 and len(out) < cap:
        out.append(i)
        i = buf.find(magic, i + 1)
    return out


def validate_structural(buf: Buffer, off: int) -> dict:
    """Structural DEX-header validation at `off` (DexDumper's core, pure).

    Returns {signature, file_size, header_size_ok, endian_ok,
    string_table_ok, structural, detail}. Never raises on short buffers —
    a truncated tail is a verdict, not an error.
    """
    if off + 8 > len(buf):
        return {"signature": off, "structural": False,
                "detail": "truncated: < 8 bytes after magic"}
    version = buf[off + 4:off + 8]
    if off + HEADER_SIZE > len(buf):
        return {"signature": off, "version": version.decode("latin1").rstrip("\x00"),
                "structural": False,
                "detail": f"truncated: {len(buf) - off} bytes after magic < 0x70 header"}
    fsize = struct.unpack("<I", buf[off + OFF_FILE_SIZE:off + OFF_FILE_SIZE + 4])[0]
    hsize = struct.unpack("<I", buf[off + OFF_HEADER_SIZE:off + OFF_HEADER_SIZE + 4])[0]
    endian = struct.unpack("<I", buf[off + OFF_ENDIAN_TAG:off + OFF_ENDIAN_TAG + 4])[0]
    s_count = struct.unpack("<I", buf[off + OFF_STRING_IDS_SIZE:off + OFF_STRING_IDS_SIZE + 4])[0]
    s_off = struct.unpack("<I", buf[off + OFF_STRING_IDS_OFF:off + OFF_STRING_IDS_OFF + 4])[0]
    problems = []
    if not (DEX_MIN_SIZE <= fsize <= DEX_MAX_SIZE):
        problems.append(f"file_size {fsize} outside {DEX_MIN_SIZE}-{DEX_MAX_SIZE}")
    # NOTE: "claimed size > available buffer" is NOT a structural failure —
    # the header is coherent, the payload is just truncated. classify_hit
    # reports it as INCOMPLETE (DexDumper's own logic distinguishes the two).
    if hsize != HEADER_SIZE:
        problems.append(f"header_size {hsize:#x} != {HEADER_SIZE:#x}")
    if endian != ENDIAN_TAG:
        problems.append(f"endian_tag {endian:#010x} != {ENDIAN_TAG:#010x}")
    if s_off > fsize or s_off + s_count * 4 > fsize:
        problems.append(f"string_ids {s_count}@{s_off:#x} out of bounds")
    structural = not problems
    return {
        "signature": off,
        "version": version.decode("latin1").rstrip("\x00"),
        "file_size": fsize,
        "structural": structural,
        "detail": "; ".join(problems) if problems else
                  f"size {fsize} header 0x70 endian 0x12345678 strings {s_count}@{s_off:#x}",
    }


def classify_hit(buf: Buffer, off: int) -> dict:
    """Full verdict for one signature: structural + integrity (dexutil)."""
    v = validate_structural(buf, off)
    if not v["structural"]:
        v["integrity"] = None
        v["state"] = "STRUCTURAL-FAIL"
        return v
    fsize = v["file_size"]
    complete = (off + fsize) <= len(buf)
    if not complete:
        v["integrity"] = None
        v["state"] = "INCOMPLETE (claimed size exceeds buffer)"
        return v
    chk = dexutil.check_header(buf[off:off + fsize])
    v["integrity"] = {
        "magic_ok": chk["magic_ok"], "version_ok": chk["version_ok"],
        "size_ok": chk["size_ok"], "sha1_ok": chk["sha1_ok"],
        "checksum_ok": chk["checksum_ok"], "valid": chk["valid"],
    }
    v["state"] = "VALID DEX" if chk["valid"] else "INTEGRITY-FAIL (sha1/adler mismatch)"
    return v


def scan_regions(buf: Buffer, label: str, cap: int = MAX_HITS) -> tuple[list[dict], list[dict]]:
    """Scan one 'region' (byte buffer). Returns (dex_hits, oat_markers)."""
    hits = []
    for off in _find_all(buf[:MAX_SCAN_BYTES], MAGIC, cap):
        h = classify_hit(buf, off)
        h["region"] = label
        hits.append(h)
    oat = [{"signature": o, "region": label}
           for o in _find_all(buf[:MAX_SCAN_BYTES], OAT_MAGIC, 16)]
    return hits, oat


def _read_capped(path: str) -> bytes:
    """Read up to MAX_SCAN_BYTES + margin (the DEX magic scan cap)."""
    out = bytearray()
    with open(path, "rb") as f:
        while len(out) < MAX_SCAN_BYTES + len(MAGIC):
            chunk = f.read(1 << 20)
            if not chunk:
                break
            out += chunk
    return bytes(out)


def _find_tail(path: str) -> bytes:
    """Bytes after the EOCD (the dex-shell appended-dex location). Reads the
    last 64 KB of the file, so it works regardless of total file size.
    Returns b"" if the file is not a zip or the EOCD is absent."""
    import os
    size = os.path.getsize(path)
    if size < 22:
        return b""
    with open(path, "rb") as f:
        f.seek(max(0, size - 64 * 1024))
        tail = f.read()
    eocd = tail.rfind(b"PK\x05\x06")
    if eocd == -1:
        return b""
    comment_len = struct.unpack("<H", tail[eocd + 20:eocd + 22])[0]
    end = eocd + 22 + comment_len
    if end > len(tail):
        return b""  # EOCD in our window but tail data beyond it — need re-read
    after = tail[end:]
    # if the EOCD sat within the last 64KB, `after` may be short; extend from disk
    remaining = size - (max(0, size - 64 * 1024) + end)
    if remaining > len(after):
        with open(path, "rb") as f:
            f.seek(max(0, size - 64 * 1024) + end)
            after = f.read(MAX_SCAN_BYTES)
    return after


def scan_artifact(path: str) -> dict:
    """Scan an .apk/.dex/.apkx/raw-binary artifact (read-only).

    Regions: for zip artifacts — every decompressed entry (a packer's stub
    classes.dex shows here; the real dex appended after the central
    directory shows in the 'raw tail' region, read from the file end so it
    works on files larger than the scan cap).
    """
    raw = _read_capped(path)
    result = {"path": os.path.basename(path), "bytes": len(raw),
              "kind": "binary", "hits": [], "oat": [], "zip_entries": []}

    if path.lower().endswith(".dex"):
        h = classify_hit(raw, 0)
        h["region"] = "file (dex)"
        result["hits"].append(h)
        result["kind"] = "dex"
        _finalize(result)
        return result

    zf = None
    is_zip = False
    try:
        zf = zipfile.ZipFile(path)
        is_zip = True
        names = zf.namelist()
        result["kind"] = "zip/apk"
        result["zip_entries"] = names[:200]
        for n in names:
            if n.lower().endswith((".dex", ".oat", ".vdex")) or "/lib/" in n:
                try:
                    data = zf.read(n)
                except Exception:
                    continue
                h, o = scan_regions(data, f"zip:{n}")
                result["hits"].extend(h)
                result["oat"].extend(o)
    except zipfile.BadZipFile:
        pass
    finally:
        if zf:
            zf.close()

    if is_zip:
        tail = _find_tail(path)
        if tail:
            h, o = scan_regions(tail, "raw tail (after zip EOCD)")
            result["hits"].extend(h)
            result["oat"].extend(o)
    else:
        h, o = scan_regions(raw, "raw file")
        result["hits"].extend(h)
        result["oat"].extend(o)

    _finalize(result)
    return result


def _finalize(res: dict) -> None:
    """Dedupe hits (a stored/uncompressed entry and the same raw bytes) and
    compute the count summary."""
    seen = set()
    uniq = []
    for x in res["hits"]:
        integ = x.get("integrity")
        k = (x.get("file_size"), x.get("state"),
             (integ or {}).get("sha1_ok") if integ else None)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(x)
    res["hits"] = uniq
    res["counts"] = {
        "signatures": len(res["hits"]),
        "valid": sum(1 for x in res["hits"] if x["state"] == "VALID DEX"),
        "structural_fail": sum(1 for x in res["hits"]
                               if x["state"] == "STRUCTURAL-FAIL"),
        "incomplete": sum(1 for x in res["hits"]
                          if x["state"].startswith("INCOMPLETE")),
        "oat_markers": len(res["oat"]),
    }


def render(res: dict) -> str:
    lines = [f"DexDump: {res['path']} ({res['bytes']} bytes, kind={res['kind']})"]
    c = res["counts"]
    lines.append(f"  signatures={c['signatures']}  valid={c['valid']}  "
                 f"structural-fail={c['structural_fail']}  "
                 f"incomplete={c['incomplete']}  oat-markers={c['oat_markers']}")
    if not res["hits"]:
        lines.append("  no DEX signature found (NOT OBSERVED — a packer may hide it "
                     "behind runtime decryption: memory dump / DexDumper-style "
                     "runtime extraction is the next step)")
        return "\n".join(lines) + "\n"
    for i, h in enumerate(res["hits"], 1):
        integ = h.get("integrity")
        tail = ""
        if integ:
            tail = (f"  sha1={'OK' if integ['sha1_ok'] else 'MISMATCH'} "
                    f"adler={'OK' if integ['checksum_ok'] else 'MISMATCH'} "
                    f"version={'OK' if integ['version_ok'] else 'BAD'}")
        lines.append(f"  [{i}] {h['state']}  region={h['region']}  "
                     f"+0x{h['signature']:#x}  v{h.get('version', '?')}  {h['detail']}{tail}")
    for o in res["oat"][:8]:
        lines.append(f"  OAT marker at {o['region']} +0x{o['signature']:#x} "
                     "(embedded DEX scanned in place)")
    lines.append("Static discovery ceiling: packed DEX behind runtime decryption is "
                 "NOT OBSERVED here (needs an in-process memory dump).")
    return "\n".join(lines) + "\n"
