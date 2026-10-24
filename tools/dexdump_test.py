#!/usr/bin/env python3
"""dexdump unit tests — pure stdlib, no androguard, no external artifacts.

Builds synthetic DEX buffers (header fields per the DEX spec, integrity
recomputed with the repo's own dexutil — source of record) and synthetic
APK layouts (stub classes.dex in the zip + real dex appended after the
EOCD = the dex-shell pattern) to pin the DexDumper-ported detection core.

Run:  python tools/dexdump_test.py   (exit 0 = all pass)
"""

import os
import struct
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vibebot import dexdump  # noqa: E402
from vibebot import dexutil  # noqa: E402

FAILS = 0


def check(name, cond, detail=""):
    global FAILS
    print(f"  {'OK  ' if cond else 'FAIL'} {name}" + (f"   ({detail})" if detail and not cond else ""))
    if not cond:
        FAILS += 1


def make_dex(size: int, version: bytes = b"037\x00",
             endian: int = 0x12345678,
             header_size: int = dexdump.HEADER_SIZE,
             strings: int = 4, str_off: int | None = None) -> bytearray:
    """A synthetic DEX: valid magic+version, consistent size fields, and
    (unless overridden) a real SHA-1/Adler per dexutil's repair."""
    b = bytearray(size)
    b[0:4] = b"dex\n"
    b[4:8] = version
    struct.pack_into("<I", b, 0x08, 0)   # checksum placeholder
    b[0x0C:0x20] = b"\x00" * 20          # sha1 placeholder
    struct.pack_into("<I", b, 0x20, size)      # file_size
    struct.pack_into("<I", b, 0x24, header_size)
    struct.pack_into("<I", b, 0x28, endian)
    struct.pack_into("<I", b, 0x38, strings)   # string_ids_size
    struct.pack_into("<I", b, 0x3C, str_off if str_off is not None else 0x70)
    repaired, _rep = dexutil.repair(bytes(b))  # sets checksum + sha1
    return bytearray(repaired)


def main():
    td = tempfile.mkdtemp(prefix="dexdump-test-")
    try:
        print("== structural validation (pure) ==")
        good = make_dex(4096)
        v = dexdump.validate_structural(good, 0)
        check("valid dex: structural True", v["structural"], str(v))
        check("valid dex: file_size read back", v.get("file_size") == 4096, str(v))

        trunc = make_dex(4096)[:100]
        v = dexdump.validate_structural(trunc, 0)
        check("truncated: structural False (verdict, not crash)", v["structural"] is False)
        check("truncated: detail says why", "truncated" in v["detail"], v["detail"])

        bad_endian = make_dex(4096, endian=0x78563412)
        v = dexdump.validate_structural(bad_endian, 0)
        check("big-endian tag: structural False", v["structural"] is False, v["detail"])

        bad_header = make_dex(4096, header_size=0x6C)
        v = dexdump.validate_structural(bad_header, 0)
        check("header_size != 0x70: structural False", v["structural"] is False, v["detail"])

        huge = make_dex(4096)
        struct.pack_into("<I", huge, 0x20, 60 * 1024 * 1024)
        v = dexdump.validate_structural(huge, 0)
        check("file_size out of bounds: structural False", v["structural"] is False, v["detail"])

        s_out = make_dex(4096, strings=100, str_off=4096 - 8)
        v = dexdump.validate_structural(s_out, 0)
        check("string table out of bounds: structural False", v["structural"] is False, v["detail"])

        check("short buffer: no crash, structural False",
              dexdump.validate_structural(b"dex\n03", 0)["structural"] is False)

        print("== classify_hit (structural + integrity) ==")
        v = dexdump.classify_hit(good, 0)
        check("valid dex: state VALID DEX", v["state"] == "VALID DEX", str(v["state"]))
        check("valid dex: integrity sha1 OK", v["integrity"]["sha1_ok"])
        check("valid dex: integrity adler OK", v["integrity"]["checksum_ok"])

        # corrupt sha1 of a structural-valid dex -> INTEGRITY-FAIL, not silent
        bad_sha = bytearray(make_dex(4096))
        bad_sha[0x0C] ^= 0xFF
        v = dexdump.classify_hit(bytes(bad_sha), 0)
        check("sha1 mismatch: INTEGRITY-FAIL state", v["state"].startswith("INTEGRITY-FAIL"),
              str(v["state"]))
        check("sha1 mismatch: still structural (header fine)",
              v["structural"] is True or "size" in v["detail"], str(v))

        incomplete = make_dex(8192)[:4096]
        v = dexdump.classify_hit(incomplete, 0)
        check("header coherent but payload truncated: INCOMPLETE",
              v["state"].startswith("INCOMPLETE"), str(v["state"]))

        print("== scan_regions (magic hunt) ==")
        pad = b"\x00" * 1000
        buf = pad + good + b"\xAA" * 500 + good
        hits, oat = dexdump.scan_regions(buf, "test")
        check("two signatures found", len(hits) == 2, str([h['signature'] for h in hits]))
        check("offsets correct", [h["signature"] for h in hits] == [1000, 1000 + 4096 + 500],
              str([h['signature'] for h in hits]))
        check("both VALID", all(h["state"] == "VALID DEX" for h in hits))
        check("no oat markers", oat == [])

        oat_buf = b"oat\n037" + b"\x00" * 64
        hits, oat = dexdump.scan_regions(oat_buf, "oat")
        check("oat marker detected", len(oat) == 1 and oat[0]["signature"] == 0, str(oat))
        check("oat without embedded dex: no hits", hits == [])

        check("empty buffer: no hits", dexdump.scan_regions(b"", "e") == ([], []))

        print("== scan_artifact: bare .dex file ==")
        p = os.path.join(td, "real.dex")
        open(p, "wb").write(good)
        res = dexdump.scan_artifact(p)
        check("dex file: kind dex", res["kind"] == "dex")
        check("dex file: one VALID hit", res["counts"]["valid"] == 1, str(res["counts"]))

        print("== scan_artifact: dex-shell APK (stub in zip + real at tail) ==")
        real = make_dex(16384)
        stub = make_dex(2048)
        apk = os.path.join(td, "packed.apk")
        with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("AndroidManifest.xml", b"<manifest/>")
            z.writestr("classes.dex", stub)
            z.writestr("res/x.xml", b"<x/>")
        with open(apk, "ab") as f:
            f.write(b"\x00" * 32)   # alignment padding some packers add
            f.write(real)
        res = dexdump.scan_artifact(apk)
        check("packed: kind zip/apk", res["kind"] == "zip/apk")
        check("packed: 2 signatures (stub + real)", res["counts"]["signatures"] == 2,
              str(res["counts"]))
        check("packed: 2 valid dex", res["counts"]["valid"] == 2, str(res["counts"]))
        regions = sorted(h["region"] for h in res["hits"])
        check("packed: stub via zip region", any(r.startswith("zip:classes.dex") for r in regions),
              str(regions))
        check("packed: real via tail region", any(r.startswith("raw tail") for r in regions),
              str(regions))
        sizes = sorted(h.get("file_size") for h in res["hits"])
        check("packed: both sizes present", sizes == [2048, 16384], str(sizes))

        print("== scan_artifact: plain APK, no tail ==")
        plain = os.path.join(td, "plain.apk")
        with zipfile.ZipFile(plain, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("classes.dex", good)
            z.writestr("res/a.xml", b"<a/>")
        res = dexdump.scan_artifact(plain)
        check("plain: 1 valid (the zip entry)", res["counts"]["valid"] == 1, str(res["counts"]))
        check("plain: signature count 1 (deduped tail miss)", res["counts"]["signatures"] == 1,
              str(res["counts"]))

        print("== scan_artifact: not a zip / not a dex ==")
        notdex = os.path.join(td, "blob.bin")
        open(notdex, "wb").write(os.urandom(65536))
        res = dexdump.scan_artifact(notdex)
        check("random binary: kind binary", res["kind"] == "binary")
        check("random binary: honest 0 (may be lucky-0, never a crash)",
              res["counts"]["signatures"] in (0, 1), str(res["counts"]))

        print("== render ==")
        text = dexdump.render(res)
        check("render has counts line", "signatures=" in text)
        text2 = dexdump.render(dexdump.scan_artifact(plain))
        check("render lists regions", "zip:classes.dex" in text2, text2)
        empty = {"path": "x.apk", "bytes": 10, "kind": "zip/apk", "hits": [], "oat": [],
                 "zip_entries": [], "counts": {"signatures": 0, "valid": 0,
                                               "structural_fail": 0, "incomplete": 0,
                                               "oat_markers": 0}}
        check("render empty: NOT OBSERVED + next-step hint",
              "NOT OBSERVED" in dexdump.render(empty) and "memory dump" in dexdump.render(empty))
    finally:
        import shutil
        shutil.rmtree(td, ignore_errors=True)

    print()
    if FAILS:
        print(f"dexdump: {FAILS} FAIL")
        sys.exit(1)
    print("dexdump: ALL PASS")


if __name__ == "__main__":
    main()
