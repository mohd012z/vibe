"""Hermes inspector regression tests, standard library only."""
from __future__ import annotations
import io
import struct
import sys
import unittest
import warnings
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from vibe_hermes import MAGIC, SUPPORTED, InvalidAPK, inspect_bytes, read_hbc_header


def bytecode(version: int) -> bytes:
    raw = bytearray(64)
    struct.pack_into("<QI", raw, 0, MAGIC, version)
    struct.pack_into("<I", raw, 32, 64)
    return bytes(raw)


def apk(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members:
            z.writestr(name, data)
    return buf.getvalue()


class InspectorTests(unittest.TestCase):
    def test_all_registered_versions(self):
        self.assertEqual(len(SUPPORTED), 22)
        for version in SUPPORTED:
            with self.subTest(version=version):
                self.assertTrue(read_hbc_header(bytecode(version))["hbctool_0_1_7_registered"])

    def test_unknown_versions_fail_closed(self):
        for version in (58, 60, 63, 75, 101):
            self.assertFalse(read_hbc_header(bytecode(version))["hbctool_0_1_7_registered"])

    def test_bad_headers(self):
        for data in (b"", b"x" * 11, b"x" * 64):
            with self.assertRaises(InvalidAPK):
                read_hbc_header(data)

    def test_bigint_preflight_fails_closed(self):
        raw=bytearray(80)
        struct.pack_into("<QI",raw,0,MAGIC,100)
        struct.pack_into("<I",raw,32,80)
        struct.pack_into("<II",raw,64,2,16)
        result=read_hbc_header(bytes(raw),80)
        self.assertEqual(result["layout_preflight"],"unsupported_bigint_sections")
        inventory=inspect_bytes(apk([("assets/index.android.bundle",bytes(raw))]))
        self.assertEqual(inventory["bundles"][0]["layout_preflight"],
                         "unsupported_bigint_sections")

    def test_bigint_empty_preflight(self):
        raw=bytearray(80)
        struct.pack_into("<QI",raw,0,MAGIC,99)
        struct.pack_into("<I",raw,32,80)
        self.assertEqual(read_hbc_header(bytes(raw),80)["layout_preflight"],
                         "bigint_sections_empty")

    def test_mixed_technology(self):
        raw = apk([("classes.dex", b"dex"), ("lib/arm64-v8a/libflutter.so", b"x"),
                   ("assets/index.android.bundle", bytecode(100))])
        res = inspect_bytes(raw)
        self.assertEqual(set(res["technologies"]), {"DEX", "Flutter", "React Native", "Hermes"})
        self.assertEqual(res["bundles"][0]["hbc_version"], 100)

    def test_javascript_not_misclassified(self):
        res = inspect_bytes(apk([("assets/index.android.bundle", b"var x=1;")]))
        self.assertNotIn("Hermes", res["technologies"])

    def test_reject_invalid_archive(self):
        with self.assertRaises(InvalidAPK):
            inspect_bytes(b"not an archive")

    def test_reject_traversal(self):
        for name in ("../bad", "/bad", "a/../../b", "a\\b"):
            with self.assertRaises(InvalidAPK):
                inspect_bytes(apk([(name, b"test")]))

    def test_duplicate_entry(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            raw = apk([("classes.dex", b"x"), ("classes.dex", b"y")])
        with self.assertRaises(InvalidAPK):
            inspect_bytes(raw)

    def test_bomb_rejected(self):
        with self.assertRaises(InvalidAPK):
            inspect_bytes(apk([("assets/bomb", b"0" * 2_000_000)]))

    def test_preserve_input(self):
        raw = apk([("assets/index.android.bundle", bytecode(100))])
        before = bytes(raw)
        inspect_bytes(raw)
        self.assertEqual(raw, before)


if __name__ == "__main__":
    unittest.main()
