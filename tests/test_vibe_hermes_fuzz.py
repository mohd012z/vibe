"""Deterministic mutation corpus for APK ZIP and Hermes magic/version preflight."""
from __future__ import annotations

import io
import random
import struct
import sys
import unittest
import zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from vibe_hermes import MAGIC,InvalidAPK,inspect_bytes,read_hbc_header

def apk(bundle:bytes)->bytes:
    f=io.BytesIO()
    with zipfile.ZipFile(f,"w",zipfile.ZIP_DEFLATED) as z:
        z.writestr("classes.dex",b"dex\n039\x00")
        z.writestr("assets/index.android.bundle",bundle)
    return f.getvalue()

def header(version:int=99)->bytes:
    b=bytearray(128)
    struct.pack_into("<QI",b,0,MAGIC,version)
    struct.pack_into("<I",b,32,len(b))
    return bytes(b)

class FuzzTests(unittest.TestCase):
    def test_deterministic_corrupt_zip_bytes(self):
        seed=apk(header())
        rand=random.Random(20261101)
        for n in range(300):
            case=bytearray(seed)
            for _ in range(1+rand.randrange(5)):
                offset=rand.randrange(len(case))
                case[offset]^=rand.randrange(1,256)
            with self.subTest(case=n):
                try:
                    response=inspect_bytes(bytes(case))
                    self.assertEqual(len(response["sha256"]),64)
                except InvalidAPK:
                    pass

    def test_truncations_and_trailing_garbage(self):
        raw=apk(header())
        for length in range(0,min(len(raw),180),3):
            with self.subTest(length=length):
                try: inspect_bytes(raw[:length])
                except InvalidAPK: pass
        accepted=inspect_bytes(raw+b"junk")
        self.assertIn("bundles",accepted)

    def test_header_fuzz_tolerates_unsupported_versions(self):
        rng=random.Random(9981)
        for _ in range(400):
            data=bytearray(header())
            for j in range(rng.randrange(1,5)):
                data[rng.randrange(80)]^=rng.randrange(1,256)
            try:
                response=read_hbc_header(bytes(data),128)
                self.assertTrue(1<=response["hbc_version"]<=65535)
            except InvalidAPK:
                pass

    def test_compressed_bomb_and_duplicate_members_fail_closed(self):
        with self.assertRaises(InvalidAPK):
            inspect_bytes(apk(b"0"*3_000_000))
        f=io.BytesIO()
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore",UserWarning)
            with zipfile.ZipFile(f,"w") as z:
                z.writestr("classes.dex",b"one")
                z.writestr("classes.dex",b"two")
        with self.assertRaises(InvalidAPK):
            inspect_bytes(f.getvalue())

if __name__=="__main__":
    unittest.main()
