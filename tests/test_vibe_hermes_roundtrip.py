"""Round-trip gate must never mistake missing/synthetic inputs for success."""
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from vibe_hbc_roundtrip_matrix import check_fixture,matrix

class RoundtripFixtureTests(unittest.TestCase):
    def test_missing_fixtures_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            out=matrix(Path(temp))
            self.assertEqual(out['versions_registered'],22)
            self.assertEqual(out['exact_matches'],0)
            self.assertFalse(out['runtime_semantics_verified'])
            self.assertTrue(all(row['status']=='missing_fixture' for row in out['results']))

    def test_invalid_fixture_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'hbc100.hbc'
            p.write_bytes(b'not an HBC fixture')
            self.assertEqual(check_fixture(p,100)['status'],'invalid_hbc_header')

    def test_mismatched_declared_version_fails_closed(self):
        import struct
        from vibe_hermes import MAGIC
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'hbc100.hbc'
            raw=bytearray(64)
            struct.pack_into('<QI',raw,0,MAGIC,99)
            p.write_bytes(raw)
            self.assertEqual(check_fixture(p,100)['status'],'version_mismatch')

if __name__=='__main__':
    unittest.main()
