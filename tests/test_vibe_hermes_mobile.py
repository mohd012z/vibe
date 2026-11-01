"""Regression checks for Vibe's phone-first Hermes UI (no external dependencies)."""
from __future__ import annotations
import http.client
import io
import json
import socket
import struct
import sys
import threading
import unittest
from pathlib import Path
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from vibe_hermes import MAGIC
from vibe_hermes_mobile import LocalServer,disassemble,handler_factory


def make_apk():
    bundle=bytearray(64)
    struct.pack_into('<QI',bundle,0,MAGIC,100)
    struct.pack_into('<I',bundle,32,64)
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('classes.dex',b'dex\\n039\\0')
        z.writestr('assets/index.android.bundle',bundle)
    return out.getvalue()


class MobileServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.token='unit-test-only-not-a-real-token'
        cls.server=LocalServer(('127.0.0.1',0),handler_factory(cls.token))
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def request(self,method,path,payload=b'',headers=None):
        c=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=4)
        hdr={'Host':'127.0.0.1:'+str(self.server.server_port)}
        hdr.update(headers or {})
        c.request(method,path,body=payload,headers=hdr)
        r=c.getresponse()
        body=r.read()
        result=(r.status,body,r.getheader('Content-Security-Policy'))
        c.close()
        return result

    def test_local_page(self):
        status,body,csp=self.request('GET','/')
        self.assertEqual(status,200)
        self.assertIn(b'viewport',body)
        self.assertIn(b'__TOKEN__'.replace(b'__TOKEN__',self.token.encode()),body)
        self.assertIn('default-src',csp)

    def test_host_rebinding_denied(self):
        status,_,_=self.request('GET','/',headers={'Host':'attacker.invalid'})
        self.assertEqual(status,403)

    def test_csrf_denied(self):
        status,_,_=self.request('POST','/api/inspect',make_apk(),{'X-Vibe-Token':'wrong'})
        self.assertEqual(status,403)

    def test_untrusted_origin_denied(self):
        status,_,_=self.request('POST','/api/inspect',make_apk(),
           {'X-Vibe-Token':self.token,'Origin':'https://attacker.invalid'})
        self.assertEqual(status,403)

    def test_invalid_and_missing_body_denied(self):
        status,_,_=self.request('POST','/api/inspect',b'x',
           {'X-Vibe-Token':self.token})
        self.assertEqual(status,400)

    def test_mixed_apk_inspection(self):
        status,body,_=self.request('POST','/api/inspect',make_apk(),
           {'X-Vibe-Token':self.token})
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)['bundles'][0]['hbc_version'],100)

    def test_mobile_pagination_markup(self):
        status,body,_=self.request('GET','/')
        self.assertEqual(status,200)
        for element in (b'id="pageInfo"',b'id="prev"',b'id="next"',
                        b'PAGE_SIZE=50',b'aria-live="polite"'):
            self.assertIn(element,body)

    def test_reject_parallel_analysis(self):
        acquired=self.server.analysis_semaphore.acquire(blocking=False)
        self.assertTrue(acquired)
        try:
            status,body,_=self.request('POST','/api/inspect',make_apk(),
              {'X-Vibe-Token':self.token})
            self.assertEqual(status,429)
            self.assertIn(b'Analysis already active',body)
        finally:
            self.server.analysis_semaphore.release()

    def test_resource_guard_recovers_after_bad_request(self):
        status,_,_=self.request('POST','/api/inspect',b'no',
          {'X-Vibe-Token':self.token})
        self.assertEqual(status,400)
        status,_,_=self.request('POST','/api/inspect',make_apk(),
          {'X-Vibe-Token':self.token})
        self.assertEqual(status,200)

    def test_disassembly_rejects_invalid_entry(self):
        with self.assertRaises(ValueError):
            disassemble(make_apk(),'../../../etc/passwd')


if __name__=='__main__':
    unittest.main()
