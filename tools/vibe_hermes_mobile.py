"""Local-only, read-only Hermes analyzer UI for Vibe staging (stdlib).
No cloud requests, target execution, APK mutation, signing or deployment.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import zipfile

from vibe_hermes import InvalidAPK, inspect_bytes
from vibe_hermes_index import function_index

MAX_DISASM = 48 * 1024 * 1024
MAX_OUTPUT = 16 * 1024 * 1024
MAX_RESULTS = 2000
MAX_MOBILE_UPLOAD = 96 * 1024 * 1024

PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vibe Hermes Inspector</title><style>
:root{color-scheme:dark;font:16px system-ui;background:#0f1521;color:#e8f2ff}
*{box-sizing:border-box}body{max-width:960px;margin:auto;padding:16px}
header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap}
section{padding:14px;margin:12px 0;border-radius:14px;background:#1d293a;border:1px solid #3c526f}
input,button,select{font:inherit;color:inherit;background:#122135;border:1px solid #6f85a3;border-radius:10px;padding:12px;max-width:100%}
input[type=file],input[type=search],select{width:100%}button{background:#255fbc;cursor:pointer}
button:disabled{opacity:.5}small{color:#bccce1}p,pre{overflow-wrap:anywhere}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:8px;border-bottom:1px solid #40536a;overflow-wrap:anywhere}
.scroll{overflow:auto;max-height:390px}@media(max-width:550px){body{padding:10px}h1{font-size:22px}button{width:100%;margin-top:6px}}
</style></head><body>
<header><h1>Hermes Inspector</h1><small>On-device · Read-only · RM0</small></header>
<section><p>Choose an authorized APK. Inspection stays on this device.</p>
<input id="apk" aria-label="APK file" type="file" accept=".apk,.zip">
<p><button id="scan">Inspect APK</button><button id="disasm" disabled>Search Hermes strings/functions</button></p>
<div id="status" role="status" aria-live="polite">No file selected</div></section>
<section id="inventory" hidden><h2>APK inventory</h2><pre id="meta"></pre>
<label for="entry">Hermes bundle</label><select id="entry"></select></section>
<section id="analysis" hidden><h2>String and function search</h2>
<label for="query">Search</label><input id="query" type="search" placeholder="Filter up to 2000 strings and functions">
<p id="counts"></p><nav aria-label="Search results pages"><button id="prev" disabled>Previous</button> <output id="pageInfo" aria-live="polite">Page 1</output> <button id="next" disabled>Next</button></nav><div class="scroll"><table><thead><tr><th>Type</th><th>ID</th><th>Value</th></tr></thead><tbody id="rows"></tbody></table></div></section>
<script>
const token='__TOKEN__';let file=null;let records=[];let pageNumber=0;const PAGE_SIZE=50;const el=s=>document.getElementById(s);
const status=s=>el('status').textContent=s;
async function post(route,entry){
 if(!file)throw Error('Select an APK first');if(file.size>100663296)throw Error('APK exceeds 96 MiB mobile limit');
 const headers={'X-Vibe-Token':token,'Content-Type':'application/octet-stream'};
 if(entry)headers['X-Hermes-Entry']=entry;
 const r=await fetch(route,{method:'POST',headers,body:file,cache:'no-store'});
 const data=await r.json();if(!r.ok)throw Error(data.error||'Inspection error');return data;
}
el('apk').onchange=e=>{file=e.target.files[0]||null;el('disasm').disabled=true;el('inventory').hidden=true;el('analysis').hidden=true;status(file?'Selected: '+file.name:'No file selected')};
el('scan').onclick=async()=>{el('scan').disabled=true;try{status('Inspecting local bytes…');let x=await post('/api/inspect');
 el('meta').textContent=JSON.stringify({sha256:x.sha256,bytes:x.byte_size,technologies:x.technologies,evidence:x.evidence},null,2);
 el('entry').replaceChildren();for(const b of x.bundles||[]){if(b.status!=='hermes')continue;let o=document.createElement('option');o.value=b.entry;o.textContent=b.entry+' · HBC '+b.hbc_version;el('entry').append(o)}
 el('disasm').disabled=!el('entry').options.length;el('inventory').hidden=false;status('Indexed '+x.entries+' ZIP entries');}
 catch(e){status('Error: '+e.message)}finally{el('scan').disabled=false}};
el('disasm').onclick=async()=>{el('disasm').disabled=true;try{status('Analyzing in temporary directory…');
 let x=await post('/api/disasm',el('entry').value);if(x.status!=='ok')throw Error(x.reason||x.status);
 records=[...x.strings.map(v=>['String',v.id,v.value]),...x.functions.map(v=>['Function',v.id,v.name+' · '+v.instruction_count+' instructions · strings '+v.string_refs.join(',')])];pageNumber=0;
 el('analysis').hidden=false;el('counts').textContent=x.string_count+' strings, '+x.function_count+' functions'+(x.truncated?' (results capped)':'');
 render();status('Read-only analysis complete');}catch(e){status('Error: '+e.message)}finally{el('disasm').disabled=false}};
function render(){let q=el('query').value.toLowerCase();let body=el('rows');body.replaceChildren();
 let matches=records.filter(r=>String(r[2]).toLowerCase().includes(q));let totalPages=Math.max(1,Math.ceil(matches.length/PAGE_SIZE));
 pageNumber=Math.max(0,Math.min(pageNumber,totalPages-1));let start=pageNumber*PAGE_SIZE;
 for(let rec of matches.slice(start,start+PAGE_SIZE)){let row=document.createElement('tr');for(let v of rec){let cell=document.createElement('td');cell.textContent=String(v);row.append(cell)}body.append(row)}
 el('pageInfo').textContent='Page '+(pageNumber+1)+' / '+totalPages+' ('+matches.length+' results)';
 el('prev').disabled=pageNumber===0;el('next').disabled=pageNumber>=totalPages-1;
}
el('prev').onclick=()=>{pageNumber--;render()};
el('next').onclick=()=>{pageNumber++;render()};
el('query').oninput=()=>{pageNumber=0;render()};
</script></body></html>'''


def disassemble(apk: bytes, entry: str) -> dict:
    inventory = inspect_bytes(apk)
    found = [row for row in inventory['bundles']
             if row['entry'] == entry and row['status'] == 'hermes']
    if len(found) != 1:
        raise InvalidAPK('Invalid or unverified Hermes entry')
    bundle = found[0]
    if not bundle['hbctool_0_1_7_registered']:
        return {'status': 'unsupported', 'reason': 'Unregistered HBC version'}
    if 87 <= bundle['hbc_version'] <= 100 and bundle.get('layout_preflight') != 'bigint_sections_empty':
        return {'status': 'unsupported', 'reason': 'Unverified or unsupported BigInt section layout'}
    if bundle['size'] > MAX_DISASM:
        raise InvalidAPK('Hermes candidate exceeds local analysis limit')
    if not shutil.which('hbctool'):
        return {'status': 'unavailable', 'reason': 'Local hbctool is not installed'}
    with tempfile.TemporaryDirectory(prefix='vibe-hbc-') as d:
        raw = Path(d)/'input.bundle'
        out = Path(d)/'hasm'
        with zipfile.ZipFile(io.BytesIO(apk)) as z, z.open(entry) as stream, raw.open('wb') as dest:
            while True:
                block = stream.read(65536)
                if not block:
                    break
                dest.write(block)
                if dest.tell() > MAX_DISASM:
                    raise InvalidAPK('Hermes candidate exceeds local analysis limit')
        try:
            proc = subprocess.run(['hbctool','disasm',str(raw),str(out)],
                                  capture_output=True, stdin=subprocess.DEVNULL,
                                  timeout=30, cwd=d, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return {'status':'error', 'reason':'Local disassembler failed or timed out'}
        if proc.returncode:
            return {'status':'error', 'reason':'Local disassembler returned an error'}
        strings_path = out/'string.json'
        inst_path = out/'instruction.hasm'
        if not strings_path.is_file() or not inst_path.is_file():
            return {'status':'error', 'reason':'Expected analysis outputs missing'}
        if strings_path.stat().st_size > MAX_OUTPUT or inst_path.stat().st_size > MAX_OUTPUT:
            return {'status':'error', 'reason':'Analysis output size limit exceeded'}
        try:
            strings = json.loads(strings_path.read_text('utf-8'))
            if not isinstance(strings,list):
                raise ValueError('Invalid string table')
            text = inst_path.read_text('utf-8')
            indexed = function_index(text)
        except (OSError,UnicodeError,ValueError):
            return {'status':'error','reason':'Malformed analysis output'}
        return {'status':'ok', 'string_count':len(strings), 'function_count':indexed['function_count'],
                'strings':[{'id':v.get('id'),'value':str(v.get('value',''))[:1024]} for v in strings[:MAX_RESULTS] if isinstance(v,dict)],
                'functions':indexed['functions'],
                'references_scanned':indexed['references_scanned'],
                'truncated':len(strings)>MAX_RESULTS or indexed['truncated']}


def handler_factory(token: str):
    class Handler(BaseHTTPRequestHandler):
        def _json(self,status,data):
            body=json.dumps(data).encode('utf-8')
            self.send_response(status)
            for key,value in {'Content-Type':'application/json; charset=utf-8',
                              'Content-Length':str(len(body)),
                              'Cache-Control':'no-store',
                              'X-Content-Type-Options':'nosniff'}.items():
                self.send_header(key,value)
            self.end_headers()
            self.wfile.write(body)

        def _trusted(self):
            return self.headers.get('Host') in (
                f'127.0.0.1:{self.server.server_port}',
                f'localhost:{self.server.server_port}')

        def do_GET(self):
            if not self._trusted():
                return self._json(403,{'error':'Host rejected'})
            if self.path!='/':
                return self._json(404,{'error':'Not found'})
            page=PAGE.replace('__TOKEN__',token).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Content-Length',str(len(page)))
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(page)

        def do_POST(self):
            if not self._trusted():
                return self._json(403,{'error':'Host rejected'})
            if self.path not in ('/api/inspect','/api/disasm'):
                return self._json(404,{'error':'Not found'})
            if self.headers.get('X-Vibe-Token')!=token:
                return self._json(403,{'error':'Invalid local session'})
            if self.headers.get('Origin','') not in ('',
                  f'http://127.0.0.1:{self.server.server_port}',
                  f'http://localhost:{self.server.server_port}'):
                return self._json(403,{'error':'Origin rejected'})
            if not self.server.analysis_semaphore.acquire(blocking=False):
                return self._json(429,{'error':'Analysis already active; retry after completion'})
            try:
                self.connection.settimeout(20)
                length=int(self.headers.get('Content-Length','-1'))
                if not 22<=length<=MAX_MOBILE_UPLOAD:
                    raise InvalidAPK('Invalid request size')
                raw=self.rfile.read(length)
                if len(raw)!=length:
                    raise InvalidAPK('Truncated upload')
                value=(inspect_bytes(raw) if self.path=='/api/inspect'
                       else disassemble(raw,self.headers.get('X-Hermes-Entry','')))
                return self._json(200,value)
            except InvalidAPK as e:
                return self._json(400,{'error':str(e)[:150]})
            except Exception:
                return self._json(400,{'error':'Inspection failed safely'})
            finally:
                self.server.analysis_semaphore.release()
    return Handler


class LocalServer(ThreadingHTTPServer):
    daemon_threads=True
    request_queue_size=8
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.analysis_semaphore=threading.BoundedSemaphore(1)


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--port',type=int,default=8765)
    args=p.parse_args()
    token=secrets.token_urlsafe(32)
    with LocalServer(('127.0.0.1',args.port),handler_factory(token)) as server:
        print('Vibe local Hermes inspector: http://127.0.0.1:'+str(server.server_port),flush=True)
        server.serve_forever()


if __name__=='__main__':
    main()
