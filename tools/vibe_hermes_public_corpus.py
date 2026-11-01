"""Independent interoperability smoke gate on public P1sec/Hermes-dec bytecode fixtures.

Use original cloned tools, not fixtures bundled with this repository. Only
structural/function-count parity is tested; semantic parity is never asserted.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from vibe_hbc_opcode_parity import parity
from vibe_hbc_official_oracle import compare_to_official

FIXTURES={"84":"tests/version-84/sample.hbc",
          "94":"tests/version-94/sample.hbc",
          "99":"tests/version-99-202602/sample.hbc"}

def run(argv:list[str], *, timeout:int=30, env:dict|None=None):
    try:
        p=subprocess.run(argv,stdin=subprocess.DEVNULL,
                         capture_output=True,timeout=timeout,
                         check=False,env=env)
        return {"exit":p.returncode,"stderr":p.stderr.decode(errors="replace")[-240:],
                "stdout":p.stdout.decode(errors="replace")[-150:]}
    except (OSError,subprocess.TimeoutExpired) as e:
        return {"exit":-1,"error":type(e).__name__}

def check(toolroot: Path, p1root: Path, version:str)->dict:
    input_file=(p1root/FIXTURES[version]).resolve()
    if not input_file.is_file() or input_file.is_symlink() or input_file.stat().st_size>8*1024*1024:
        return {"version":version,"status":"fixture_unavailable"}
    orig=input_file.read_bytes()
    header=int.from_bytes(orig[8:12],"little") if len(orig)>=12 else -1
    if header!=int(version):
        return {"version":version,"status":"unexpected_fixture_version","reported":header}
    out={"version":version,"fixture_sha256":hashlib.sha256(orig).hexdigest(),
         "size":len(orig),"semantic_equivalence":"unverified"}
    with tempfile.TemporaryDirectory(prefix="vibe-hermes-corpus-") as tmp:
        temp=Path(tmp)
        hbcout=temp/"hasm"
        rebuilt=temp/"rebuilt.hbc"
        shim=(temp/"driver.py")
        shim.write_text("""import sys,types
d=types.ModuleType('docopt')
d.docopt=lambda *args,**kwargs: {}
sys.modules['docopt']=d
import hbctool
hbctool.disasm(sys.argv[1],sys.argv[2])
hbctool.asm(sys.argv[2],sys.argv[3])
""",encoding="utf-8")
        env=dict(os.environ)
        env["PYTHONPATH"]=str(toolroot.resolve())
        out["hbctool"]=run([sys.executable,str(shim),str(input_file),str(hbcout),str(rebuilt)],env=env,timeout=90 if version=="84" else 30)
        p1out=temp/"p1.hasm"
        env_p1=dict(os.environ)
        env_p1["PYTHONPATH"]=str((p1root/"src").resolve())
        out["hermes_dec"]=run([sys.executable,str(p1root/"hbc-disassembler"),
                               str(input_file),str(p1out)],env=env_p1,timeout=90 if version=="84" else 30)
        if rebuilt.is_file() and rebuilt.stat().st_size<8*1024*1024:
            newer=rebuilt.read_bytes()
            out["reassembled_sha256"]=hashlib.sha256(newer).hexdigest()
            out["byte_identical"]=newer==orig
        else:
            out["byte_identical"]=False
        if (hbcout/"instruction.hasm").is_file() and p1out.is_file():
            a=(hbcout/"instruction.hasm").read_text("utf-8",errors="replace")
            b=p1out.read_text("utf-8",errors="replace")
            count_a=len(re.findall(r"^Function<",a,re.MULTILINE))
            count_b=len(re.findall(r"^=> \[(?:Function|Generator function|Async function) #",b,re.MULTILINE))
            out["function_counts"]={"hbctool":count_a,"hermes_dec":count_b}
            out["structural_count_agreement"]=count_a==count_b
            out["instruction_parity"]=parity(hbcout/"instruction.hasm",p1out)
            if version in ("94","99"):
                out["official_oracle"]=compare_to_official(orig,hbcout/"instruction.hasm",p1out,input_file.with_name("sample.hermes_raw_hasm"))
        else:
            out["structural_count_agreement"]=False
        out["status"]=("byte_exact_and_function_count_agreement"
                       if out["byte_identical"] and out["structural_count_agreement"]
                       else "not_verified_or_mismatch")
    return out

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("patched_hbctool",type=Path)
    p.add_argument("hermes_dec",type=Path)
    a=p.parse_args()
    rows=[check(a.patched_hbctool,a.hermes_dec,v) for v in FIXTURES]
    print(json.dumps({"fixtures":rows,"semantic_parity":"unverified"},indent=2))
    if any(r["status"]=="fixture_unavailable" for r in rows):
        sys.exit(3)
    if any(r["hbctool"]["exit"]!=0 or r["hermes_dec"]["exit"]!=0
           for r in rows):
        sys.exit(2)
