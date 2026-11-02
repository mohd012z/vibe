"""Interoperability matrix on pinned public Talaria Hermes bytecode files.

Genuine fixtures are referenced from an independently cloned repository and
never committed into Vibe. Failures are reported per sample, not hidden.
No APK modifications, dynamic execution, or runtime-semantic assertions.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

VERSIONS=(59,62,74,76,84,85,90,94,96,98)
MAX_FIXTURE=12*1024*1024
TIMEOUT=60

def invoke(args:list[str], env:dict[str,str], timeout:int=TIMEOUT)->tuple[int,str]:
    try:
        proc=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,cwd=None,env=env,
                            timeout=timeout,check=False)
        return proc.returncode,proc.stderr.decode("utf-8","replace")[-300:]
    except (OSError,subprocess.TimeoutExpired) as exc:
        return -1,type(exc).__name__

def verify(toolroot:Path, fixtures:Path, version:int)->dict:
    path=fixtures/f"src/talaria/hbc/hbc{version}/example/index.android.bundle"
    row={"version":version,"source":"Talaria","status":"unverified"}
    if path.is_symlink() or not path.is_file():
        row["status"]="missing_fixture"
        return row
    if not 64<=path.stat().st_size<=MAX_FIXTURE:
        row["status"]="invalid_fixture_size"
        return row
    original=path.read_bytes()
    row.update(size=len(original),input_sha256=hashlib.sha256(original).hexdigest())
    if int.from_bytes(original[8:12],"little")!=version:
        row["status"]="version_mismatch"
        return row
    with tempfile.TemporaryDirectory(prefix=f"vibe-hbc{version}-") as temp:
        root=Path(temp)
        shim=root/"runner.py"
        shim.write_text("""import sys,types
d=types.ModuleType('docopt')
d.docopt=lambda *a,**k: {}
sys.modules['docopt']=d
from hbctool import disasm,asm
disasm(sys.argv[1],sys.argv[2])
asm(sys.argv[2],sys.argv[3])
""",encoding="utf-8")
        rebuilt=root/"rebuilt.bundle"
        env={**os.environ,"PYTHONPATH":str(toolroot.resolve())}
        result,error=invoke([sys.executable,str(shim),str(path.resolve()),
                             str(root/"hasm"),str(rebuilt)],env)
        row["tool_exit"]=result
        if result!=0:
            row.update(status="tool_failed",error=error)
        elif not rebuilt.is_file() or rebuilt.stat().st_size>MAX_FIXTURE:
            row["status"]="rebuilt_missing_or_oversize"
        else:
            output=rebuilt.read_bytes()
            row["rebuilt_sha256"]=hashlib.sha256(output).hexdigest()
            row["status"]="byte_exact" if output==original else "byte_mismatch"
            row["size_delta"]=len(output)-len(original)
        return row

def matrix(toolroot:Path,fixtures:Path)->dict:
    rows=[verify(toolroot,fixtures,v) for v in VERSIONS]
    return {"source":"https://github.com/tuvior/Talaria",
            "versions":len(rows),
            "exact":sum(r["status"]=="byte_exact" for r in rows),
            "failures":sum(r["status"] not in ("byte_exact",) for r in rows),
            "runtime_equivalence":"unverified",
            "rows":rows}

if __name__=="__main__":
    a=argparse.ArgumentParser()
    a.add_argument("patched_toolroot",type=Path)
    a.add_argument("talaria_checkout",type=Path)
    a.add_argument("--strict",action="store_true")
    args=a.parse_args()
    out=matrix(args.patched_toolroot,args.talaria_checkout)
    print(json.dumps(out,indent=2))
    if args.strict and out["failures"]:
        sys.exit(2)
