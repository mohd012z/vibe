"""Deterministic validation for the isolated v87-100 BigInt section codec."""
from __future__ import annotations
import argparse
import importlib
import io
import sys
from pathlib import Path
import types
import tempfile
import shutil
import os
import subprocess
from vibe_hbc_bigint_patch import VERSIONS, patch
from vibe_hbc_patch_all import git, PINNED

def validate(root:Path)->dict:
    if git(["rev-parse","HEAD"],root)!=PINNED:
        raise ValueError("Not pinned upstream commit")
    sys.path.insert(0,str(root.resolve()))
    shim=types.ModuleType("docopt")
    shim.docopt=lambda *a,**k: {}
    sys.modules.setdefault("docopt",shim)
    from hbctool.util import BitWriter,BitReader
    count=0
    for version in VERSIONS:
        mod=importlib.import_module(f"hbctool.hbc.hbc{version}.parser")
        cases=[
          ({"bigIntCount":0,"bigIntStorageSize":0},[],[]),
          ({"bigIntCount":1,"bigIntStorageSize":1},[{"offset":0,"length":1}],[0x6a]),
          ({"bigIntCount":2,"bigIntStorageSize":3},
           [{"offset":0,"length":2},{"offset":2,"length":1}],[1,2,3])
        ]
        for header,table,storage in cases:
            buf=io.BytesIO()
            writer=BitWriter(buf)
            mod._write_bigint_sections(writer,{"bigIntTable":table,"bigIntStorage":storage},header)
            writer.flush()
            encoded=buf.getvalue()
            reader=BitReader(io.BytesIO(encoded))
            recovered_table,recovered_storage=mod._read_bigint_sections(reader,header)
            assert recovered_table==table,(version,header)
            assert recovered_storage==storage,(version,header)
            assert len(encoded)%4==0,(version,len(encoded))
            count+=1
        bad=[
          ({"bigIntCount":1,"bigIntStorageSize":1},[{"offset":0,"length":2}],[1]),
          ({"bigIntCount":1,"bigIntStorageSize":1},[{"offset":0,"length":1}],[]),
          ({"bigIntCount":100001,"bigIntStorageSize":0},[],[]),
          ({"bigIntCount":0,"bigIntStorageSize":8*1024*1024+1},[],[])
        ]
        for header,table,storage in bad:
            try:
                mod._write_bigint_sections(BitWriter(io.BytesIO()),
                    {"bigIntTable":table,"bigIntStorage":storage},header)
            except (ValueError,TypeError): pass
            else:raise AssertionError(f"HBC{version} allowed corrupt BigInt section")
            count+=1
    # Fault-inject a crash on second atomic replacement in a separate checkout.
    with tempfile.TemporaryDirectory(prefix="vibe-bigint-rollback-") as work:
        scratch=Path(work)/"checkout"
        shutil.copytree(root,scratch,symlinks=True,
             ignore=shutil.ignore_patterns(".vibe-hbc-bigint-backup-v1"))
        originals={}
        for version in VERSIONS:
            rel=f"hbctool/hbc/hbc{version}/parser.py"
            proc=subprocess.run(["git","-C",str(root),"show",f"HEAD:{rel}"],
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
            path=scratch/rel
            path.write_bytes(proc.stdout)
            originals[path]=proc.stdout
        counter=[0]
        def fail_second(src,dst):
            counter[0]+=1
            if counter[0]==2:
                raise OSError("injected replacement failure")
            return os.replace(src,dst)
        try:
            patch(scratch,replace=fail_second)
        except OSError as exc:
            assert "injected" in str(exc),str(exc)
        else:
            raise AssertionError("Fault-injection did not trigger")
        assert counter[0]==2
        for path,original in originals.items():
            assert path.read_bytes()==original,("rollback mismatch",path)
        assert not list(scratch.rglob(".vibe-hbc-stage-*"))
    print("PASS: BigInt patch mid-replacement rollback recovered all original parser bytes")
    return {"versions":len(VERSIONS),"codec_cases":count,"status":"PASS",
            "genuine_nonempty_bigint_roundtrip":"unverified"}

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("source_checkout",type=Path)
    args=p.parse_args()
    print(validate(args.source_checkout))
