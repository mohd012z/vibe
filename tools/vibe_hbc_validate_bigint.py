"""Deterministic validation for the isolated v87-100 BigInt section codec."""
from __future__ import annotations
import argparse
import importlib
import io
import sys
from pathlib import Path
import types
from vibe_hbc_bigint_patch import VERSIONS
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
    return {"versions":len(VERSIONS),"codec_cases":count,"status":"PASS",
            "genuine_nonempty_bigint_roundtrip":"unverified"}

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("source_checkout",type=Path)
    args=p.parse_args()
    print(validate(args.source_checkout))
