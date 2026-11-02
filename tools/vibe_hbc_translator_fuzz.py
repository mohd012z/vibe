"""Bounded deterministic opcode fuzz harness for SHA-pinned, patched translators."""
from __future__ import annotations
import importlib
import random
import sys
import types
from pathlib import Path
from vibe_hbc_patch_all import VERSIONS,PINNED,git

def verify(root:Path)->dict:
    if git(["rev-parse","HEAD"],root)!=PINNED:
        raise ValueError("Unexpected checkout")
    sys.path.insert(0,str(root.resolve()))
    shim=types.ModuleType("docopt");shim.docopt=lambda *a,**k: {}
    sys.modules.setdefault("docopt",shim)
    cases=0
    errors=0
    for version in VERSIONS:
        rng=random.Random(version+20261101)
        module=importlib.import_module(f"hbctool.hbc.hbc{version}.translator")
        for n in range(180):
            payload=bytes(rng.randrange(256) for _ in range(rng.randrange(0,80)))
            cases+=1
            try:result=module.disassemble(payload)
            except ValueError:errors+=1
            else:
                if not isinstance(result,list):
                    raise AssertionError(f"HBC{version} returned malformed decode result")
        try:
            module.disassemble(b"\0"*(8*1024*1024+1))
        except ValueError:
            pass
        else:raise AssertionError(f"HBC{version} accepted oversized function")
        try:
            module.disassemble(object())
        except TypeError:pass
        else:raise AssertionError("Non-bytecode accepted")
    return {"versions":len(VERSIONS),"random_inputs":cases,
            "rejected_as_valueerror":errors,
            "crash_or_unexpected_exception":0,"status":"PASS",
            "runtime_semantics":"unverified"}

if __name__=="__main__":
    import argparse,json
    parser=argparse.ArgumentParser()
    parser.add_argument("checkout",type=Path)
    args=parser.parse_args()
    print(json.dumps(verify(args.checkout),indent=2))
