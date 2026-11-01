"""Experimental FunctionSource table repair for HBC84-100.

Patches only an audited clean parser or the exact BigInt experimental patch
derived from the pinned source. Preserves original files with SHA256 backups.
Do not merge/ship until genuine opcode-level differential testing passes.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
from vibe_hbc_patch_all import PINNED, git, stage
from vibe_hbc_bigint_patch import (VERSIONS as BIG_VERSIONS,
  INSERT_FUNCTIONS, PARSE_ANCHOR, EXPORT_ANCHOR, PARSE_BLOCK, EXPORT_BLOCK)

VERSIONS=(84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100)
PARSE_INSERT='''    # Function source table, following CommonJS modules.
    functionSourceTable=[]
    source_count=header["functionSourceCount"]
    if source_count>100000:
        raise ValueError("Function source count exceeds safe limit")
    for _ in range(source_count):
        first=readuint(f,bits=32)
        second=readuint(f,bits=32)
        functionSourceTable.append({"first":first,"second":second})
    obj["functionSourceTable"]=functionSourceTable
    align(f)

'''
EXPORT_INSERT='''    # Preserve the FunctionSource table entries exactly.
    functionSourceTable=obj["functionSourceTable"]
    if header["functionSourceCount"]>100000 or len(functionSourceTable)!=header["functionSourceCount"]:
        raise ValueError("Invalid function-source table length")
    for entry in functionSourceTable:
        writeuint(f,entry["first"],bits=32)
        writeuint(f,entry["second"],bits=32)
    align(f)

'''

def expected_bigint_source(original:str)->str:
    text=original.replace("def parse(f):",INSERT_FUNCTIONS+"def parse(f):",1)
    text=text.replace(PARSE_ANCHOR,PARSE_BLOCK+PARSE_ANCHOR,1)
    text=text.replace(EXPORT_ANCHOR,EXPORT_BLOCK+EXPORT_ANCHOR,1)
    return text

def patch(root:Path,replace=os.replace)->dict:
    root=Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Invalid source checkout")
    root=root.resolve()
    if git(["rev-parse","HEAD"],root)!=PINNED:
        raise ValueError("Not pinned upstream commit")
    backup=root/".vibe-hbc-functionsource-backup-v1"
    if backup.exists() or backup.is_symlink():
        raise ValueError("Function-source backup already exists")
    changes=[]
    for v in VERSIONS:
        rel=f"hbctool/hbc/hbc{v}/parser.py"
        path=root/rel
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or unsafe parser")
        proc=subprocess.run(["git","-C",str(root),"show",f"HEAD:{rel}"],
              stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
        original=proc.stdout.decode("utf-8")
        expected=expected_bigint_source(original) if v in BIG_VERSIONS else original
        before=path.read_bytes()
        if before.decode("utf-8")!=expected:
            raise ValueError(f"Unexpected parser modifications in HBC{v}")
        if before.count(b'obj["instOffset"] = f.tell()')!=1 or before.count(b'    # Write remaining')!=1:
            raise ValueError("Unexpected function-source parser anchors")
        update=expected.replace('    obj["instOffset"] = f.tell()',PARSE_INSERT+'    obj["instOffset"] = f.tell()',1)
        update=update.replace('    # Write remaining',EXPORT_INSERT+'    # Write remaining',1)
        compile(update,str(path),"exec")
        changes.append((path,before,update.encode("utf-8"),path.stat().st_mode))
    staged={}
    replaced=[]
    try:
        for path,_,updated,mode in changes:
            staged[path]=stage(path,updated,mode)
        backup.mkdir(mode=0o700)
        manifest=[]
        for path,before,_,_ in changes:
            original_copy=backup/(path.parent.name+".parser.py.orig")
            with original_copy.open("xb") as f:
                f.write(before);f.flush();os.fsync(f.fileno())
            sha=hashlib.sha256(before).hexdigest()
            if hashlib.sha256(original_copy.read_bytes()).hexdigest()!=sha:
                raise OSError("FunctionSource backup checksum mismatch")
            manifest.append({"path":str(path.relative_to(root)),"sha256":sha,"backup":original_copy.name})
        with (backup/"manifest.json").open("x") as f:
            json.dump({"pinned_sha":PINNED,"files":manifest},f)
            f.flush();os.fsync(f.fileno())
        for path,_,_,_ in changes:
            replace(staged[path],path);staged.pop(path);replaced.append(path)
        return {"patched_function_source_parsers":len(replaced),"status":"experimental","backup":str(backup)}
    except BaseException as error:
        failures=[]
        for path,before,_,mode in reversed(changes):
            if path not in replaced:continue
            try:
                old=stage(path,before,mode)
                os.replace(old,path)
            except OSError:failures.append(str(path))
        if failures:raise RuntimeError("FunctionSource rollback incomplete: "+", ".join(failures)) from error
        raise
    finally:
        for path in staged.values():path.unlink(missing_ok=True)

if __name__=="__main__":
    import argparse
    a=argparse.ArgumentParser()
    a.add_argument("checkout",type=Path)
    args=a.parse_args()
    print(json.dumps(patch(args.checkout),indent=2))
