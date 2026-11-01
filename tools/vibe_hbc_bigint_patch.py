"""Experimental, fail-closed BigInt binary section repair for HBC87-100.

Run ONLY after vibe_hbc_patch_all.py on a separate pinned checkout.
The parser must use the same declared sizes on assembly. Tested independently
with synthetic sections; genuine nonempty BigInt fixture validation is a
separate gate. Vibe UI still rejects nonempty BigInt until that gate passes.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import os
import subprocess
from vibe_hbc_patch_all import PINNED, stage, git

VERSIONS=(87,88,89,90,91,92,93,94,95,96,97,98,99,100)
MAX_COUNT=100000
MAX_STORAGE=8*1024*1024
INSERT_FUNCTIONS = '''
def _read_bigint_sections(f, header):
    count = header["bigIntCount"]
    size = header["bigIntStorageSize"]
    if count > 100000 or size > 8 * 1024 * 1024:
        raise ValueError("BigInt section exceeds parser limits")
    table = []
    for _ in range(count):
        offset = readuint(f, bits=32)
        length = readuint(f, bits=32)
        if offset > size or length > size - offset:
            raise ValueError("BigInt table entry outside declared storage")
        table.append({"offset": offset, "length": length})
    align(f)
    data = read(f, ["uint", 8, size])
    align(f)
    return table, data


def _write_bigint_sections(f, obj, header):
    count = header["bigIntCount"]
    size = header["bigIntStorageSize"]
    table = obj["bigIntTable"]
    data = obj["bigIntStorage"]
    if count > 100000 or size > 8 * 1024 * 1024:
        raise ValueError("BigInt section exceeds writer limits")
    if len(table) != count or len(data) != size:
        raise ValueError("BigInt table/storage size mismatches header")
    for entry in table:
        offset, length = entry["offset"], entry["length"]
        if not isinstance(offset, int) or not isinstance(length, int) or (
            offset < 0 or length < 0 or offset > size or length > size - offset
        ):
            raise ValueError("Invalid BigInt table entry")
        writeuint(f, offset, bits=32)
        writeuint(f, length, bits=32)
    align(f)
    write(f, data, ["uint", 8, size])
    align(f)


'''
PARSE_ANCHOR='    # Segment 11: RegExpTable\n    regExpTable = []'
EXPORT_ANCHOR='    # Segment 11: RegExpTable\n    regExpTable = obj["regExpTable"]'
PARSE_BLOCK='''    # Preserve BigInt table and storage in canonical segment order.
    bigIntTable, bigIntStorage = _read_bigint_sections(f, header)
    obj["bigIntTable"] = bigIntTable
    obj["bigIntStorage"] = bigIntStorage

'''
EXPORT_BLOCK='''    # Re-emit validated BigInt sections without changing declared sizes.
    _write_bigint_sections(f, obj, header)

'''

def patch(root:Path,replace=os.replace)->dict:
    root=Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Unsafe source checkout directory")
    root=root.resolve()
    if git(["rev-parse","HEAD"],root)!=PINNED:
        raise ValueError("Not pinned HBC-Tool revision")
    backup=root/".vibe-hbc-bigint-backup-v1"
    if backup.exists() or backup.is_symlink():
        raise ValueError("BigInt backup already exists")
    modifications=[]
    for version in VERSIONS:
        relative=f"hbctool/hbc/hbc{version}/parser.py"
        path=root/relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or symlinked parser")
        original=path.read_bytes()
        actual=hashlib.sha1(b"blob "+str(len(original)).encode()+b"\0"+original).hexdigest()
        if actual!=git(["rev-parse",f"HEAD:{relative}"],root):
            raise ValueError("Pinned parser blob mismatch")
        source=original.decode("utf-8")
        if source.count("def parse(f):")!=1 or source.count(PARSE_ANCHOR)!=1 or source.count(EXPORT_ANCHOR)!=1:
            raise ValueError("Unexpected parser structure")
        updated=source.replace("def parse(f):", INSERT_FUNCTIONS+"def parse(f):",1)
        updated=updated.replace(PARSE_ANCHOR,PARSE_BLOCK+PARSE_ANCHOR,1)
        updated=updated.replace(EXPORT_ANCHOR,EXPORT_BLOCK+EXPORT_ANCHOR,1)
        compile(updated,str(path),"exec")
        modifications.append((path,original,updated.encode("utf-8"),path.stat().st_mode))
    staged={}
    replaced=[]
    try:
        for path,_,out,mode in modifications:
            staged[path]=stage(path,out,mode)
        backup.mkdir(mode=0o700)
        manifest=[]
        for path,original,_,_ in modifications:
            dest=backup/(path.parent.name+".parser.py.orig")
            with dest.open("xb") as f:
                f.write(original);f.flush();os.fsync(f.fileno())
            sha=hashlib.sha256(original).hexdigest()
            if hashlib.sha256(dest.read_bytes()).hexdigest()!=sha:
                raise OSError("Backup verification failure")
            manifest.append({"path":str(path.relative_to(root)),"sha256":sha,"backup":dest.name})
        with (backup/"manifest.json").open("x") as f:
            json.dump({"source_commit":PINNED,"files":manifest},f)
            f.flush();os.fsync(f.fileno())
        for path,_,_,_ in modifications:
            replace(staged[path],path)
            staged.pop(path)
            replaced.append(path)
        return {"patched_bigint_parsers":len(replaced),"backup":str(backup),"status":"experimental"}
    except BaseException as error:
        failures=[]
        for path,original,_,mode in reversed(modifications):
            if path not in replaced:continue
            try:
                restored=stage(path,original,mode)
                os.replace(restored,path)
            except OSError:failures.append(str(path))
        if failures:
            raise RuntimeError("Rollback incomplete: "+", ".join(failures)) from error
        raise
    finally:
        for path in staged.values():
            path.unlink(missing_ok=True)

if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("checkout",type=Path)
    args=p.parse_args()
    print(json.dumps(patch(args.checkout),indent=2))
