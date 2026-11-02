"""Audit-pinned disassembler error normalization for all 22 opcode translators.

Reject malformed/truncated instruction streams as ValueError, rather than raw
IndexError/KeyError/struct.error. Does not change valid decoded instructions.
Applied only to temporary source checkouts; not upstream and not an APK patch.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
from vibe_hbc_patch_all import PINNED,VERSIONS,git,stage

PREAMBLE='''def disassemble(bc):
    if not isinstance(bc, (bytes, bytearray, list)):
        raise TypeError("Bytecode must be bytes or byte list")
    if len(bc) > 8 * 1024 * 1024:
        raise ValueError("Function bytecode exceeds safe decode limit")
    try:
        return _disassemble_unchecked(bc)
    except (IndexError, KeyError, struct.error, ValueError, OverflowError) as exc:
        raise ValueError("Malformed Hermes opcode or truncated operand") from exc


def _disassemble_unchecked(bc):'''

def patch(root:Path,replace=os.replace)->dict:
    root=Path(root)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("Invalid or symlinked source checkout")
    root=root.resolve()
    if git(["rev-parse","HEAD"],root)!=PINNED:
        raise ValueError("Unexpected source commit")
    backup=root/".vibe-hbc-translator-backup-v1"
    if backup.exists() or backup.is_symlink():
        raise ValueError("Existing translator backup")
    entries=[]
    for version in VERSIONS:
        rel=f"hbctool/hbc/hbc{version}/translator.py"
        path=root/rel
        if path.is_symlink() or not path.is_file():
            raise ValueError("Invalid translator path")
        original=path.read_bytes()
        digest=hashlib.sha1(b"blob "+str(len(original)).encode()+b"\0"+original).hexdigest()
        if digest!=git(["rev-parse",f"HEAD:{rel}"],root):
            raise ValueError("Translator has unexpected changes")
        text=original.decode("utf-8")
        if text.count("def disassemble(bc):")!=1 or "import json" not in text:
            raise ValueError("Unknown translator format")
        updated=text.replace("import json","import json\nimport struct",1)
        updated=updated.replace("def disassemble(bc):",PREAMBLE,1)
        compile(updated,str(path),"exec")
        entries.append((path,original,updated.encode("utf-8"),path.stat().st_mode))
    stages={}
    replaced=[]
    try:
        for path,original,updated,mode in entries:
            stages[path]=stage(path,updated,mode)
        backup.mkdir(mode=0o700)
        manifest=[]
        for path,original,updated,mode in entries:
            dest=backup/(path.parent.name+".translator.py.orig")
            with dest.open("xb") as out:
                out.write(original);out.flush();os.fsync(out.fileno())
            sha=hashlib.sha256(original).hexdigest()
            if hashlib.sha256(dest.read_bytes()).hexdigest()!=sha:
                raise OSError("Corrupt translator backup")
            manifest.append({"path":str(path.relative_to(root)),
                             "backup":dest.name,"sha256":sha})
        with (backup/"manifest.json").open("x") as f:
            json.dump({"pinned_commit":PINNED,"files":manifest},f)
            f.flush();os.fsync(f.fileno())
        for path,_,_,_ in entries:
            replace(stages[path],path);stages.pop(path);replaced.append(path)
        return {"patched_translators":len(entries),"backup":str(backup),
                "status":"experimental"}
    except BaseException as exc:
        failed=[]
        for path,raw,_,mode in reversed(entries):
            if path not in replaced:continue
            try:
                orig=stage(path,raw,mode);os.replace(orig,path)
            except OSError:failed.append(str(path))
        if failed:raise RuntimeError("Translator rollback incomplete: "+", ".join(failed)) from exc
        raise
    finally:
        for path in stages.values():path.unlink(missing_ok=True)

if __name__=="__main__":
    import argparse
    a=argparse.ArgumentParser()
    a.add_argument("checkout",type=Path)
    args=a.parse_args()
    print(json.dumps(patch(args.checkout),indent=2))
