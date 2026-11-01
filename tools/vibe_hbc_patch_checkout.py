"""SHA-pinned, rollback-protected source repair for a separate HBC-Tool checkout.
The upstream repository is never modified. Source changes require exact blobs.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

EXPECTED={59:"09051d83731d88f67d422ac069b42f5c3a9d19d3",
          99:"83420899eb38820ea65bbcc82b91c9f5322fbc4c",
          100:"22a18c05fa707bfbfb0db421cd608b82216d495a"}
OLD="""        if isUTF16:
            s = list(bytes.fromhex(val))
            l = len(s) // 2
        else:
            l = len(val)
            s = val.encode("utf-8")

        assert l <= length, "Overflowed string length is not supported yet."

        memcpy(stringStorage, s, offset, len(s))"""
NEW="""        if not isinstance(val, str):
            raise TypeError("Replacement must be a string")
        if isUTF16:
            s = bytes.fromhex(val)
            if len(s) % 2:
                raise ValueError("Incomplete UTF-16 code unit")
            capacity = length * 2
        else:
            s = val.encode("utf-8")
            capacity = length
        if len(s) != capacity:
            raise ValueError("Replacement must have the same encoded byte length")
        if offset < 0 or offset + capacity > len(stringStorage):
            raise ValueError("String storage offset out of bounds")
        memcpy(stringStorage, s, offset, len(s))"""

def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()

def transform(content: str, version: int) -> str:
    if version not in EXPECTED or content.count(OLD)!=1:
        raise ValueError("Source does not match an audited HBC module")
    text=content.replace(OLD,NEW,1)
    if version in (59,100):
        old=74 if version==59 else 99
        original=f"    def getVersion(self):\n        return {old}\n"
        if text.count(original)!=1:
            raise ValueError("Unexpected version getter")
        text=text.replace(original,f"    def getVersion(self):\n        return {version}\n",1)
    return text

def _stage(folder:Path,data:bytes,mode:int)->Path:
    fd,name=tempfile.mkstemp(prefix=".hbc-stage-",dir=folder)
    path=Path(name)
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(data);f.flush();os.fsync(f.fileno())
        os.chmod(path,stat.S_IMODE(mode))
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise

def patch(root:Path)->dict:
    root=Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Checkout must be an actual directory")
    root=root.resolve()
    backup=root/".hbc-repair-backup"
    if backup.exists() or backup.is_symlink():
        raise ValueError("Backup already exists; refusing overwrite")
    records=[]
    for version,sha in EXPECTED.items():
        file=root/"hbctool"/"hbc"/f"hbc{version}"/"__init__.py"
        if file.is_symlink() or not file.is_file():
            raise ValueError(f"Missing or symlinked HBC{version} source")
        raw=file.read_bytes()
        if blob_sha(raw)!=sha:
            raise ValueError(f"HBC{version} Git blob SHA mismatch")
        altered=transform(raw.decode("utf-8"),version).encode("utf-8")
        compile(altered,str(file),"exec")
        records.append((file,raw,altered,file.stat().st_mode,version))
    staged={}
    replaced=[]
    try:
        for file,raw,altered,mode,version in records:
            staged[file]=_stage(file.parent,altered,mode)
        backup.mkdir(exist_ok=False)
        manifest=[]
        for file,raw,altered,mode,version in records:
            saved=backup/f"hbc{version}.py.orig"
            with saved.open("xb") as stream:
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            if saved.read_bytes()!=raw:
                raise OSError("Backup checksum failure")
            manifest.append({"version":version,
                             "source":str(file.relative_to(root)),
                             "backup":saved.name,
                             "sha256":hashlib.sha256(raw).hexdigest()})
        with (backup/"manifest.json").open("x") as f:
            json.dump({"format":"hbc-backup-v1","files":manifest},f,indent=2)
            f.flush();os.fsync(f.fileno())
        for file,raw,altered,mode,version in records:
            os.replace(staged[file],file)
            staged.pop(file)
            replaced.append(file)
        return {"changed":[str(p.relative_to(root)) for p in replaced],
                "backup":str(backup)}
    except BaseException as exc:
        failures=[]
        for file,raw,altered,mode,version in records:
            if file not in replaced:
                continue
            try:
                restored=_stage(file.parent,raw,mode)
                os.replace(restored,file)
            except OSError as rollback_exc:
                failures.append(type(rollback_exc).__name__+":"+str(file))
        if failures:
            raise RuntimeError("Rollback incomplete: "+", ".join(failures)) from exc
        raise
    finally:
        for path in staged.values():
            path.unlink(missing_ok=True)

if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("checkout",type=Path)
    a=p.parse_args()
    print(json.dumps(patch(a.checkout),indent=2))
