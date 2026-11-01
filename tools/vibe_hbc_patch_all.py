"""Offline SHA-verified patch for all 22 registered Kirlif/HBC-Tool modules.
Operates ONLY on a clean checkout of audited commit; no upstream writes.
Backups and mutation rollback are all-or-nothing at file level.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

PINNED = "eaf70a8700380f35e39e1bdbcaac01a3c49a63b0"
VERSIONS = (59, 62, 74, 76, 83, 84, 85, 86, 87, 88, 89, 90, 91,
            92, 93, 94, 95, 96, 97, 98, 99, 100)
UNSAFE = """        if isUTF16:
            s = list(bytes.fromhex(val))
            l = len(s) // 2
        else:
            l = len(val)
            s = val.encode("utf-8")

        assert l <= length, "Overflowed string length is not supported yet."

        memcpy(stringStorage, s, offset, len(s))"""
SAFE = """        if not isinstance(val, str):
            raise TypeError("Replacement must be a string")
        if isUTF16:
            s = bytes.fromhex(val)
            if len(s) % 2:
                raise ValueError("Incomplete UTF-16 replacement")
            capacity = length * 2
        else:
            s = val.encode("utf-8")
            capacity = length
        if len(s) != capacity:
            raise ValueError("Replacement must have same encoded byte length")
        if offset < 0 or offset + capacity > len(stringStorage):
            raise ValueError("String storage offset out of bounds")
        memcpy(stringStorage, s, offset, len(s))"""
BAD_ALIGN = """        self.out.write(bytes((self.accumulator,)))
        self.accumulator = 0
        self.bcount = 0
        return pad"""
GOOD_ALIGN = """        self.out.write(bytes((self.accumulator,)))
        self.write += 1
        self.accumulator = 0
        self.bcount = 0
        return pad"""


def git(args: list[str], root: Path) -> str:
    proc = subprocess.run(["git", "-C", str(root), *args],
                          capture_output=True, text=True, timeout=10, check=False)
    if proc.returncode:
        raise ValueError("Source checkout verification failed")
    return proc.stdout.strip()


def stage(path: Path, data: bytes, mode: int) -> Path:
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".vibe-hbc-stage-")
    p = Path(name)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(p, stat.S_IMODE(mode))
    except BaseException:
        p.unlink(missing_ok=True)
        raise
    return p


def patch_all(root: Path, *, replace=os.replace) -> dict:
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Checkout directory missing or symlinked")
    root = root.resolve()
    if git(["rev-parse", "HEAD"], root) != PINNED:
        raise ValueError("Unexpected upstream revision")
    if git(["status", "--porcelain", "--untracked-files=no"], root):
        raise ValueError("Source checkout already modified")
    backup = root / ".vibe-hbc-backup-v2"
    if backup.exists() or backup.is_symlink():
        raise ValueError("Backup already exists")
    prepared = []
    for version in VERSIONS:
        relative = f"hbctool/hbc/hbc{version}/__init__.py"
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or unsafe source file")
        raw = path.read_bytes()
        expected_sha = git(["rev-parse", f"HEAD:{relative}"], root)
        computed = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if computed != expected_sha:
            raise ValueError(f"Git blob mismatch in HBC{version}")
        old = raw.decode("utf-8")
        if old.count(UNSAFE) != 1:
            raise ValueError(f"HBC{version} string code unexpectedly changed")
        candidate = old.replace(UNSAFE, SAFE)
        getter = f"    def getVersion(self):\n        return {74 if version==59 else 99 if version==100 else version}\n"
        if candidate.count(getter) != 1:
            raise ValueError(f"HBC{version} getter unexpectedly changed")
        if version in (59, 100):
            candidate = candidate.replace(getter,
                f"    def getVersion(self):\n        return {version}\n", 1)
        prepared.append((path, raw, candidate.encode("utf-8"), path.stat().st_mode))
    relative = "hbctool/util.py"
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise ValueError("Invalid writer module")
    raw = path.read_bytes()
    expected = git(["rev-parse", f"HEAD:{relative}"], root)
    actual = hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
    if expected != actual:
        raise ValueError("Writer SHA mismatch")
    old = raw.decode("utf-8")
    if old.count(BAD_ALIGN) != 1:
        raise ValueError("Writer align code unexpectedly changed")
    candidate = old.replace(BAD_ALIGN, GOOD_ALIGN, 1)
    prepared.append((path, raw, candidate.encode("utf-8"), path.stat().st_mode))
    for path, _, updated, _ in prepared:
        compile(updated, str(path), "exec")
    staged, replaced = {}, []
    try:
        for path, _, updated, mode in prepared:
            staged[path] = stage(path, updated, mode)
        backup.mkdir(mode=0o700)
        manifest = []
        for path, original, _, mode in prepared:
            target = backup / (path.parent.name + "_" + path.name + ".orig")
            if path.name == "util.py":
                target = backup / "util.py.orig"
            with target.open("xb") as out:
                out.write(original)
                out.flush()
                os.fsync(out.fileno())
            digest = hashlib.sha256(original).hexdigest()
            if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                raise OSError("Backup verification failed")
            manifest.append({"path": str(path.relative_to(root)),
                             "backup":target.name, "sha256":digest})
        manifest_path = backup / "manifest.json"
        with manifest_path.open("x", encoding="utf-8") as out:
            json.dump({"pinned_commit":PINNED,"files":manifest},out,indent=2)
            out.flush()
            os.fsync(out.fileno())
        for path, raw, _, mode in prepared:
            replace(staged[path], path)
            staged.pop(path)
            replaced.append(path)
        return {"patched_files": len(replaced), "modules": len(VERSIONS),
                "backup":str(backup),"pinned_commit":PINNED}
    except BaseException as exc:
        rollback_failures = []
        for path, original, _, mode in reversed(prepared):
            if path not in replaced:
                continue
            try:
                temp = stage(path, original, mode)
                os.replace(temp,path)
            except OSError:
                rollback_failures.append(str(path))
        if rollback_failures:
            raise RuntimeError("Rollback incomplete: "+", ".join(rollback_failures)) from exc
        raise
    finally:
        for p in staged.values():
            p.unlink(missing_ok=True)


if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("checkout",type=Path)
    args=parser.parse_args()
    print(json.dumps(patch_all(args.checkout),indent=2))
