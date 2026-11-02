"""Read-only no-edit round-trip gate for *genuine* authorized HBC fixtures.

Supply one genuine compiled file per version named hbcNN.hbc. This file does
not supply synthetic inputs or claim a missing version passed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from vibe_hermes import MAX_APK, SUPPORTED, InvalidAPK, read_hbc_header

MAX_BUNDLE=48*1024*1024

def check_fixture(path: Path, version: int, timeout: int = 30) -> dict:
    result={'version':version,'fixture':path.name,'status':'unverified'}
    if path.is_symlink() or not path.is_file():
        result['status']='missing_fixture'
        return result
    if path.stat().st_size > MAX_BUNDLE:
        result['status']='fixture_too_large'
        return result
    raw=path.read_bytes()
    try:
        hdr=read_hbc_header(raw[:64],len(raw))
    except InvalidAPK:
        result['status']='invalid_hbc_header'
        return result
    result['sha256']=hashlib.sha256(raw).hexdigest()
    if hdr['hbc_version']!=version:
        result['status']='version_mismatch'
        return result
    if not shutil.which('hbctool'):
        result['status']='provider_unavailable'
        return result
    with tempfile.TemporaryDirectory(prefix='vibe-hbc-roundtrip-') as folder:
        asm=Path(folder)/'hasm'
        target=Path(folder)/'rebuilt.hbc'
        for stage,cmd in [
            ('disasm',['hbctool','disasm',str(path.resolve()),str(asm)]),
            ('asm',['hbctool','asm',str(asm),str(target)])
        ]:
            try:
                proc=subprocess.run(cmd,cwd=folder,stdin=subprocess.DEVNULL,
                                    capture_output=True,timeout=timeout,check=False)
            except (OSError,subprocess.TimeoutExpired):
                result['status']=stage+'_error_or_timeout'
                return result
            if proc.returncode:
                result['status']=stage+'_failed'
                result['exit_code']=proc.returncode
                return result
        if not target.is_file() or target.stat().st_size > MAX_BUNDLE:
            result['status']='invalid_reassembled_output'
            return result
        rebuilt=target.read_bytes()
        try:
            new_header=read_hbc_header(rebuilt[:64],len(rebuilt))
        except InvalidAPK:
            result['status']='invalid_reassembled_header'
            return result
        if new_header['hbc_version']!=version:
            result['status']='version_changed'
            return result
        result['rebuilt_sha256']=hashlib.sha256(rebuilt).hexdigest()
        result['status']='exact_bytes_match' if rebuilt==raw else 'bytewise_mismatch'
        result['runtime_semantics_verified']=False
        return result


def matrix(fixtures_dir: Path) -> dict:
    rows=[check_fixture(fixtures_dir/f'hbc{v}.hbc',v) for v in sorted(SUPPORTED)]
    return {'fixture_policy':'genuine_authorized_compiled_HBC_only',
            'versions_registered':len(rows),
            'exact_matches':sum(row['status']=='exact_bytes_match' for row in rows),
            'runtime_semantics_verified':False, 'results':rows}

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('fixtures_dir',type=Path)
    args=p.parse_args()
    print(json.dumps(matrix(args.fixtures_dir),indent=2))
