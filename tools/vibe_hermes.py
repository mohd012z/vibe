"""Vibe read-only Hermes and APK technology inventory.

Self-contained stdlib parser. Never extracts, executes, edits or signs code.
This module is intentionally independent from Vibe's production gateway.
"""
from __future__ import annotations
import hashlib
import io
from pathlib import Path, PurePosixPath
import re
import struct
import zipfile

MAGIC = 2240826417119764422
SUPPORTED = frozenset((59,62,74,76,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100))
MAX_APK = 256 * 1024 * 1024
MAX_ENTRIES = 20_000
MAX_TOTAL = 1024 * 1024 * 1024
MAX_BUNDLE = 128 * 1024 * 1024


class InvalidAPK(ValueError):
    pass


def read_hbc_header(data: bytes, entry_size: int | None = None) -> dict:
    if len(data) < 12:
        raise InvalidAPK("Truncated Hermes header")
    magic, version = struct.unpack_from("<QI", data)
    if magic != MAGIC:
        raise InvalidAPK("Not a Hermes bytecode header")
    if not (1 <= version <= 65535):
        raise InvalidAPK("Implausible Hermes version")
    result = {"hbc_version": version, "hbctool_0_1_7_registered": version in SUPPORTED}
    if version in (97,98,99,100) and len(data) >= 36:
        declared = struct.unpack_from("<I", data, 32)[0]
        result["declared_file_length"] = declared
        if declared and entry_size is not None and declared != entry_size:
            result["length_warning"] = "Declared length differs from ZIP entry length"
    if 87 <= version <= 100:
        if len(data) < 72:
            result["layout_preflight"] = "insufficient_header_bytes"
        else:
            bigint_count, bigint_storage = struct.unpack_from("<II", data, 64)
            result["bigint_count"] = bigint_count
            result["bigint_storage_size"] = bigint_storage
            result["layout_preflight"] = (
                "unsupported_bigint_sections" if bigint_count or bigint_storage
                else "bigint_sections_empty"
            )
    return result


def _inspect_bytes_impl(payload: bytes) -> dict:
    if len(payload) > MAX_APK:
        raise InvalidAPK("APK exceeds upload size limit")
    if not zipfile.is_zipfile(io.BytesIO(payload)):
        raise InvalidAPK("Not an APK ZIP archive")
    with zipfile.ZipFile(io.BytesIO(payload)) as z:
        entries = z.infolist()
        if len(entries) > MAX_ENTRIES:
            raise InvalidAPK("Too many ZIP members")
        seen = set()
        total = 0
        names = []
        hermes = []
        for member in entries:
            raw = member.filename
            path = PurePosixPath(raw)
            if not raw or raw.startswith("/") or chr(92) in raw or chr(0) in raw or ".." in path.parts:
                raise InvalidAPK("Unsafe ZIP entry path")
            name = str(path)
            if name in seen:
                raise InvalidAPK("Duplicate ZIP entry")
            seen.add(name)
            names.append(name.lower())
            if member.flag_bits & 1:
                raise InvalidAPK("Encrypted ZIP members unsupported")
            total += member.file_size
            if member.file_size > MAX_TOTAL or total > MAX_TOTAL:
                raise InvalidAPK("Uncompressed size limit exceeded")
            if member.file_size and not member.compress_size and not member.is_dir():
                raise InvalidAPK("Invalid member compressed length")
            if (member.compress_size and member.file_size > 1024 * 1024
                    and member.file_size > member.compress_size * 200):
                raise InvalidAPK("ZIP compression ratio limit exceeded")
            if member.is_dir() or not (name.lower().endswith(".bundle") or name.lower().endswith(".hbc")):
                continue
            rec = {"entry": name, "size": member.file_size}
            if member.file_size > MAX_BUNDLE:
                rec["status"] = "oversize"
            else:
                try:
                    with z.open(member) as f:
                        rec.update(read_hbc_header(f.read(80), member.file_size))
                    rec["status"] = "hermes"
                except InvalidAPK:
                    rec["status"] = "not_hermes"
                except (EOFError, RuntimeError, zipfile.BadZipFile, OSError):
                    rec["status"] = "unreadable"
            hermes.append(rec)
        has_hbc = any(b.get("status") == "hermes" for b in hermes)
        is_dex = any(re.fullmatch(r"classes\d*\.dex", n) for n in names)
        is_flutter = any(n.endswith("/libflutter.so") or n.endswith("/libapp.so")
                         or n.startswith("assets/flutter_assets/") for n in names)
        is_rn = any(n.startswith("assets/") and
                    ("index.android.bundle" in n or n.endswith(".bundle")) for n in names)
        technologies = (["DEX"] if is_dex else []) + (["Flutter"] if is_flutter else []) + (
            ["React Native"] if is_rn or has_hbc else []) + (["Hermes"] if has_hbc else [])
        return {"sha256": hashlib.sha256(payload).hexdigest(), "byte_size": len(payload),
                "entries": len(entries), "technologies": technologies, "bundles": hermes,
                "evidence": "static packaging and HBC header only",
                "limitations": ["No runtime claims", "No opcode or full semantic validation"]}



def inspect_bytes(payload: bytes) -> dict:
    """Normalize corrupt ZIP internals into a public, bounded validation error."""
    try:
        return _inspect_bytes_impl(payload)
    except (zipfile.BadZipFile, EOFError, OSError, RuntimeError,
            NotImplementedError, UnicodeError, struct.error) as exc:
        raise InvalidAPK("Malformed or unsupported ZIP structure") from exc


def inspect_path(path: str | Path) -> dict:
    source = Path(path)
    if not source.is_file():
        raise InvalidAPK("APK file does not exist")
    if source.stat().st_size > MAX_APK:
        raise InvalidAPK("APK exceeds size limit")
    return inspect_bytes(source.read_bytes())


if __name__ == "__main__":
    import argparse
    import json
    p = argparse.ArgumentParser()
    p.add_argument("apk")
    args = p.parse_args()
    try:
        print(json.dumps(inspect_path(args.apk), indent=2))
    except (InvalidAPK, OSError, zipfile.BadZipFile) as e:
        p.exit(2, "Inspection refused: " + str(e) + "\n")
