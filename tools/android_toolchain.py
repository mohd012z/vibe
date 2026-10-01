#!/usr/bin/env python3
"""Vibe Android APK toolchain manager.

Safe responsibilities:
- discover locally installed APK analysis/build tools
- report versions and missing capabilities
- emit reproducible install guidance
- never download/execute remote code implicitly

Actual APK modifications remain authorization-gated by the Vibe workflow.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "toolchain" / "android-tools.json"

COMMANDS = {
    "java": ["java", "-version"],
    "apktool": ["apktool", "--version"],
    "jadx": ["jadx", "--version"],
    "radare2": ["r2", "-v"],
    "aapt2": ["aapt2", "version"],
    "apksigner": ["apksigner", "version"],
    "zipalign": ["zipalign", "-h"],
    "adb": ["adb", "version"],
    "sdkmanager": ["sdkmanager", "--version"],
}

CAPABILITIES = {
    "extract/resources": ["apktool"],
    "decompile/readable": ["jadx"],
    "dex/smali": ["java"],
    "native/.so": ["radare2"],
    "resource-compile": ["aapt2"],
    "align": ["zipalign"],
    "sign/verify": ["apksigner"],
    "runtime-smoke-test": ["adb"],
}


def run_version(argv: list[str]) -> str:
    exe = shutil.which(argv[0])
    if not exe:
        return "MISSING"
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=8)
        text = (p.stdout or p.stderr).strip().splitlines()
        return text[0][:240] if text else f"FOUND ({exe})"
    except Exception as exc:
        return f"FOUND but version probe failed: {type(exc).__name__}"


def doctor(as_json: bool = False) -> int:
    status = {name: run_version(cmd) for name, cmd in COMMANDS.items()}
    caps = {
        cap: all(status.get(dep, "MISSING") != "MISSING" for dep in deps)
        for cap, deps in CAPABILITIES.items()
    }
    result = {"tools": status, "capabilities": caps}
    if as_json:
        print(json.dumps(result, indent=2))
    else:
        print("Vibe Android Toolchain Doctor")
        print("=" * 31)
        for name, value in status.items():
            mark = "OK" if value != "MISSING" else "--"
            print(f"[{mark:2}] {name:12} {value}")
        print("\nCapabilities")
        for cap, ok in caps.items():
            print(f"[{'OK' if ok else '--':2}] {cap}")
    return 0 if all(caps.values()) else 2


def plan() -> int:
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    print("Vibe Android toolchain install plan (no changes performed)\n")
    for name, meta in data["tools"].items():
        print(f"{name}: {meta['version']}")
        print("  role: " + ", ".join(meta["role"]))
        print("  source: " + meta["source"])
    print("\nRecommended host prerequisites:")
    print("  * 64-bit JDK 17+ for JADX/current Android tooling")
    print("  * Android SDK command-line tools + platform-tools + build-tools")
    print("  * Python environment with androguard for existing apkmod.py")
    print("  * Google smali/dexlib2 as pinned Maven/JAR dependencies")
    print("\nKeep downloaded binaries in .toolchain/ (gitignored), verify checksums,")
    print("and pin versions in toolchain/android-tools.json before CI use.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["doctor", "plan"])
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    return doctor(args.json) if args.command == "doctor" else plan()


if __name__ == "__main__":
    raise SystemExit(main())
