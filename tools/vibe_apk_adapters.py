"""Read-only adapters that normalize APK/native inspection into Vibe observations.

External tools are optional. Adapters never patch, rewrite, sign, install, or
execute target code. Command execution is argument-list based (no shell=True),
time-bounded, and returns structured provider failures to the evidence layer.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

from tools.vibe_evidence import Observation


class ToolUnavailable(RuntimeError):
    pass


class CommandFailed(RuntimeError):
    pass


class ReadOnlyCommand:
    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout

    def run(self, argv: list[str]) -> str:
        if not argv or shutil.which(argv[0]) is None:
            raise ToolUnavailable(f"tool unavailable: {argv[0] if argv else 'unknown'}")
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout, check=False)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip()[:500]
            raise CommandFailed(f"{argv[0]} exited {proc.returncode}: {detail}")
        return proc.stdout


class Radare2ReadProvider:
    """Native ELF/.so reader using radare2 JSON commands."""
    name = "radare2"

    def __init__(self, binary: str | Path, runner: ReadOnlyCommand | None = None) -> None:
        self.binary = str(binary)
        self.runner = runner or ReadOnlyCommand()

    def supports(self, capability: str) -> bool:
        return capability in {"STRING_SEARCH", "REFERENCE_IN", "REFERENCE_OUT"}

    def _r2_json(self, command: str) -> Any:
        raw = self.runner.run(["r2", "-2", "-q", "-c", command, self.binary])
        return json.loads(raw or "[]")

    def observe(self, capability: str, target: str | None) -> list[Observation]:
        if capability == "STRING_SEARCH":
            rows = self._r2_json("izzj")
            return [Observation(capability, self.name, target, "string", {"offset": r.get("vaddr", r.get("paddr")), "text": r.get("string")}, self.binary) for r in rows]
        if not target:
            return []
        # Target is expected to be an already-resolved address/symbol. The
        # adapter does not interpolate it into a shell; it remains an r2 command.
        command = f"axtj @ {target}" if capability == "REFERENCE_IN" else f"axfj @ {target}"
        rows = self._r2_json(command)
        kind = "xref_in" if capability == "REFERENCE_IN" else "xref_out"
        return [Observation(capability, self.name, target, kind, row, self.binary) for row in rows]


class JadxReadProvider:
    """APK/DEX source-tree reader. Decompilation writes only to a caller-owned workspace."""
    name = "jadx"

    def __init__(self, apk: str | Path, workspace: str | Path, runner: ReadOnlyCommand | None = None) -> None:
        self.apk = str(apk)
        self.workspace = Path(workspace)
        self.runner = runner or ReadOnlyCommand(timeout=120)

    def supports(self, capability: str) -> bool:
        return capability in {"ARTIFACT_INDEX", "STRING_SEARCH"}

    def _ensure_sources(self) -> Path:
        out = self.workspace / "jadx"
        if not out.exists():
            out.parent.mkdir(parents=True, exist_ok=True)
            self.runner.run(["jadx", "--no-res", "-d", str(out), self.apk])
        return out

    def observe(self, capability: str, target: str | None) -> list[Observation]:
        root = self._ensure_sources()
        files = sorted(p for p in root.rglob("*") if p.is_file())
        if capability == "ARTIFACT_INDEX":
            return [Observation(capability, self.name, target, "source_file", str(p.relative_to(root)), self.apk) for p in files]
        observations: list[Observation] = []
        needle = (target or "").lower()
        if not needle:
            return observations
        for path in files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if needle in line.lower():
                    observations.append(Observation(capability, self.name, target, "text_match", {"file": str(path.relative_to(root)), "line": lineno, "snippet": line.strip()[:240]}, self.apk))
                    if len(observations) >= 200:
                        return observations
        return observations


class ApktoolReadProvider:
    """Manifest/resources/smali inventory adapter; no rebuild capability exposed."""
    name = "apktool"

    def __init__(self, apk: str | Path, workspace: str | Path, runner: ReadOnlyCommand | None = None) -> None:
        self.apk = str(apk)
        self.workspace = Path(workspace)
        self.runner = runner or ReadOnlyCommand(timeout=120)

    def supports(self, capability: str) -> bool:
        return capability == "ARTIFACT_INDEX"

    def observe(self, capability: str, target: str | None) -> list[Observation]:
        out = self.workspace / "apktool"
        if not out.exists():
            out.parent.mkdir(parents=True, exist_ok=True)
            self.runner.run(["apktool", "d", "-f", "-o", str(out), self.apk])
        rows: list[Observation] = []
        for path in sorted(p for p in out.rglob("*") if p.is_file()):
            rel = str(path.relative_to(out))
            kind = "smali_file" if path.suffix == ".smali" else "resource_file"
            if rel == "AndroidManifest.xml":
                kind = "manifest"
            rows.append(Observation(capability, self.name, target, kind, rel, self.apk))
        return rows
