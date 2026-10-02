#!/usr/bin/env python3
"""Evidence-first Android APK pipeline for Vibe.

Read-only stages never modify the input APK. Mutating stages are explicitly
authorization-gated and are intended to operate on a working copy.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class PipelineError(RuntimeError):
    pass


class Stage(str, Enum):
    INSPECT = "inspect"
    EXTRACT = "extract"
    DECOMPILE = "decompile"
    SMALI = "smali"
    NATIVE = "native"
    TARGETS = "targets"
    REBUILD = "rebuild"
    ALIGN = "align"
    SIGN = "sign"
    VERIFY = "verify"
    TEST = "test"
    REPORT = "report"


MUTATING_STAGES = {Stage.REBUILD, Stage.ALIGN, Stage.SIGN}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class StageResult:
    stage: Stage
    ok: bool
    outputs: list[str] = field(default_factory=list)
    output_hashes: dict[str, str] = field(default_factory=dict)
    evidence: list[dict] = field(default_factory=list)
    error: str | None = None


class ApkPipeline:
    def __init__(self, apk: str | Path, runs_root: str | Path = "apk-runs"):
        self.apk = Path(apk).resolve()
        if not self.apk.is_file():
            raise PipelineError(f"APK not found: {self.apk}")
        if not zipfile.is_zipfile(self.apk):
            raise PipelineError(f"not a valid ZIP/APK container: {self.apk}")
        self.sha256 = sha256_file(self.apk)
        self.run_dir = Path(runs_root).resolve() / self.sha256
        (self.run_dir / "stages").mkdir(parents=True, exist_ok=True)

    def require_authorization(self, stage: Stage, authorization: str | None) -> None:
        if stage in MUTATING_STAGES and not (authorization or "").strip():
            raise PipelineError(f"authorization required for mutating stage: {stage.value}")

    def _record(self, result: StageResult, started: str, extra: dict | None = None) -> StageResult:
        record = {
            "stage": result.stage.value,
            "input": str(self.apk),
            "input_sha256": self.sha256,
            "ok": result.ok,
            "outputs": result.outputs,
            "output_hashes": result.output_hashes,
            "evidence": result.evidence,
            "error": result.error,
            "started_at": started,
            "finished_at": now(),
        }
        if extra:
            record.update(extra)
        path = self.run_dir / "stages" / f"{result.stage.value}.json"
        path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
        return result

    def inspect(self) -> StageResult:
        started = now()
        try:
            with zipfile.ZipFile(self.apk) as z:
                names = z.namelist()
                inventory = {
                    "sha256": self.sha256,
                    "size": self.apk.stat().st_size,
                    "entry_count": len(names),
                    "has_manifest": "AndroidManifest.xml" in names,
                    "dex_files": sorted(n for n in names if n.startswith("classes") and n.endswith(".dex")),
                    "native_libs": sorted(n for n in names if n.startswith("lib/") and n.endswith(".so")),
                    "resource_table": "resources.arsc" in names,
                }
            out = self.run_dir / "inventory.json"
            out.write_text(json.dumps(inventory, indent=2, sort_keys=True), encoding="utf-8")
            result = StageResult(
                Stage.INSPECT,
                True,
                [str(out)],
                {str(out): sha256_file(out)},
                [{"kind": "container-inventory", "source": "zip-central-directory"}],
            )
        except Exception as exc:
            result = StageResult(Stage.INSPECT, False, error=f"{type(exc).__name__}: {exc}")
        return self._record(result, started)

    def extract(self) -> StageResult:
        started = now()
        dest = self.run_dir / "extracted"
        try:
            if dest.exists():
                shutil.rmtree(dest)
            dest.mkdir(parents=True)
            with zipfile.ZipFile(self.apk) as z:
                # ZipFile.extractall performs path sanitization; additionally reject
                # entries resolving outside the run directory for explicit provenance.
                root = dest.resolve()
                for info in z.infolist():
                    target = (dest / info.filename).resolve()
                    if root != target and root not in target.parents:
                        raise PipelineError(f"unsafe archive path: {info.filename}")
                    z.extract(info, dest)
            outputs = sorted(str(p) for p in dest.rglob("*") if p.is_file())
            hashes = {p: sha256_file(Path(p)) for p in outputs}
            result = StageResult(
                Stage.EXTRACT,
                True,
                outputs,
                hashes,
                [{"kind": "read-only-extraction", "entries": len(outputs)}],
            )
        except Exception as exc:
            result = StageResult(Stage.EXTRACT, False, error=f"{type(exc).__name__}: {exc}")
        return self._record(result, started)
