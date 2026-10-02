"""vibebot.engines — the engine implementations behind core.Engine.

  * ApkModEngine — adapter over the EXISTING tools/apkmod.py pipeline
    (INTAKE -> DETECT -> GRAPH -> REPORT). This is the study's "apkmod.py
    becomes the first adapter, not the product" step: apkmod stays a library
    of pure functions; the adapter normalizes its findings into the shared
    Finding schema.
  * MockEngine — deterministic offline engine (no artifact parsing) that
    proves the gateway/job/session/deepdive machinery end-to-end in CI
    without androguard.

Engines are READ-ONLY with respect to the artifact: apkmod never modifies
APK bytes; MockEngine reads nothing.
"""

from __future__ import annotations

import os
import sys

from . import core

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _apkmod():
    """Import the sibling tools/apkmod.py module (kept as a library, not copied)."""
    tools_dir = os.path.join(ROOT, "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    # androguard logs via loguru at DEBUG — silence it before first use so
    # job progress lines (the real evidence) stay readable
    try:
        import logging
        for name in ("androguard", "androguard.core", "loguru"):
            logging.getLogger(name).setLevel(logging.ERROR)
        from loguru import logger as _log
        _log.remove()
    except Exception:
        pass
    import importlib
    return importlib.import_module("apkmod")


class ApkModEngine(core.Engine):
    """Adapter: apkmod pipeline -> normalized EngineResult."""

    spec = core.EngineSpec(
        name="apkmod",
        description="authorized-APK analysis: intake, E1-E3 ad/analytics/consent "
                    "detection, DEX call-graph, structured findings",
        formats=("apk", "dex"),
    )

    def __init__(self, report_dir: str, fingerprints: str | None = None):
        self.report_dir = report_dir
        self.fingerprints = fingerprints  # optional extra reduced FP DB path

    def can_run(self, artifact: str) -> bool:
        return artifact.lower().endswith((".apk", ".apkx"))

    def run(self, job: core.Job) -> core.EngineResult:
        apk = _apkmod()
        fp_path = job.params.get("fingerprints") or self.fingerprints
        extra_fp = None
        if fp_path:
            import json as _json
            extra_fp = _json.load(open(fp_path, encoding="utf-8"))

        job.progress("intake", 10, "manifest + inventory")
        inv = apk.intake(job.artifact)
        job.checkpoint("intake", {k: inv[k] for k in
                                         ("sha256", "package", "versionName")})

        job.progress("detect", 30, "DEX classes vs fingerprint DB")
        dexes = apk._dex_objects(job.artifact)
        findings = apk.detect(inv, dexes, extra_fp)
        job.checkpoint("detect", {"findingCount": len(findings)})

        job.progress("graph", 70, "app-owned callers (call graph)")
        normalized = [core.normalize_finding(f, self.spec.name, i + 1)
                      for i, f in enumerate(findings)]
        job.checkpoint("graph", {
            "chokepointCallers": sum(len(f.get("appCallers", [])) for f in findings)
        })

        job.progress("report", 90, "markdown report card")
        os.makedirs(self.report_dir, exist_ok=True)
        rep_path = apk.report(job.artifact, inv, findings, None, self.report_dir)
        job.checkpoint("report", rep_path)

        structural = {
            "package": inv.get("package"),
            "versionName": inv.get("versionName"),
            "permissions": inv.get("permissions"),
            "dexFiles": inv.get("dexFiles"),
            "nativeLibs": inv.get("nativeLibs"),
            "activities": inv.get("activities"),
            "services": inv.get("services"),
            "components": {
                "activities": len(inv.get("activities") or []),
                "services": len(inv.get("services") or []),
                "receivers": len(inv.get("receivers") or []),
            },
            "flutter": {"detected": self._flutter(inv, dexes)},
        }
        job.progress("report", 100, "done")

        return core.EngineResult(
            intake={k: inv.get(k) for k in
                    ("sha256", "size", "package", "versionName", "versionCode",
                     "minSdk", "targetSdk", "signingDigest")},
            structural=structural,
            findings=normalized,
            report_md=open(rep_path, encoding="utf-8").read(),
            outputs={"report": rep_path},
        )

    @staticmethod
    def _flutter(inv: dict, dexes: list) -> bool:
        """Cheap structural flutter signal (assets + class prefixes),
        clearly a presence hint, not execution evidence."""
        try:
            names = [c.get_name() for _, d in dexes for c in d.get_classes()]
            if any(n.startswith("Lio/flutter/") for n in names):
                return True
        except Exception:
            pass
        return False


class MockEngine(core.Engine):
    """Deterministic offline engine — no artifact content is read.

    Emits two findings (one E1, one E3 with an app caller) so CI can prove
    normalization, session persistence, and stateful deepdive without
    androguard or a real APK.
    """

    spec = core.EngineSpec(name="mock", description="deterministic offline mock",
                           formats=("*",))

    def can_run(self, artifact: str) -> bool:
        return artifact.lower().endswith((".mock", ".apk"))

    def run(self, job: core.Job) -> core.EngineResult:
        import hashlib
        job.progress("intake", 50, "mock intake")
        h = hashlib.sha256()
        with open(job.artifact, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        job.checkpoint("intake", {"sha256": h.hexdigest()})
        job.progress("detect", 100, "mock detect")
        raw = [
            {
                "id": "FND-001", "sdk": "MOCKSDK", "classification": "ADVERTISING",
                "evidence": [
                    {"level": "E1", "artifact": "classes.dex",
                     "class": "Lcom/mock/Ads;", "detail": "mock SDK class present"},
                    {"level": "E3", "artifact": "classes.dex",
                     "class": "Lcom/app/Demo;", "method": "onCreate",
                     "detail": "app onCreate() invokes Lcom/mock/Ads;->init()"},
                ],
                "appCallers": [{"artifact": "classes.dex",
                                "class": "com.app.Demo", "method": "onCreate",
                                "invokes": "com.mock.Ads.init()"}],
                "falsification": ["mock: no caller via reflection"],
            },
            {
                "id": "FND-002", "sdk": "MOCKANALYTICS", "classification": "ANALYTICS",
                "evidence": [
                    {"level": "E1", "artifact": "classes.dex",
                     "class": "Lcom/mock/Tracker;", "detail": "analytics class present"},
                ],
                "appCallers": [],
                "falsification": ["presence only (E1)"],
            },
        ]
        findings = [core.normalize_finding(f, self.spec.name, i + 1)
                    for i, f in enumerate(raw)]
        return core.EngineResult(
            intake={"sha256": h.hexdigest(), "package": "com.mock.app",
                    "versionName": "0.0.0"},
            structural={"package": "com.mock.app", "dexFiles": ["classes.dex"],
                        "nativeLibs": ["lib/arm64-v8a/libmock.so"],
                        "activities": ["com.app.MainActivity"]},
            findings=findings,
            report_md="# mock report\n\n2 findings (mock).\n",
        )
