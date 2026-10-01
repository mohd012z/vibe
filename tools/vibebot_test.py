#!/usr/bin/env python3
"""vibebot regression suite — proves the VibeBot core without any network.

Always-on (stdlib only, MockEngine):
  * job lifecycle: QUEUED -> RUNNING -> COMPLETED, progress + checkpoints
  * finding normalization invariants (id, provenance, derived confidence,
    location, verification.runtime=UNKNOWN, alternatives)
  * session store: fingerprint -> structural map + findings persist
  * stateful /deepdive: callers / references / native / substring, no rescan
  * gateway command surface: ACK immediately, /status, /sessions, /cancel,
    refusal of missing artifacts, sha hex validation
  * engine independence: the gateway never special-cases engine names

Conditionally (androguard present — CI installs it; local SKIP):
  * ApkModEngine adapter over the committed fixture APK: intake sha pinned,
    E1/E2/E3 findings, E3 callers in callGraph, report written

CI runs: python3 tools/vibebot_test.py
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.dirname(os.path.abspath(__file__))
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

FIXTURE = os.path.join(ROOT, "tests", "fixtures", "fixture-demo.apk")
EXTRA_FP = os.path.join(ROOT, "apk", "fingerprints.example-extra.json")

failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  {'OK ' if cond else 'FAIL'} {name}"
          + (f"  ({detail})" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def main() -> int:
    try:
        import androguard  # noqa: F401
        HAVE_ANDROGUARD = True
    except ImportError:
        HAVE_ANDROGUARD = False

    from vibebot import core, engines, gateway

    td = tempfile.mkdtemp(prefix="vibebot-test-")
    try:
        print("== core: job lifecycle + engine contract ==")
        store = core.SessionStore(td)
        mgr = core.JobManager({"mock": engines.MockEngine()}, store)
        fake = os.path.join(td, "dummy.apk")
        open(fake, "wb").write(b"not a real apk (mock engine)")
        job = mgr.submit("analyze", fake, user="test")
        check("submit returns QUEUED job", job.state == core.Job.QUEUED)
        check("job id format VIBE-XXXX", job.id.startswith("VIBE-"))
        jobs = mgr.process()
        check("job reaches COMPLETED", jobs[0].state == core.Job.COMPLETED,
              jobs[0].error or "")
        res = jobs[0].result
        check("COMPLETED job carries a result", res is not None)
        if res is None:
            print("  (cannot continue without result)")
            return 1
        ev = [e for e in jobs[0].events if e["type"] == "progress"]
        check("progress events recorded", len(ev) >= 2 and
              ev[-1]["pct"] == 100, str(len(ev)))
        check("checkpoints recorded",
              "intake" in jobs[0].checkpoints or "detect" in jobs[0].checkpoints)

        print("== core: finding normalization invariants ==")
        check("result has 2 mock findings", len(res.findings) == 2)
        for f in res.findings:
            for k in ("id", "engine", "evidenceLevel", "location", "evidence",
                      "confidence", "confidenceBasis", "alternatives",
                      "verification", "provenance"):
                check(f"finding has {k}", k in f)
        f1, f2 = res.findings
        check("E3 finding confidence HIGH", f1["evidenceLevel"] == "E3"
              and f1["confidence"] == "HIGH", f1["confidence"])
        check("E1 finding confidence LOW", f2["evidenceLevel"] == "E1"
              and f2["confidence"] == "LOW", f2["confidence"])
        check("runtime stays UNKNOWN (static ceiling)",
              f1["verification"]["runtime"] == "UNKNOWN")
        check("alternatives recorded (falsification)",
              f1["alternatives"] and f1["alternatives"] != ["none identified"])
        check("provenance stamps engine + schema",
              f1["provenance"]["tool"] == "mock"
              and f1["provenance"]["schemaVersion"] == core.FINDING_SCHEMA_VERSION)

        print("== core: session store ==")
        sha = res.intake["sha256"]
        sess = store.load(sha)
        check("session persisted under fingerprint", sess is not None)
        if sess is None:
            return 1
        check("session carries structural map",
              "nativeLibs" in sess["structural"] and
              sess["structural"]["nativeLibs"])
        check("session lists 2 findings", len(sess["findings"]) == 2)

        print("== core: stateful deepdive (no rescan) ==")
        d = core.deepdive(sess, "callers")
        check("deepdive callers finds E3 caller",
              d["matchCount"] >= 1 and
              any("com.app.Demo" in json.dumps(m) for m in d["matches"]),
              json.dumps(d["matches"])[:200])
        d = core.deepdive(sess, "references")
        check("deepdive references >= 3 evidence rows", d["matchCount"] >= 3,
              str(d["matchCount"]))
        d = core.deepdive(sess, "native")
        check("deepdive native lists .so",
              any("libmock.so" in json.dumps(m) for m in d["matches"]))
        d = core.deepdive(sess, "mockanalytics")
        check("deepdive substring matches SDK name", d["matchCount"] >= 1)
        d = core.deepdive(sess, "zzz-nothing")
        check("deepdive no-match honest", d["matchCount"] == 0
              and "run /analyze first" in d["note"])
        r = core.record_deepdive(store, sha, "callers")
        check("record_deepdive appends history",
              store.load(sha)["deepdive"][-1]["target"] == "callers")
        unk = core.record_deepdive(store, "00" * 16, "x")
        check("record_deepdive on unknown sha errors", "error" in unk)

        print("== core: cancel ==")
        j2 = mgr.submit("analyze", fake)
        j2.request_cancel()
        mgr.process()
        check("cancelled job not COMPLETED",
              j2.state in (core.Job.CANCELLED,), j2.state)

        print("== gateway: command surface ==")
        gw = gateway.Gateway(td)
        reply, job = gw.handle("/analyze /nope/missing.apk")
        check("missing artifact refused, no job", job is None
              and "not found" in reply)
        reply, job = gw.handle(f"/analyze {fake} --engine mock")
        check("analyze ACKs immediately with job id", job is not None
              and job.id in reply and "ACK" in reply)
        gw.process_pending()
        assert job is not None and job.result is not None
        reply, _ = gw.handle(f"/status {job.id}")
        check("status shows COMPLETED", "COMPLETED" in reply, reply)
        reply, _ = gw.handle("/sessions")
        check("sessions lists stored session", job.result.intake["sha256"][:16]
              in reply, reply)
        reply, _ = gw.handle(f"/deepdive callers --sha "
                             f"{job.result.intake['sha256'][:16]}")
        check("gateway deepdive traverses", "E3 caller" in reply, reply)
        reply, _ = gw.handle("/deepdive callers --sha ZZZZ")
        check("bad sha rejected", "hex" in reply or "8..64" in reply)
        reply, _ = gw.handle("/deepdive callers --sha 00000000")
        check("unknown sha honest", "no session" in reply, reply)
        reply, _ = gw.handle("/report --sha " + job.result.intake["sha256"][:16])
        check("report returns stored card or honest note",
              "mock report" in reply or "no stored report" in reply, reply)
        reply, _ = gw.handle("/boguscmd")
        check("unknown command -> help", "vibebot commands" in reply)
        reply, _ = gw.handle("/help")
        check("help lists /analyze", "/analyze" in reply)
        # queue bound: 16 max
        many = []
        for i in range(20):
            try:
                many.append(gw.jobs.submit("analyze", fake, engine="mock"))
            except RuntimeError:
                break
        check("queue bound enforced at max_jobs",
              len(many) == gw.jobs.max_jobs, str(len(many)))

        if HAVE_ANDROGUARD:
            print("== apkmod adapter (androguard present) ==")
            gw2 = gateway.Gateway(td)
            reply, job = gw2.handle(f"/analyze {FIXTURE} --engine apkmod "
                                    f"--fingerprints {EXTRA_FP}")
            check("fixture analyze accepted", job is not None, reply)
            if job is None:
                return 1
            gw2.process_pending()
            check("fixture job COMPLETED", job.state == core.Job.COMPLETED,
                  job.error or "")
            res = job.result
            if res is None:
                return 1
            check("fixture intake sha 64-hex",
                  len(res.intake["sha256"]) == 64)
            check("fixture package com.fixture.demo",
                  res.intake.get("package") == "com.fixture.demo")
            check("fixture findings >= 5", len(res.findings) >= 5,
                  str(len(res.findings)))
            e3 = [f for f in res.findings if f["evidenceLevel"] == "E3"]
            check("fixture has E3 app-caller findings", len(e3) >= 1,
                  str([f["id"] for f in res.findings]))
            cg = [c for f in e3 for c in f.get("callGraph", [])]
            check("fixture E3 callers structured in callGraph", len(cg) >= 4,
                  str(len(cg)))
            check("fixture report written",
                  res.outputs.get("report")
                  and os.path.exists(res.outputs["report"]))
            sess = gw2.sessions.load(res.intake["sha256"])
            if sess is None:
                return 1
            d = core.deepdive(sess, "callers")
            check("fixture deepdive callers >= 4", d["matchCount"] >= 4,
                  str(d["matchCount"]))
            d = core.deepdive(sess, "InterstitialAd")
            check("fixture deepdive by class name", d["matchCount"] >= 1)
        else:
            print("== apkmod adapter: SKIP (androguard not installed) ==")

        print("== telegram transport: construction without network ==")
        g = gateway.Gateway(td)
        t = gateway.TelegramTransport(g, token="TEST-TOKEN-NOT-USED",
                                      allowed_user_ids={"123"})
        check("transport api url from token",
              t.api == "https://api.telegram.org/botTEST-TOKEN-NOT-USED")
        check("token never in gateway help", "TEST-TOKEN-NOT-USED"
              not in g.handle("/help")[0])

    finally:
        shutil.rmtree(td, ignore_errors=True)

    print()
    if failures:
        print(f"vibebot test: FAILED ({len(failures)}): {failures}")
        return 1
    print("vibebot test: ALL PASS"
          + ("" if HAVE_ANDROGUARD else " (apkmod adapter SKIPPED — no androguard)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
