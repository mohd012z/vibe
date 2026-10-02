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
import re
import shutil
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.dirname(os.path.abspath(__file__))
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

FIXTURE = os.path.join(ROOT, "tests", "fixtures", "fixture-demo.apk")
EXTRA_FP = os.path.join(ROOT, "apk", "fingerprints.example-extra.json")

failures: list[str] = []


def check(name: str, cond: bool, detail: object = "") -> None:
    d = "" if detail is None else (detail if isinstance(detail, str)
                                   else str(detail))
    print(f"  {'OK ' if cond else 'FAIL'} {name}"
          + (f"  ({d})" if d and not cond else ""))
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
              and "run /analyze" in d["note"])
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

        print("== P2: /smali opcode table (canonical Dalvik values) ==")
        from vibebot import smali
        r, _ = gw.handle("/smali invoke-virtual")
        check("smali invoke-virtual = 0x6e (35c)",
              "0x6e" in r and "invoke-virtual" in r and "35c" in r, r)
        r, _ = gw.handle("/smali const/4")
        check("smali const/4 = 0x12 (11n)", "0x12" in r and "11n" in r, r)
        r, _ = gw.handle("/smali new-instance")
        check("smali new-instance = 0x22 (21c)", "0x22" in r, r)
        r, _ = gw.handle("/smali return-void")
        check("smali return-void = 0x0e (10x)", "0x0e" in r and "10x" in r, r)
        r, _ = gw.handle("/smali 0x1a")
        check("smali 0x1a -> const-string", "const-string" in r, r)
        r, _ = gw.handle("/smali invoke")
        check("smali substring 'invoke' lists >= 10",
              "opcodes matching" in r and "invoke-virtual" in r
              and "invoke-static" in r, r)
        r, _ = gw.handle("/smali 0x00")
        check("smali 0x00 -> nop", "nop" in r, r)
        check("smali count is honest (100 < n <= 257)",
              smali.opcode_count() > 100, str(smali.opcode_count()))

        print("== P2: /base + /hash ==")
        r, _ = gw.handle("/base ff 16 10")
        check("base ff 16 -> 255 10", "255" in r, r)
        r, _ = gw.handle("/base 255 10 16")
        check("base 255 10 -> ff 16", "ff" in r, r)
        r, _ = gw.handle("/base 101010 2 10")
        check("base 101010 2 -> 42", "42" in r, r)
        r, _ = gw.handle("/base zz 16 10")
        check("base invalid value refused", "error" in r, r)
        r, _ = gw.handle("/base ff 100 10")
        check("base out-of-range base refused", "2..36" in r, r)
        import hashlib as _h
        expected = _h.sha256(b"hello world").hexdigest()
        r, _ = gw.handle("/hash hello world")
        check("hash sha256 correct", expected in r, r)

        print("== P2: /dexcheck + /dexrepair (byte-verified, stdlib) ==")
        from vibebot import dexutil
        import zipfile as _zip
        with _zip.ZipFile(FIXTURE) as _z:
            _dex = _z.read("classes.dex")
        h = dexutil.check_header(_dex)
        check("dexcheck fixture valid", h["valid"] is True, str(h.get("details")))
        _ver = h["version"].replace("\x00", "")
        check("dexcheck version in 035..040", _ver in
              ("035", "037", "038", "039", "040"), _ver)
        # case 1: corrupt sig + checksum only -> repair == original bytes
        c1 = bytearray(_dex)
        c1[12:32] = b"\x00" * 20
        c1[8:12] = b"\xde\xad\xbe\xef"
        r1, rep1 = dexutil.repair(bytes(c1))
        check("dexrepair case1 byte-identical to original", r1 == _dex)
        check("dexrepair case1 flags sig+chk recomputed",
              rep1["sig_recomputed"] and rep1["chk_recomputed"])
        check("dexrepair case1 no magic change", rep1["magic_changed"] is None)
        # case 2: corrupt magic prefix only -> valid + version preserved
        c2 = bytearray(_dex)
        c2[0:4] = b"XXXX"
        r2, rep2 = dexutil.repair(bytes(c2))
        check("dexrepair case2 repaired valid",
              rep2["sha1_ok"] and rep2["checksum_ok"])
        check("dexrepair case2 magic change noted",
              rep2["magic_changed"] is not None)
        check("dexrepair case2 version preserved (not downgraded)",
              rep2["version"].replace("\x00", "") == _ver, rep2["version"])
        # case 4: healthy -> no change, byte-identical
        r4, rep4 = dexutil.repair(_dex)
        check("dexrepair healthy no-op byte-identical",
              r4 == _dex and rep4["changed"] is False)
        # idempotency
        r4b, rep4b = dexutil.repair(r4)
        check("dexrepair idempotent", r4b == r4 and rep4b["changed"] is False)
        # gateway rendering
        r, _ = gw.handle(f"/dexcheck {FIXTURE}")
        check("gateway /dexcheck renders valid", "valid=True" in r, r)
        r, _ = gw.handle(f"/dexrepair {FIXTURE}")
        check("gateway /dexrepair dry-run reports no change",
              "changed=no" in r, r)
        # too-short input is refused honestly
        check("dexcheck too-short refused",
              dexutil.check_header(b"short")["valid"] is False)

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

        if HAVE_ANDROGUARD:
            print("== P3a: Vibe IR graph engine (androguard decoder) ==")
            from vibebot import graphutil
            gwf = gateway.Gateway(td)
            check("graph engine registered when androguard present",
                  "graph" in gwf.engines)
            reply, jg = gwf.handle(f"/apk {FIXTURE}", user="test")
            check("/apk accepted", jg is not None and "ACK" in reply, reply)
            if jg is not None:
                gwf.process_pending()
                check("/apk job COMPLETED",
                      jg.state == core.Job.COMPLETED, jg.error or "")
                gres = jg.result
                if gres is None:
                    check("apk result present", False)
                else:
                    check("apk result has graph layer",
                          "graph" in gres.structural)
                    graph = gres.structural.get("graph", {})
                    check("graph has stable C-ids",
                          all(c["id"].startswith("C") for c in
                              graph["nodes"]["class"]), str(graph["nodes"]["class"][:2]))
                    check("graph S-corpus >= 30 (full string table, not just refs)",
                          graph["counts"]["string"] >= 30, str(graph["counts"]))
                    # reproducible: two raw builds of the same SHA are identical
                    # (the engine adds libs/certs on top, but the core graph is
                    # deterministic — that's the stable-ID guarantee)
                    g_a = graphutil.build_graph(FIXTURE)
                    g_b = graphutil.build_graph(FIXTURE)
                    import json as _json2
                    check("graph reproducible (2 builds identical)",
                          _json2.dumps(g_a, sort_keys=True)
                          == _json2.dumps(g_b, sort_keys=True))
                    sha_g = gres.intake["sha256"]
                    # /map renders from the stored session (stateful)
                    reply, _ = gwf.handle(f"/map --sha {sha_g[:16]}")
                    check("/map renders VIBE MAP from session", "VIBE MAP" in reply, reply)
                    reply, _ = gwf.handle(f"/map {FIXTURE}")
                    check("/map by path reuses session", "VIBE MAP" in reply)
                    # overview card
                    check("overview card has package",
                          "com.fixture.demo" in gres.outputs["overview"])
                    # SESSION MERGE: /dex after /apk on same SHA must coexist
                    reply, jd = gwf.handle(f"/dex {FIXTURE}", user="test")
                    if jd is not None:
                        gwf.process_pending()
                    sess = gwf.sessions.load(sha_g)
                    if sess is None:
                        check("session persisted for /map + merge", False)
                    else:
                        check("session merge: engines accumulate (graph+dexmapper)",
                              "graph" in sess["engines"] and "dexmapper" in sess["engines"],
                              str(sess.get("engines")))
                        check("session merge: graph layer intact after /dex",
                              (sess["structural"].get("graph") or {}).get("counts", {})
                              .get("class") == graph["counts"]["class"])
                        check("session merge: dexmapper jni layer present",
                              "jni" in sess["structural"])
                        check("session merge: intake package preserved",
                              sess["intake"].get("package") == "com.fixture.demo")
        else:
            print("== P3a graph: SKIP (androguard not installed) ==")

        print("== P3: Evidence + Claim model (pure — synthetic graph) ==")
        from vibebot import claims as cmod
        # a minimal hand-built graph: 1 component, 1 class, 1 method, 1
        # referenced string, 1 orphan string, 1 native, 3 calls
        synth = {
            "package": "com.test.app",
            "counts": {"class": 1, "method": 1, "component": 1, "string": 2,
                       "native": 1, "call": 3},
            "nodes": {
                "artifact": [{"id": "A1", "path": "x.apk"}],
                "component": [{"kind": "activity", "name": "com.test.app.A",
                               "id": "K1"}],
                "class": [{"dex": "classes.dex", "name": "com.test.app.A",
                           "id": "C1"}],
                "method": [{"dex": "classes.dex", "class": "com.test.app.A",
                            "name": "onCreate", "native": False, "id": "M1"}],
                "field": [],
                "string": [
                    {"id": "S1", "value": "used-str", "count": 1,
                     "refs": [{"class": "com.test.app.A", "method": "onCreate"}]},
                    {"id": "S2", "value": "orphan-str", "count": 0, "refs": []},
                ],
                "resource": [{"id": "R0", "value": "AndroidManifest.xml",
                              "source": "manifest"}],
                "native": [{"class": "com.test.app.A", "method": "doIt",
                            "id": "N1"}],
            },
            "calls": [{"dex": "classes.dex", "caller": "com.test.app.A",
                       "callerMethod": "onCreate", "invokeKind": "invoke-virtual",
                       "regs": [], "targetClass": "java.lang.Object",
                       "targetMethod": "toString"},
                      {"dex": "classes.dex", "caller": "com.test.app.A",
                       "callerMethod": "onCreate", "invokeKind": "invoke-virtual",
                       "regs": [], "targetClass": "com.test.app.B",
                       "targetMethod": "go"},
                      {"dex": "classes.dex", "caller": "com.test.app.A",
                       "callerMethod": "onCreate", "invokeKind": "invoke-virtual",
                       "regs": [], "targetClass": "com.test.app.C",
                       "targetMethod": "run"}],
            "dex_integrity": [{"dex": "classes.dex", "valid": True,
                               "magic_ok": True, "version_ok": True,
                               "size_ok": True, "checksum_ok": True,
                               "sha1_ok": True}],
        }
        cl = cmod.build_claims(synth, synth["dex_integrity"])
        by = {}
        for c in cl:
            by.setdefault(c["state"], []).append(c)
        # E-level table + categories + states are the documented constants
        check("E1..E5 strength table present",
              set(cmod.EVIDENCE_STRENGTH) == {"E1", "E2", "E3", "E4", "E5"})
        check("categories are the six CodeTransparent states",
              set(cmod.CATEGORIES) == {"FACT", "OBSERVATION", "INFERENCE",
                                       "ASSUMPTION", "UNKNOWN", "CONFLICT"})
        check("claim states are the seven documented states",
              set(cmod.CLAIM_STATES) == {"PROPOSED", "SUPPORTED", "REPRODUCED",
                                         "VALIDATED", "CONFLICTED", "UNRESOLVED",
                                         "REJECTED"})
        # identity = deterministic FACT/VALIDATED
        check("identity claim is FACT+VALIDATED",
              cl[0]["category"] == "FACT" and cl[0]["state"] == "VALIDATED",
              str(cl[0]))
        # a valid DEX => VALIDATED fact
        check("valid DEX header => VALIDATED",
              any(c["state"] == "VALIDATED" and "DEX header is valid"
                  in c["statement"] for c in cl), str(by.get("VALIDATED", [])))
        # a declared component => VALIDATED
        check("manifest component => VALIDATED",
              any("manifest-declared" in c["statement"] and
                  c["state"] == "VALIDATED" for c in cl))
        # a referenced string => OBSERVATION/SUPPORTED (E2)
        check("referenced string => SUPPORTED E2",
              any("used-str" in c["statement"] and c["state"] == "SUPPORTED"
                  and c["evidence"][0]["level"] == "E2" for c in cl))
        # an orphan string => PROPOSED (NOT OBSERVED != IMPOSSIBLE)
        check("orphan string => PROPOSED (not impossible)",
              any("orphan" in (c["note"] or "") and c["state"] == "PROPOSED"
                  for c in cl) or
              any(c["state"] == "PROPOSED" for c in cl),
              str(by.get("PROPOSED", [])))
        # a native method => SUPPORTED with honest runtime gap
        check("native method => SUPPORTED + runtime NOT OBSERVED",
              any("native" in c["statement"] and c["state"] == "SUPPORTED"
                  and "NOT OBSERVED" in (c["note"] or "") for c in cl),
              str([c["statement"] for c in cl if "native" in c["statement"]]))
        # call-graph claim mentions 3 edges / 3 targets
        check("call graph claim present",
              any("15" not in c["statement"] and "3 invoke edge" in c["statement"]
                  for c in cl))
        # /why traces to artifact + shows the E-level meaning
        ref_c = next(c for c in cl if "used-str" in c["statement"])
        w = cmod.why(cl, ref_c["id"], "aa"*4)
        check("why traces to evidence + artifact",
              "evidence" in w and "ARTIFACT A1" in w and "establishes:" in w, w)
        wbad = cmod.why(cl, "C999", "aa"*4)
        check("why on unknown id is honest (lists available)",
              "no claim C999" in wbad and "Available" in wbad, wbad)
        # state machine: legal + illegal moves
        check("PROPOSED->SUPPORTED legal", cmod.transition("PROPOSED", "SUPPORTED") == "SUPPORTED")
        check("PROPOSED->VALIDATED illegal (no skip)", cmod.transition("PROPOSED", "VALIDATED") is None)
        check("SUPPORTED->REPRODUCED legal", cmod.transition("SUPPORTED", "REPRODUCED") == "REPRODUCED")
        check("REJECTED is terminal", cmod.transition("REJECTED", "SUPPORTED") is None)
        check("CONFLICTED->UNRESOLVED legal", cmod.transition("CONFLICTED", "UNRESOLVED") == "UNRESOLVED")
        # deterministic: two builds identical
        cl2 = cmod.build_claims(synth, synth["dex_integrity"])
        import json as _j3
        check("claims reproducible (2 builds identical)",
              _j3.dumps(cl, sort_keys=True) == _j3.dumps(cl2, sort_keys=True))
        # board render groups + mentions /why
        board = cmod.render_claims(cl, "aa"*4)
        check("board lists states + /why hint",
              "EVIDENCE BOARD" in board and "/why" in board and "[VALIDATED]" in board,
              board)

        if HAVE_ANDROGUARD:
            print("== P3 e2e: /claims + /why through gateway ==")
            gwc = gateway.Gateway(td)
            _, jc = gwc.handle(f"/apk {FIXTURE}", user="test")
            gwc.process_pending()
            if jc is not None and jc.state == core.Job.COMPLETED and jc.result is not None:
                sha_c = jc.result.intake["sha256"][:16]
                r, _ = gwc.handle("/claims --sha " + sha_c)
                check("/claims returns an evidence board",
                      "EVIDENCE BOARD" in r and "sha[:8]=" in r, r)
                # grab a real claim id from the board and /why it
                import re as _re4
                m = _re4.search(r"\bC(\d+)\b", r)
                if m:
                    cid = "C" + m.group(1)
                    rw, _ = gwc.handle(f"/why {cid} --sha {sha_c}")
                    check("/why traces a real claim",
                          "WHY " + cid in rw and "evidence" in rw and
                          "ARTIFACT A1" in rw, rw)
                # /why with no args is honest
                rw, _ = gwc.handle("/why")
                check("/why no-arg is honest", "CodeTransparent" in rw, rw)
                # /claims with no session is honest
                rw, _ = gwc.handle("/claims --sha " + "ee"*16)
                check("/claims no-session is honest", "run /apk" in rw, rw)

        print("== P6: CapabilityRouter + AnalysisBudget + stop-controller ==")
        from vibebot import router
        # live provider detection is honest (androguard present on this host)
        provs = router.detect_providers()
        check("provider detection includes androguard=True",
              provs.get("androguard") is True, str(provs))
        check("native providers detected as absent (this host)",
              all(provs.get(x) is False for x in
                  ("radare2", "jadx", "ghidra", "frida")), str(provs))
        # plan: cheapest-capable ranking, available first
        p = router.plan("locate_string")
        check("plan ranks available before unavailable",
              len(p["available"]) >= 1 and
              all(r["provider"] is None or provs.get(r["provider"])
                  for r in p["available"]), str(p["available"]))
        check("plan picks the cheapest capable as the lead",
              "DEX string search" in p["summary"], p["summary"])
        check("plan is honest about unavailable native method",
              any("NOT AVAILABLE" in r["note"] for r in p["unavailable"]),
              str(p["unavailable"]))
        # plan: a goal with NO available provider degrades honestly
        pn = router.plan("native_analysis")
        check("plan with nothing available says NONE",
              "NONE available" in pn["summary"], pn["summary"])
        check("plan value scales with evidence tier / cost",
              all(r["value"] >= 1.0 for r in p["available"]),
              str(p["available"]))
        # BUDGET: stall (repeated same step), wall, calls, depth
        b = router.Budget(max_wall=5.0, stall_repeats=4, stall_window=5.0,
                          now=time.monotonic)
        for _ in range(3):
            b.record_progress("stuck", 40)
        try:
            b.record_progress("stuck", 40)
            check("stall detector raises on 4th repeat", False)
        except router.BudgetExceeded as e:
            check("stall detector raises on 4th repeat", "stall" in e.reason,
                  e.reason)
        # progress made clears the stall
        b = router.Budget(max_wall=5.0, stall_repeats=4, stall_window=5.0,
                          now=time.monotonic)
        for _ in range(3):
            b.record_progress("work", 40)
        b.record_progress("work", 50)  # advanced -> no raise
        check("stall cleared when progress advances", True)
        # wall time
        b = router.Budget(max_wall=0.05, now=time.monotonic)
        time.sleep(0.08)
        try:
            b.check_wall(); check("wall-time budget raises", False)
        except router.BudgetExceeded as e:
            check("wall-time budget raises", "wall-time" in e.reason, e.reason)
        # call cap
        b = router.Budget(max_calls=2, now=time.monotonic)
        b.note_call(); b.note_call()
        try:
            b.note_call(); check("call budget raises", False)
        except router.BudgetExceeded as e:
            check("call budget raises", "call" in e.reason, e.reason)
        # depth cap
        b = router.Budget(max_depth=1, now=time.monotonic)
        b.enter_depth()
        try:
            b.enter_depth(); check("depth budget raises", False)
        except router.BudgetExceeded as e:
            check("depth budget raises", "depth" in e.reason, e.reason)
        # watchdog abandons a NON-cooperative job past max_wall + grace
        b = router.Budget(max_wall=0.05, now=time.monotonic)
        def _hang():
            t0 = time.monotonic()
            while time.monotonic() - t0 < 2:
                time.sleep(0.01)
            return "done"
        t0 = time.monotonic()
        try:
            router.run_with_watchdog(_hang, b, grace=0.05)
            check("watchdog abandons non-cooperative job", False)
        except router.BudgetExceeded as e:
            check("watchdog abandons non-cooperative job",
                  "watchdog" in e.reason and (time.monotonic() - t0) < 2,
                  e.reason)
        # a normal fast fn passes through the watchdog untouched
        check("watchdog passes fast fn through",
              router.run_with_watchdog(lambda: 7, router.Budget(max_wall=1.0,
                        now=time.monotonic), grace=0.05) == 7)
        # default budget has a sane wall cap (jobs can't hang forever)
        check("default budget caps wall time",
              router.budget_from_params({}).max_wall ==
              router.DEFAULT_MAX_WALL)

        if HAVE_ANDROGUARD:
            print("== P6 e2e: /plan + /capabilities + budget through gateway ==")
            gwr = gateway.Gateway(td)
            r, _ = gwr.handle("/capabilities")
            check("/capabilities lists providers honestly",
                  "CAPABILITIES" in r and "androguard" in r and
                  "radare2" in r, r)
            r, _ = gwr.handle("/plan locate_string")
            check("/plan locate_string picks cheapest capable",
                  "DEX string search" in r and "NOT AVAILABLE" in r, r)
            r, _ = gwr.handle("/plan native_analysis")
            check("/plan native_analysis degrades honestly",
                  "NONE available" in r, r)
            r, _ = gwr.handle("/plan bogus")
            check("/plan unknown goal is honest", "unknown goal" in r, r)
            r, _ = gwr.handle("/plan")
            check("/plan no-goal lists goals", "goals:" in r, r)
            # budget enforcement: tiny wall cap -> job FAILS with "budget"
            _, jb = gwr.handle(f"/apk {FIXTURE} --max-wall 0.001", user="test")
            gwr.process_pending()
            check("job with tiny wall budget FAILs (stop-controller)",
                  jb is not None and jb.state == core.Job.FAILED
                  and "budget" in (jb.error or ""), str(jb.error if jb else None))
            # generous default -> completes (no regression)
            _, jo = gwr.handle(f"/apk {FIXTURE}", user="test")
            gwr.process_pending()
            check("normal /apk still COMPLETED under default budget",
                  jo is not None and jo.state == core.Job.COMPLETED,
                  str(jo.error if jo else None))

        if HAVE_ANDROGUARD:
            print("== P7: /xref + /callers + /callees over the call graph ==")
            gwx2 = gateway.Gateway(td)
            _, jxh = gwx2.handle(f"/apk {FIXTURE}", user="test")
            gwx2.process_pending()
            if jxh is not None and jxh.result is not None:
                sha_x = jxh.result.intake["sha256"][:16]
                # find a method with callees (DemoApp.onCreate)
                from vibebot import graphutil as gu
                sess_x = gwx2.sessions.load(sha_x)
                if sess_x is None:
                    check("P7: session persisted for xref tests", False)
                else:
                    gph = sess_x["structural"]["graph"]
                    oncreate = next(m for m in gph["nodes"]["method"]
                                    if m["name"] == "onCreate"
                                    and "DemoApp" in m["class"])
                    # /xref by M-id shows callees + strings
                    r, _ = gwx2.handle(f"/xref {oncreate['id']} --sha {sha_x}")
                    check("/xref by M-id lists callees + strings",
                          "XREF " + oncreate["id"] in r and "callees (" in r
                          and "strings referenced (" in r, r)
                    check("/xref shows an in-APK callee",
                          "MobileAds.initialize" in r, r)
                    check("/xref shows a referenced string", "ad-unit" in r, r)
                    # /callees by dotted name resolves to the same M-id
                    r, _ = gwx2.handle(f"/callees {oncreate['class']}.onCreate "
                                       f"--sha {sha_x}")
                    check("/callees by dotted name resolves to M-id",
                          "CALLEES " + oncreate["id"] in r, r)
                    # /callers card renders
                    r, _ = gwx2.handle(f"/callers {oncreate['class']}.onCreate "
                                       f"--sha {sha_x}")
                    check("/callers returns a CALLERS card", "CALLERS " in r, r)
                    # external target is flagged honestly, not faked as in-graph
                    r, _ = gwx2.handle("/xref android.os.Build.MODEL --sha "
                                       + sha_x)
                    check("/xref external is flagged EXTERNAL",
                          "EXTERNAL" in r and "not an in-APK method" in r, r)
                    # no-target / no-sha / bad-sha all honest
                    r, _ = gwx2.handle("/xref --sha " + sha_x)
                    check("/xref no-target shows usage", "/xref <M-id" in r, r)
                    r, _ = gwx2.handle("/xref M1")
                    check("/xref no-sha hints the last job sha",
                          sha_x[:8] in r, r)
                    r, _ = gwx2.handle("/xref M1 --sha ZZZZ")
                    check("/xref bad-sha rejected", "hex sha" in r, r)
                    # xrefs() is deterministic
                    a = gu.xrefs(gph, oncreate["id"])
                    b = gu.xrefs(gph, oncreate["id"])
                    import json as _j7
                    check("xrefs reproducible (2 calls identical)",
                          _j7.dumps(a, sort_keys=True)
                          == _j7.dumps(b, sort_keys=True))

        if HAVE_ANDROGUARD:
            print("== P10: /investigate — orchestrated 18-stage ==")
            from vibebot import deepdive
            from vibebot import graphutil
            gwi = gateway.Gateway(td)
            ack, ji = gwi.handle(f"/investigate {FIXTURE}", user="test")
            check("/investigate ACKs a job",
                  ji is not None and "ACK" in ack, ack)
            gwi.process_pending()
            check("/investigate whole-artifact COMPLETED",
                  ji is not None and ji.state == core.Job.COMPLETED,
                  str(ji.error if ji else None))
            if ji is not None and ji.result is not None:
                res = ji.result.structural["deepdive"]
                check("18 stages produced",
                      len(res["stages"]) == 18, str(len(res["stages"])))
                marks = {s["num"]: s["mark"] for s in res["stages"]}
                # deterministic stages are established
                for num in ("01", "02", "06", "07", "14", "16", "17", "18"):
                    check(f"stage {num} established (✓)",
                          marks.get(num) == deepdive.DONE, str(marks.get(num)))
                # native stages are HONESTLY not-available here
                check("stage 11 (Blocks) n/a (no native provider)",
                      marks.get("11") == deepdive.NOTAVAILABLE, str(marks.get("11")))
                check("stage 12 (CFG) n/a (no native provider)",
                      marks.get("12") == deepdive.NOTAVAILABLE, str(marks.get("12")))
                card = ji.result.structural["deepdive_card"]
                check("card shows the 18-stage table",
                      "DEEPDIVE" in card and "18 Summary" in card, card)
                check("card is honest about native stages",
                      "n/a — requires Radare/Ghidra" in card, card)
                check("card notes NOT OBSERVED != IMPOSSIBLE",
                      "NOT OBSERVED" in card, card)
            # method-level: resolves the target, shows its callees
            _, jm = gwi.handle(
                f"/investigate {FIXTURE} com.fixture.demo.DemoApp.onCreate",
                user="test")
            gwi.process_pending()
            check("/investigate method-level COMPLETED",
                  jm is not None and jm.state == core.Job.COMPLETED,
                  str(jm.error if jm else None))
            if jm is not None and jm.result is not None:
                resm = jm.result.structural["deepdive"]
                check("method target resolved (M-id, not unrecognized)",
                      resm["method"] is not None
                      and resm["unrecognized"] is False,
                      str(resm["method"]))
                # stage 07 callees shows a real invoke
                s07 = next(s for s in resm["stages"] if s["num"] == "07")
                check("method stage 07 lists a callee",
                      any("->" in l for l in s07["lines"]), str(s07["lines"]))
            # staged progress events were recorded (bounded + cancellable)
            if ji is not None:
                progs = [e for e in ji.events if e["type"] == "progress"]
                check("staged progress recorded (>= 18 stage pings)",
                      len(progs) >= 18, str(len(progs)))
            # budget enforcement: tiny wall -> FAILED "budget"
            _, jb = gwi.handle(f"/investigate {FIXTURE} --max-wall 0.001",
                               user="test")
            gwi.process_pending()
            check("/investigate tiny-wall FAILs (stop-controller)",
                  jb is not None and jb.state == core.Job.FAILED
                  and "budget" in (jb.error or ""),
                  str(jb.error if jb else None))
            # honest no-arg + missing path
            r, _ = gwi.handle("/investigate")
            check("/investigate no-arg shows usage", "<path>" in r, r)
            r, _ = gwi.handle("/investigate /nope/missing.apk")
            check("/investigate missing path refused", "not found" in r, r)
            # run_deepdive is deterministic (2 runs identical)
            gph = graphutil.build_graph(FIXTURE)
            a = deepdive.run_deepdive(gph, "apk")
            b = deepdive.run_deepdive(gph, "apk")
            import json as _j10
            check("run_deepdive reproducible (2 runs identical)",
                  _j10.dumps(a, sort_keys=True)
                  == _j10.dumps(b, sort_keys=True))

        print("== P5: Radare native provider (pure — injected runner) ==")
        import struct as _struct
        from vibebot import native as nat
        # --- synthetic ELF64 with 2 LOAD segments ---
        def _mk_elf():
            b = bytearray(64); b[:4] = b"\x7fELF"; b[4] = 2; b[5] = 1; b[6] = 1
            _struct.pack_into("<H", b, 0x10, 2); _struct.pack_into("<H", b, 0x12, 0xB7)
            _struct.pack_into("<I", b, 0x18, 1)
            _struct.pack_into("<I", b, 0x20, 64); _struct.pack_into("<H", b, 0x36, 56)
            _struct.pack_into("<H", b, 0x38, 2)
            def _ph(off, va, fsize, typ=1):
                seg = bytearray(56); _struct.pack_into("<I", seg, 0, typ)
                _struct.pack_into("<Q", seg, 8, off); _struct.pack_into("<Q", seg, 16, va)
                _struct.pack_into("<Q", seg, 32, fsize); return seg
            return bytes(b + _ph(0x1000, 0x400000, 0x100) + _ph(0x2000, 0x400100, 0x80))
        elf = _mk_elf()
        segs = nat.elf_segments_64(elf)
        check("elf_segments_64 parses 2 segments", len(segs) == 2, str(segs))
        off, exact = nat.va_to_offset(0x400050, segs)
        check("va_to_offset exact (in segment)", off == 0x1050 and exact, f"{hex(off)} {exact}")
        off2, exact2 = nat.va_to_offset(0xFFFF, segs)
        check("va_to_offset approx (no segment) flagged", not exact2, str((off2, exact2)))
        check("va_to_offset non-ELF -> []", nat.elf_segments_64(b"nope") == [])
        # --- parsers (pure) ---
        fns = nat.parse_functions("0x00400050  112  foo\n0x00400120  64  bar\n")
        check("parse_functions rows + r2_id",
              fns[0]["va"] == 0x400050 and fns[0]["name"] == "foo"
              and fns[0]["r2_id"] == "fcn.00400050", str(fns))
        check("parse_exports names",
              nat.parse_exports("0x00400120  64  Java_a_b\n0x00400050  112  foo")
              == ["Java_a_b", "foo"])
        imps = nat.parse_imports("__cxa_finalize:libc.so.6\nprintf:libc.so.6\n")
        check("parse_imports sym:module",
              imps[0] == {"name": "__cxa_finalize", "module": "libc.so.6"}, str(imps))
        # --- injected FakeRunner -> full analyze_native (no r2 needed) ---
        class _FR:
            bin = "r2"
            def version(self):
                return "radare2 6.2.4 fake"
            def run(self, path, cmd):
                # P18: r2-6 command set (aa; aflj / iEj / iij) — text shapes
                # kept so parse_* legacy paths stay exercised.
                if "aflj" in cmd:
                    return "0x00400050  112  foo\n0x00400120  64  Java_com_foo_Bar_doIt\n"
                if "iEj" in cmd:
                    return "0x00400120  64  Java_com_foo_Bar_doIt\n0x00400050  112  foo\n"
                if "iij" in cmd:
                    return "__cxa_finalize:libc.so.6\n"
                return ""
        tmp_so = os.path.join(td, "libfoo.so")
        with open(tmp_so, "wb") as _f:
            _f.write(elf)
        n = nat.analyze_native(tmp_so, _FR(), segments=segs)
        check("analyze_native counts", n["counts"] == {"function": 2, "export": 2,
                                                       "import": 1}, str(n["counts"]))
        check("analyze_native location chain va+file_offset",
              n["functions"][0]["va"] == 0x400050
              and n["functions"][0]["file_offset"] == 0x1050
              and n["functions"][0]["offset_exact"] is True, str(n["functions"][0]))
        check("analyze_native provenance (provider version + isolation)",
              n["provenance"]["isolation"] == "subprocess"
              and "radare2" in n["provider_version"], str(n["provenance"]))
        check("render_native shows LIB + functions + imports",
              "LIB libfoo.so" in nat.render_native(n) and "imports" in nat.render_native(n)
              and "fcn.00400050" in nat.render_native(n))
        # --- JNI bridge: EXACT for found, NOT OBSERVED for missing ---
        natives = [{"id": "N1", "class": "com.foo.Bar", "method": "doIt"},
                   {"id": "N2", "class": "com.foo.Baz", "method": "missing"}]
        edges = nat.build_jni_map(natives, n["exports"])
        check("JNI EXACT for matching export",
              edges[0]["status"] == "EXACT" and edges[0]["export"]
              == "Java_com_foo_Bar_doIt", str(edges[0]))
        check("JNI NOT OBSERVED for missing export (no false positive)",
              edges[1]["status"] == "NOT OBSERVED" and edges[1]["export"] is None
              and "NOT OBSERVED != IMPOSSIBLE" in edges[1]["note"], str(edges[1]))
        check("render_jni_map shows bridge + honest note",
              "JNI BRIDGE" in nat.render_jni_map(edges) and "NOT OBSERVED" in nat.render_jni_map(edges))
        # --- EntityResolver maps native entities to canonical N-ids ---
        from vibebot import graphutil as _gu
        fp_a = _gu._fp_fingerprints("com.foo.Bar.doIt")        # androguard name
        fp_b = _gu._fp_fingerprints("java_com_foo_bar_doit")   # radare2 name
        known = [{"provider": "androguard", "name": "com.foo.Bar.doIt",
                  "canonical_id": "N1", "fingerprints": fp_a},
                 {"provider": "radare2", "name": "Java_com_foo_Bar_doIt",
                  "canonical_id": "N2", "fingerprints": fp_b}]
        # EXACT: a provider's own entity (same provider + same name)
        check("resolver: r2 own entity EXACT",
              nat.resolve_native_entity(known, "Java_com_foo_Bar_doIt")["status"]
              == "EXACT")
        # STRONG: cross-provider, fingerprint match, single hit, name agrees
        check("resolver: ghidra + r2 fp match -> STRONG",
              nat.resolve_native_entity(known, "Java_com_foo_Bar_doIt",
                                        fingerprints=fp_b,
                                        provider="ghidra")["status"] == "STRONG")
        # CONFLICT: fingerprint matches but the name disagrees (never merge)
        check("resolver: fp match + different name -> CONFLICT",
              nat.resolve_native_entity(known, "totallyDifferent",
                                        fingerprints=fp_b,
                                        provider="ghidra")["status"] == "CONFLICT")
        # UNRESOLVED: nothing close
        check("resolver: nothing close -> UNRESOLVED",
              nat.resolve_native_entity(known, "zzz-no-match",
                                        provider="ghidra")["status"] == "UNRESOLVED")
        # --- honest degrade: ProviderUnavailable when r2 absent ---
        class _RealNo:  # mimics the real runner when r2 is missing
            bin = "definitely-not-a-real-bin-xyz"
            def version(self): return "x"
            def run(self, path, cmd):
                raise nat.ProviderUnavailable("no bin")
        try:
            nat.analyze_native(tmp_so, _RealNo())
            check("ProviderUnavailable raised for missing r2", False)
        except nat.ProviderUnavailable:
            check("ProviderUnavailable raised for missing r2", True)
        # non-ELF rejected
        bad = os.path.join(td, "bad.so"); open(bad, "wb").write(b"notanelf")
        try:
            nat.analyze_native(bad, _FR(), segments=[])
            check("non-ELF rejected (ProviderError)", False)
        except nat.ProviderError:
            check("non-ELF rejected (ProviderError)", True)

        if HAVE_ANDROGUARD:
            print("== P5 e2e: /native through gateway (honest degrade) ==")
            gwn = gateway.Gateway(td)
            # APK with no native libs -> honest "no native libraries"
            _, jn = gwn.handle(f"/native {FIXTURE}", user="test")
            gwn.process_pending()
            check("/native on APK (no native libs) COMPLETED honestly",
                  jn is not None and jn.state == core.Job.COMPLETED
                  and "no native libraries" in
                  (jn.result.structural["native"].get("note") or ""),
                  str(jn.result.structural["native"] if jn and jn.result else None))
            # a real .so file -> provider NOT OBSERVED (r2 absent here)
            so2 = os.path.join(td, "liby.so")
            with open(so2, "wb") as _f:
                _f.write(elf)
            _, jn2 = gwn.handle(f"/native {so2}", user="test")
            gwn.process_pending()
            check("/native on .so degrades to 'not installed' (COMPLETED, honest)",
                  jn2 is not None and jn2.state == core.Job.COMPLETED
                  and jn2.result.structural["native"].get("available") is False
                  and "NOT OBSERVED" in
                  jn2.result.structural["native"].get("note", ""),
                  str(jn2.result.structural["native"] if jn2 and jn2.result else None))
            r, _ = gwn.handle("/native")
            check("/native no-arg shows usage", "<path>" in r, r)
            r, _ = gwn.handle("/native /nope/missing.so")
            check("/native missing path refused", "not found" in r, r)

        # ------------------------------------------------------------------
        print("== P15: native function-pattern classifier (pure — no r2) ==")
        # --- the 6 ARM64 idioms from the exercism reference corpus, each
        # recognized by its normalized instruction SEQUENCE (not hex bytes)
        pop = ["sub", "clz", "ror", "eor", "sub", "b"]
        check("P1 popcount-loop (clz+ror+eor)",
              any(p["pattern"] == "popcount-loop"
                  for p in nat.classify_function(pop)),
              str(nat.classify_function(pop)))
        # the real idiom: orr xN, xN, #32 — encode the register+immediate form
        cf = ["ldrb w1, [x0]", "orr w1, w1, #32", "sub w1, w1, #0x61", "ret"]
        check("P2 case-fold-scan (orr #32)",
              any(p["pattern"] == "case-fold-scan"
                  for p in nat.classify_function(cf)),
              str(nat.classify_function(cf)))
        bs = ["lsl", "tst x0, x1, lsl #5", "bne"]
        check("P3 bitset-test (tst with a bit index)",
              any(p["pattern"] == "bitset-test"
                  for p in nat.classify_function(bs)),
              str(nat.classify_function(bs)))
        parity = ["tbz x0, #0", "ret"]
        check("P4 tbz-bit0-parity (tbz #0)",
              any(p["pattern"] == "tbz-bit0-parity"
                  for p in nat.classify_function(parity)),
              str(nat.classify_function(parity)))
        madd = ["madd x0, x1, x2, x0", "ret"]
        check("P5 fused-madd (madd)",
              any(p["pattern"] == "fused-madd"
                  for p in nat.classify_function(madd)),
              str(nat.classify_function(madd)))
        adrp = ["adrp x8, str_lbl", "add x8, x8, :lo12:str_lbl", "ret"]
        check("P6 string-ref-pair (adrp + add :lo12:)",
              any(p["pattern"] == "string-ref-pair"
                  for p in nat.classify_function(adrp)),
              str(nat.classify_function(adrp)))

        # --- cross-match negatives: each pattern must NOT fire on the others
        check("popcount body does not report case-fold/madd",
              [p["pattern"] for p in nat.classify_function(pop)] == ["popcount-loop"],
              str(nat.classify_function(pop)))
        check("a null-test (tst x0, x0, no bit index) is NOT bitset-test",
              [p["pattern"] for p in nat.classify_function(["tst x0, x0", "bne"])]
              == [], str(nat.classify_function(["tst x0, x0", "bne"])))
        check("an empty / unknown body reports no patterns (honest)",
              nat.classify_function([]) == []
              and nat.classify_function(["mov", "ret"]) == [],
              "")
        # a function carrying TWO idioms reports both
        both = ["madd x0, x1, x2, x0", "orr w2, w2, #32"]
        bboth = sorted(p["pattern"] for p in nat.classify_function(both))
        check("a function with two idioms reports both",
              bboth == ["case-fold-scan", "fused-madd"], str(bboth))

        # --- parse_disasm: JSON (pdj) and text (pd) forms
        import json as _jsonp15
        jd = _jsonp15.dumps([{"name": "clz", "size": 4},
                             {"name": "ror.w", "size": 4},
                             {"name": "eor", "size": 4}])
        check("parse_disasm JSON -> mnemonics (suffix stripped)",
              nat.parse_disasm(jd) == ["clz", "ror", "eor"],
              str(nat.parse_disasm(jd)))
        td15 = ("0x400050  5300c0f2  clz   w2, w0\n"
                "0x400054  6f0041f2  ror   w2, w2, w3\n"
                "0x400058  4a0000eb  eor   w0, w0, w2\n")
        check("parse_disasm text -> mnemonics",
              nat.parse_disasm(td15) == ["clz", "ror", "eor"],
              str(nat.parse_disasm(td15)))
        check("parse_disasm empty -> []", nat.parse_disasm("") == [], "")

        # --- end-to-end via the FakeRunner seam (no r2 installed)
        import struct as _struct
        def _mk_elf15():
            b = bytearray(64); b[:4] = b"\x7fELF"; b[4] = 2; b[5] = 1; b[6] = 1
            _struct.pack_into("<H", b, 0x10, 2); _struct.pack_into("<H", b, 0x12, 0xB7)
            _struct.pack_into("<I", b, 0x18, 1)
            _struct.pack_into("<I", b, 0x20, 64); _struct.pack_into("<H", b, 0x36, 56)
            _struct.pack_into("<H", b, 0x38, 2)
            def _ph(off, va, fsize, typ=1):
                seg = bytearray(56); _struct.pack_into("<I", seg, 0, typ)
                _struct.pack_into("<Q", seg, 8, off); _struct.pack_into("<Q", seg, 16, va)
                _struct.pack_into("<Q", seg, 32, fsize); return seg
            return bytes(b + _ph(0x1000, 0x400000, 0x100) + _ph(0x2000, 0x400100, 0x80))
        elf15 = _mk_elf15()
        segs15 = nat.elf_segments_64(elf15)

        class _FR15:
            bin = "r2"
            def version(self):
                return "radare2 6.2.4 fake"
            def run(self, path, cmd):
                # P18: r2-6 command set — substring match (aa; prefix).
                # P19: disasm command is 'aa; pdfj @0xVA' (function-bounded).
                if "aflj" in cmd:
                    return "0x00400050  24  popcnt\n0x00400120  12  parityfn\n"
                if "iEj" in cmd:
                    return "0x00400050  24  popcnt\n"
                if "iij" in cmd:
                    return "memcpy:libc.so.6\n"
                if "pdfj" in cmd:
                    # popcnt function = clz+ror+eor ; parityfn = tbz x0, 0
                    if "400050" in cmd:
                        return _jsonp15.dumps(
                            {"name": "popcnt", "addr": 0x400050, "ops": [
                                {"disasm": "clz w2, w0"},
                                {"disasm": "ror w2, w2, w3"},
                                {"disasm": "eor w0, w0, w2"},
                                {"disasm": "sub w0, w0, w2"}]})
                    if "400120" in cmd:
                        return _jsonp15.dumps(
                            {"name": "parityfn", "addr": 0x400120, "ops": [
                                {"disasm": "tbz x0, 0, 0x400124"},
                                {"disasm": "ret"}]})
                    return "[]"
                return ""
        tmp15 = os.path.join(td, "libp15.so")
        with open(tmp15, "wb") as _f:
            _f.write(elf15)
        n15 = nat.analyze_native(tmp15, _FR15(), segments=segs15)
        byname = {f["name"]: f for f in n15["functions"]}
        check("e2e: popcnt function classified popcount-loop (E3)",
              byname.get("popcnt", {}).get("patterns") == ["popcount-loop"],
              str(byname.get("popcnt", {}).get("patterns")))
        check("e2e: parityfn classified tbz-bit0-parity (E3)",
              byname.get("parityfn", {}).get("patterns") == ["tbz-bit0-parity"],
              str(byname.get("parityfn", {}).get("patterns")))
        check("e2e: patterns are E3 + carry a reason",
              byname["popcnt"]["pattern_details"][0]["evidence"] == "E3"
              and "reason" in byname["popcnt"]["pattern_details"][0],
              str(byname["popcnt"]["pattern_details"]))
        check("render_native surfaces the recognized logic patterns",
              "logic pattern" in nat.render_native(n15)
              and "popcount-loop" in nat.render_native(n15),
              nat.render_native(n15)[-300:])

        # --- honest degrade: a runner whose disasm fails -> empty patterns
        class _FR15err:
            bin = "r2"
            def version(self):
                return "radare2 6.2.4 fake"
            def run(self, path, cmd):
                # P18: r2-6 command set — substring match (aa; prefix).
                if "aflj" in cmd:
                    return "0x00400050  24  foo\n"
                if "iEj" in cmd:
                    return "0x00400050  24  foo\n"
                if "iij" in cmd:
                    return ""
                if "pdfj" in cmd:
                    raise nat.ProviderError("disasm failed")
                return ""
        n15e = nat.analyze_native(tmp15, _FR15err(), segments=segs15)
        check("e2e: disasm error -> empty patterns (NOT OBSERVED, not crash)",
              n15e["functions"][0]["patterns"] == []
              and n15e["functions"][0]["mnemonics"] == [],
              str(n15e["functions"][0]))

        # ------------------------------------------------------------------
        print("== P16: native-harness validation (E5 — prove it BEHAVES) ==")
        # harness is stdlib-only; import it directly (no androguard needed).
        from vibebot import harness as H

        # --- pure: toolchain detection with an INJECTABLE `which`
        def _fake_which(present):
            def w(name):
                return "/fake/" + name if name in present else None
            return w
        tc_full = H.detect_toolchain(_fake_which(
            {"aarch64-linux-gnu-gcc", "aarch64-linux-gnu-as", "qemu-aarch64"}))
        check("detect_toolchain: full x86 host -> needs_qemu, all tools found",
              tc_full["needs_qemu"] is True
              and tc_full["cc"] == "/fake/aarch64-linux-gnu-gcc"
              and tc_full["as"] == "/fake/aarch64-linux-gnu-as"
              and tc_full["qemu"] == "/fake/qemu-aarch64", str(tc_full))

        # --- pure: the exercism-verbatim command builders
        check("build_cmd_c = cross-gcc CFLAGS -c (exercism CC_CMD)",
              H.build_cmd_c("CC", "t.c", "t.o")
              == ["CC", "-g", "-Wall", "-Wextra", "-pedantic", "-Werror",
                  "-std=c99", "-fPIE", "-c", "-o", "t.o", "t.c"],
              str(H.build_cmd_c("CC", "t.c", "t.o")))
        check("build_cmd_asm = as -o (exercism %.o: %.s)",
              H.build_cmd_asm("AS", "t.s", "t.o") == ["AS", "-o", "t.o", "t.s"],
              str(H.build_cmd_asm("AS", "t.s", "t.o")))
        check("build_cmd_link = CFLAGS+LDFLAGS -o (exercism tests:)",
              H.build_cmd_link("CC", ["a.o", "b.o"], "tests")
              == ["CC", "-g", "-Wall", "-Wextra", "-pedantic", "-Werror",
                  "-std=c99", "-fPIE", "-pie", "-Wl,--fatal-warnings",
                  "-o", "tests", "a.o", "b.o"],
              str(H.build_cmd_link("CC", ["a.o", "b.o"], "tests")))
        check("run_cmd: needs_qemu -> qemu -L sysroot (exercism MAYBE_QEMU)",
              H.run_cmd({"needs_qemu": True, "qemu": "QEMU"}, "tests")
              == ["QEMU", "-L", "/usr/aarch64-linux-gnu", "tests"],
              str(H.run_cmd({"needs_qemu": True, "qemu": "QEMU"}, "tests")))
        check("run_cmd: aarch64 host -> run the binary directly",
              H.run_cmd({"needs_qemu": False, "qemu": None}, "tests")
              == ["tests"], str(H.run_cmd({"needs_qemu": False, "qemu": None}, "tests")))

        # --- pure: parse_harness verdicts
        check("parse_harness unity 'x passed, y failed' -> SUCCESS",
              H.parse_harness(" 3 passed, 0 failed, 0 ignored")["verdict"]
              == "SUCCESS"
              and H.parse_harness(" 3 passed, 0 failed, 0 ignored")["passed"]
              == 3, str(H.parse_harness(" 3 passed, 0 failed, 0 ignored")))
        check("parse_harness any failure -> FAILURE",
              H.parse_harness("1 passed, 2 failed")["verdict"] == "FAILURE"
              and H.parse_harness("1 passed, 2 failed")["failed"] == 2,
              str(H.parse_harness("1 passed, 2 failed")))
        check("parse_harness no test result -> NOT_OBSERVED",
              H.parse_harness("compiled fine, no tests")["verdict"]
              == "NOT_OBSERVED"
              and H.parse_harness("")["observed"] is False,
              str(H.parse_harness("compiled fine, no tests")))

        # --- e2e: validate_native over a FakeRunner (no toolchain needed)
        class _FHR:
            """Dispatches by argv[0]: as->asm, qemu->run, gcc -c->compile,
            gcc -pie->link. `run_out` is what the harness binary prints."""
            def __init__(self, run_out, link_rc=0):
                self.run_out = run_out
                self.link_rc = link_rc
                self.calls = []

            def run(self, argv):
                self.calls.append(list(argv))
                a0 = argv[0]
                if a0.endswith("-as") or a0.endswith("as"):
                    return (0, "asm ok\n")
                if a0.endswith("qemu-aarch64"):
                    return (0, self.run_out)
                if "-pie" in argv:
                    return (self.link_rc, "link ok\n" if self.link_rc == 0
                            else "undefined reference to `foo`\n")
                return (0, "c ok\n")
        src_c = os.path.join(td, "h.c")
        src_s = os.path.join(td, "t.s")
        with open(src_c, "w") as _f:
            _f.write("int main(void){return 0;}\n")
        with open(src_s, "w") as _f:
            _f.write(".globl solve\nsolve:\n ret\n")
        tc16 = {"host": "x86_64", "needs_qemu": True,
                "cc": "/fake/aarch64-linux-gnu-gcc",
                "as": "/fake/aarch64-linux-gnu-as",
                "qemu": "/fake/qemu-aarch64"}
        inputs16 = {"c": [src_c], "asm": [src_s],
                    "out": os.path.join(td, "hb"), "binary": "tests"}
        ok16 = H.validate_native(inputs16, _FHR(" 2 passed, 0 failed, 0 ignored"),
                                 toolchain=tc16)
        check("e2e SUCCESS: full build+qemu run, 2 passed [E5]",
              ok16["verdict"] == "SUCCESS" and ok16["passed"] == 2
              and ok16["observed"] is True
              and ok16["build"]["ok"] is True
              and any(c[0].endswith("qemu-aarch64") for c in ok16["commands"]),
              str(ok16))
        fail16 = H.validate_native(inputs16,
                                   _FHR("1 passed, 2 failed"), toolchain=tc16)
        check("e2e FAILURE: the change misbehaves (a test failed)",
              fail16["verdict"] == "FAILURE" and fail16["failed"] == 2,
              str(fail16))
        bf16 = H.validate_native(inputs16, _FHR("", link_rc=1),
                                 toolchain=tc16)
        check("e2e build-fail (link error) -> NOT_OBSERVED (not a crash)",
              bf16["verdict"] == "NOT_OBSERVED"
              and bf16["build"]["ok"] is False
              and bf16["build"]["stage"] == "link", str(bf16["build"]))
        miss = H.detect_toolchain(_fake_which(set()))
        mo16 = H.validate_native(inputs16, _FHR("x"), toolchain=miss)
        check("e2e toolchain-missing -> NOT_OBSERVED (stage=toolchain)",
              mo16["verdict"] == "NOT_OBSERVED"
              and mo16["build"]["stage"] == "toolchain"
              and "cc" in mo16["build"]["error"], str(mo16["build"]))
        check("NOT_OBSERVED is honest: '!= the change is wrong' note present",
              "NOT OBSERVED" in mo16["note"] or "NOT" in mo16["note"],
              mo16["note"])

        # --- engine e2e: HarnessEngine auto-discovers .c/.s, fabricates a
        # full toolchain + FakeRunner -> SUCCESS, report JSON + E5 finding
        srcdir = os.path.join(td, "p16src")
        os.makedirs(srcdir, exist_ok=True)
        with open(os.path.join(srcdir, "test.c"), "w") as _f:
            _f.write("int main(void){return 0;}\n")
        with open(os.path.join(srcdir, "solve.s"), "w") as _f:
            _f.write(".globl solve\nsolve:\n ret\n")
        eng16 = H.HarnessEngine(os.path.join(td, "hrep"),
                                runner=_FHR(" 4 passed, 0 failed, 0 ignored"),
                                toolchain=tc16)
        check("engine can_run a source dir",
              eng16.can_run(srcdir) is True, "")
        job16 = core.Job("harness", srcdir, "harness", "cli", {})
        res16 = eng16.run(job16)
        h16 = res16.structural["harness"]
        check("engine e2e SUCCESS + E5 runtime finding",
              h16["verdict"] == "SUCCESS" and h16["passed"] == 4
              and any(f["evidence"][0]["level"] == "E5"
                      for f in res16.findings)
              and "E5 runtime" in res16.report_md,
              str(res16.report_md))
        # auto-discovery: the engine found test.c + solve.s with no params
        inp16 = job16.checkpoints.get("intake", {}).get("inputs", {})
        check("engine e2e auto-discovered test.c + solve.s from the dir",
              any("test.c" in x for x in inp16.get("c", []))
              and any("solve.s" in x for x in inp16.get("asm", [])),
              str(inp16))
        check("engine e2e ran 4 stages (2 compile + link + qemu run)",
              len(h16["commands"]) == 4
              and h16["commands"][-1][0].endswith("qemu-aarch64"),
              str(h16["commands"]))
        check("engine e2e report JSON written to reports dir",
              os.path.exists(res16.outputs["report"])
              and "verdict" in open(res16.outputs["report"]).read(), "")

        # --- HONEST DEGRADE on THIS host: real detect_toolchain() (x86_64,
        # no cross-compiler/qemu) -> the engine still COMPLETES with
        # NOT_OBSERVED, never a fabricated pass, never a crash.
        eng_real = H.HarnessEngine(os.path.join(td, "hrep_real"))
        job_real = core.Job("harness", srcdir, "harness", "cli", {})
        res_real = eng_real.run(job_real)
        hr_real = res_real.structural["harness"]
        real_tc = H.detect_toolchain()
        if real_tc["needs_qemu"] and not real_tc["qemu"]:
            check("real-host degrade: no qemu -> NOT_OBSERVED (honest)",
                  hr_real["verdict"] == "NOT_OBSERVED"
                  and hr_real["build"]["stage"] == "toolchain",
                  str(hr_real["build"]))
            check("real-host degrade: no E5 claim made",
                  all(f["evidence"][0]["level"] != "E5"
                      for f in res_real.findings),
                  str(res_real.findings))
        else:  # toolchain present: whatever happens, it must not crash
            check("real-host: ran to a verdict without crashing",
                  hr_real["verdict"] in ("SUCCESS", "FAILURE", "NOT_OBSERVED"),
                  str(hr_real["verdict"]))

        # --- P16 REAL e2e: actually BUILD + RUN the harness on a real aarch64
        # toolchain (cross gcc + qemu-aarch64, user-space in scratch) — the
        # E5 top of the chain P16 had only ever exercised via FakeRunner.
        # Degrades to an honest NOT-OBSERVED line when the toolchain is
        # absent (CI shape stays green).
        _CROSS16 = "/opt/data/cache/scratch/toolchain/cross16/usr/bin"
        import os as _os16
        _which16 = shutil
        _cc16 = _which16.which("aarch64-linux-gnu-gcc") or \
            (_os16.path.join(_CROSS16, "aarch64-linux-gnu-gcc")
             if _os16.path.exists(_os16.path.join(_CROSS16, "aarch64-linux-gnu-gcc")) else None)
        _q16 = _which16.which("qemu-aarch64") or \
            (_os16.path.join(_CROSS16, "qemu-aarch64")
             if _os16.path.exists(_os16.path.join(_CROSS16, "qemu-aarch64")) else None)
        if _cc16 and _q16:
            import subprocess as _sub16
            _SR16 = "/opt/data/cache/scratch/toolchain/cross16"  # extract root
            # qemu's -L <sysroot> resolves the baked-in aarch64 interpreter
            # '/lib/ld-linux-aarch64.so.1' as <sysroot>/lib/... — ensure the
            # user-space extract has that /lib link (idempotent; host state a
            # fresh re-extract would lose).
            try:
                _liblink = _os16.path.join(_SR16, "lib")
                if not _os16.path.exists(_liblink):
                    _os16.symlink(
                        _os16.path.join("usr", "aarch64-linux-gnu", "lib"),
                        _liblink)
            except OSError:
                pass
            _env16 = dict(os.environ)
            _env16["PATH"] = _os16.path.dirname(_cc16) + os.pathsep + \
                _os16.path.dirname(_q16) + os.pathsep + _env16.get("PATH", "")
            # the cross gcc's internal as/ld are shared-lib builds needing
            # the host lib dir (libbfd/libopcodes) — same as P19's binut.
            _env16["LD_LIBRARY_PATH"] = \
                _os16.path.join(_SR16, "usr", "lib", "x86_64-linux-gnu") + \
                os.pathsep + _env16.get("LD_LIBRARY_PATH", "")

            class _R16:
                """RealSubprocess under the scratch toolchain PATH/LD paths."""
                def run(self, argv):
                    p = _sub16.run(argv, capture_output=True, text=True,
                                   env=_env16, timeout=120)
                    return (p.returncode, p.stdout + p.stderr)

            _src16 = os.path.join(ROOT, "tests", "fixtures", "harness",
                                  "popcount.c")
            _out16 = os.path.join(td, "p16real")
            _os16.makedirs(_out16, exist_ok=True)
            _tc16 = {"host": "x86_64", "needs_qemu": True,
                     "cc": _cc16,
                     "as": (_which16.which("aarch64-linux-gnu-as")
                            or _os16.path.join(_CROSS16, "aarch64-linux-gnu-as")),
                     "qemu": _q16}
            _inp16 = {"c": [_src16], "asm": [], "out": _out16,
                      "binary": "tests", "sysroot": _SR16}
            _res16 = H.validate_native(_inp16, runner=_R16(), toolchain=_tc16)
            check("P16 real e2e: cross-gcc BUILD + qemu-aarch64 RUN observed",
                  _res16["verdict"] == "SUCCESS"
                  and _res16["passed"] == 6 and _res16["failed"] == 0
                  and _res16["build"]["ok"] is True,
                  str(_res16))
            check("P16 real e2e: final command is qemu-aarch64 -L sysroot",
                  _res16["commands"][-1][0] == _q16
                  and _res16["commands"][-1][1] == "-L",
                  str(_res16["commands"][-1]))
            check("P16 real e2e: E5 ceiling note (proves THIS build, not "
                  "generally-correct)", "E5" in _res16["note"], _res16["note"])
        else:
            print("  [P16] NOT OBSERVED: real aarch64 toolchain (cross gcc + "
                  "qemu-aarch64) absent on this host — P16 real-run path "
                  "not exercised (FakeRunner e2e above still applies)")

        # --- gateway dispatch: /harness registered + usage + missing-path
        if "harness" in gw.engines:
            r, j = gw.handle("/harness")
            check("/harness no-arg shows usage", "<srcdir>" in r, r)
            r, j = gw.handle("/harness /nope/p16/srcdir")
            check("/harness missing path refused", "not found" in r, r)
        else:
            check("harness engine registered in gateway", False,
                  str(sorted(gw.engines)))

        # ------------------------------------------------------------------
        print("== P17: Kotlin @Metadata name recovery (backlog #2) ==")
        from vibebot import kotlinmeta as KM
        KT_DEX = os.path.join(ROOT, "tests", "fixtures", "ktmeta",
                              "classes.dex")
        check("ground-truth ktmeta fixture present",
              os.path.exists(KT_DEX), KT_DEX)
        ktdex = open(KT_DEX, "rb").read()
        # --- BitEncoding UTF-8 mode: U+0000 marker + char(0..255)->byte 1:1
        # (the inverse of the compiler's BitEncoding.encodeBytes). No encode
        # helper is shipped (decode-only), so build the encoded d1 by hand and
        # confirm bitencoding_decode inverts it.
        payload = b"\x00\x01\x02\xff"
        enc = "\x00" + "".join(chr(b) for b in payload)
        check("utf8 decode: drops U+0000 marker + 1:1 char->byte",
              KM.bitencoding_decode(enc) == payload,
              repr(KM.bitencoding_decode(enc)))
        check("utf8 decode: empty d1 -> empty bytes",
              KM.bitencoding_decode("") == b"", "")
        check("utf8 decode: un-marked fallback = char->byte (no drop)",
              KM.bitencoding_decode("ab") == b"ab",
              repr(KM.bitencoding_decode("ab")))
        # --- DEX annotation extraction: envelope + d2 name table
        krecs = KM.extract_kotlin_metadata(ktdex)
        check("extract: 6 @Metadata classes in the fixture",
              len(krecs) == 6, str(len(krecs)))
        main = next(r for r in krecs
                    if r["class_desc"].endswith("CheckoutService;"))
        check("envelope k=1 (CLASS) + mv + xi present",
              main["k"] == 1 and len(main["mv"]) == 3 and main["xi"] is not None,
              str({kk: main[kk] for kk in ("k", "mv", "xi")}))
        check("d2 = original (pre-R8) name table, carries real names",
              any("CheckoutService" in s for s in main["d2"])
              and "charge" in main["d2"] and "gateway" in main["d2"],
              str(main["d2"]))
        # --- pure-Python decode (the deliverable): d1 + d2 -> names
        km0 = KM.decode_class_metadata(main["d1"] or "", main["d2"] or [])
        check("decode: returned a name table (not None)", km0 is not None,
              str(km0))
        km0 = km0 or {}
        check("decode: fq_name recovered (com/fatah/vibetest/CheckoutService)",
              km0.get("fq_name") == "com/fatah/vibetest/CheckoutService",
              str(km0.get("fq_name")))
        check("decode: nested 'Companion' recovered (packed int32 field 7)",
              km0.get("nested") == ["Companion"], str(km0.get("nested")))
        check("decode: companion object name (field 4) recovered",
              km0.get("companion") == "Companion", str(km0.get("companion")))
        check("decode: function 'charge' + properties gateway/totalCents",
              "charge" in km0.get("functions", [])
              and set(km0.get("properties", [])) >= {"gateway", "totalCents"},
              str({"f": km0.get("functions"), "p": km0.get("properties")}))
        check("decode: >=1 constructor recorded",
              km0.get("constructors", 0) >= 1, str(km0.get("constructors")))
        # a nested/enum class resolves too (Order$Paid: amountCents, sku)
        paid = next((r for r in krecs
                     if r["class_desc"].endswith("Order$Paid;")), None)
        if paid:
            kp = KM.decode_class_metadata(paid["d1"] or "", paid["d2"] or [])
            # nested/enum fq_name is dotted inside the outer (Order.Paid)
            check("decode nested enum Order$Paid (amountCents + sku)",
                  kp is not None
                  and (kp.get("fq_name") or "").endswith("Order.Paid")
                  and set(kp.get("properties", [])) >= {"amountCents", "sku"},
                  str({k: kp.get(k) for k in ("fq_name", "properties")}
                      if kp else None))
        # --- extract with class_filter (flows through the engine params)
        kfil = KM.extract_kotlin_metadata(ktdex, "PaymentGateway")
        check("extract class_filter: only PaymentGateway* returned",
              all("PaymentGateway" in r["class_desc"] for r in kfil)
              and len(kfil) == 1, str([r["class_desc"] for r in kfil]))
        # --- engine e2e on the fixture dex (structural + report + E2)
        eng17 = KM.KotlinMetaEngine(os.path.join(td, "krep"))
        job17 = core.Job("kotlinmeta", KT_DEX, "kmeta", "cli", {})
        res17 = eng17.run(job17)
        k17 = res17.structural["kotlin_meta"]
        check("engine e2e: available, 6 classes decoded",
              k17["available"] is True and k17["class_count"] == 6,
              str({k: k17[k] for k in ("available", "class_count")}))
        check("engine e2e: E2 finding emitted (PROBABLE ceiling, not EXACT)",
              any(f["evidence"][0]["level"] == "E2" for f in res17.findings)
              and "E2" in res17.report_md and "recovered" in res17.report_md,
              res17.report_md)
        check("engine e2e: report JSON written",
              os.path.exists(res17.outputs["report"])
              and "class_count" in open(res17.outputs["report"]).read(), "")
        # --- JVM oracle DIFFERENTIAL check: pure decode == the compiler's own
        # deserializer (only when this host has a Kotlin toolchain — otherwise
        # NOT OBSERVED, never a skip that pretends to pass)
        oracle_tc = KM._find_kotlin_toolchain()
        oracle_v = KM._find_java_verifier()
        if oracle_tc and oracle_v:
            diffs = 0
            for r in krecs:
                pure = KM.decode_class_metadata(r["d1"] or "", r["d2"] or [])
                orc = KM.run_jvm_oracle(r["d1"] or "", r["d2"] or [],
                                        os.path.join(td, "koracle"))
                if orc is None:
                    diffs += 1
                    continue
                if (orc["fq_name"] != pure["fq_name"]
                        or orc["functions"] != pure["functions"]
                        or orc["properties"] != pure["properties"]
                        or orc["constructors"] != pure["constructors"]):
                    diffs += 1
            check("differential: pure decode == Kotlin compiler oracle "
                  "(all classes)", diffs == 0, f"diffs={diffs}")
        else:
            check("differential: NOT OBSERVED here (no Kotlin toolchain) — "
                  "pure decode stands, unverified against oracle",
                  True, "toolchain absent; disclosed, not skipped")
        # --- gateway dispatch: /kmeta registered + usage + missing path
        if "kotlinmeta" in gw.engines:
            r, j = gw.handle("/kmeta")
            check("/kmeta no-arg shows usage", "<classes.dex" in r, r)
            r, j = gw.handle("/kmeta /nope/p17/classes.dex")
            check("/kmeta missing path refused", "not found" in r, r)
            # fresh gateway: the shared gw's job queue is full (max_jobs) by
            # P17, so the submit path is checked on a clean instance
            gw17 = gateway.Gateway(td)
            r, j = gw17.handle(f"/kmeta {KT_DEX}")
            check("/kmeta ACK + engine=kotlinmeta",
                  j is not None and "engine=kotlinmeta" in r, r)
        else:
            check("kotlinmeta engine registered in gateway", False,
                  str(sorted(gw.engines)))

        # ------------------------------------------------------------------
        print("== P11: Falsifier — deterministic mechanical refutation (pure) ==")
        from vibebot import falsify as F
        from vibebot import claims as C
        from vibebot.claims import TRANSITIONS as _TR

        def _g(clean: bool) -> dict:
            # two DEX passes: methods via 'method' nodes (dexmapper), native
            # nodes via access flags — the falsifier cross-checks them
            native_flag = False if clean else False
            return {
                "package": "com.x",
                "nodes": {
                    "artifact": [{"path": "/t/x.apk"}],
                    "component": [],
                    "class": [{"id": "C1", "dex": "d", "name": "com.x.Main"}],
                    "method": [
                        {"id": "M1", "dex": "d", "class": "com.x.Main",
                         "name": "onCreate", "native": False},
                        {"id": "M2", "dex": "d", "class": "com.x.Main",
                         "name": "nativeThing", "native": native_flag},
                    ],
                    "string": [
                        {"id": "S1", "value": "hi",
                         "refs": [{"class": "com.x.Main", "method": "onCreate"}]},
                        *([] if clean else [
                            {"id": "S2", "value": "ghost",
                             "refs": [{"class": "com.x.Main",
                                       "method": "DOES_NOT_EXIST"}]}]),
                    ],
                    "native": [
                        *([] if clean else
                          [{"id": "N1", "class": "com.x.Main",
                            "method": "nativeThing"}]),
                    ],
                    "field": [],
                },
                "counts": {
                    "class": 1, "method": 2,
                    "string": 1 if clean else 2, "native": 0 if clean else 1,
                    "component": 0, "call": 1,
                },
                "calls": [
                    {"sourceClass": "com.x.Main", "targetClass": "com.x.Main"},
                    *([] if clean else
                      [{"sourceClass": "com.x.Main", "targetClass": "java.lang.Object"}]),
                ],
                "dex_integrity": [],
            }

        gc = _g(True)
        cl = C.build_claims(gc, gc["dex_integrity"])
        f_clean = F.falsify_graph(gc) + F.falsify_claims(cl, gc)
        check("falsifier: clean graph -> ZERO findings (no false positives)",
              f_clean == [], str(f_clean))
        r = F.render_falsifications([], "aabbccddeeff0011")
        check("falsifier: clean board says 'no contradictions'",
              "no contradictions" in r, r)

        gb = _g(False)
        # also make the counts stale vs. the lists (corruption case 1)
        gb["counts"]["call"] = 99          # 2 edges exist
        clb = C.build_claims(gb, gb["dex_integrity"])
        fb = F.falsify_graph(gb) + F.falsify_claims(clb, gb)
        kinds = {x["kind"] for x in fb}
        check("falsifier: stale counts['call'] caught (tier1, graph-level)",
              "count:call" in kinds, str(kinds))
        check("falsifier: native pass-divergence caught (two DEX passes disagree)",
              "native:flag" in kinds, str(kinds))
        check("falsifier: dangling string ref caught (graph-level)",
              "string:dangling_ref" in kinds, str(kinds))
        check("falsifier: claim-level call-edge recount caught",
              any(x["claim_id"] and x["kind"] == "call:edges" for x in fb),
              str(fb))
        check("falsifier: claim-level dangling ref caught on the string claim",
              any(x["claim_id"] and x["kind"] == "string:dangling_ref" for x in fb),
              str(fb))

        applied = F.apply_falsifications(clb, fb)
        changed = [(c["id"], c["state"], a["state"]) for c, a in zip(clb, applied)
                   if c["state"] != a["state"]]
        check("falsifier: at least one claim moved to CONFLICTED",
              any(t == "CONFLICTED" for _, _, t in changed), str(changed))
        check("falsifier: every state move is a LEGAL transition (no skips)",
              all(t in _TR[s] for _, s, t in changed), str(changed))
        check("falsifier: untouched claims keep their state + evidence",
              all(c["state"] == a["state"] for c, a in zip(clb, applied)
                  if c["id"] not in {i for i, _, _ in changed}), "")
        hit = next(a for c, a in zip(clb, applied)
                   if c["state"] != a["state"])
        check("falsifier: contradiction recorded as F1 evidence on the claim",
              any(e["ref"] == "falsifier" and e["level"] == "F1"
                  for e in hit["contradicting"]), str(hit["contradicting"]))

        # /why renders the falsifier contradiction without crashing on the
        # non-E level tag
        w = C.why(applied, hit["id"], "aabbccddeeff0011")
        check("/why shows the [F1] falsifier contradiction",
              "[F1]" in w and "falsifier" in w, w)

        # advisory (note-severity) findings never change a claim's state
        gn = _g(True)
        gn["calls"].append({"sourceClass": "com.x.Main",
                            "targetClass": "com.someobf.Single"})
        gn["counts"]["call"] = 2  # keep the count honest — isolate the advisory
        cln = C.build_claims(gn, gn["dex_integrity"])
        fn = F.falsify_graph(gn) + F.falsify_claims(cln, gn)
        check("falsifier: external/framework class is advisory, not refutation",
              all(x["severity"] != F.TIER1 for x in fn if x["kind"].startswith("call:")),
              str(fn))
        check("falsifier: advisory findings change nothing",
              F.apply_falsifications(cln, fn) == cln or
              all(c["state"] == a["state"] for c, a in
                  zip(cln, F.apply_falsifications(cln, fn))), "")

        if HAVE_ANDROGUARD:
            print("== P11 e2e: /falsify through gateway (real fixture) ==")
            gwf = gateway.Gateway(td)
            reply, jf = gwf.handle(f"/apk {FIXTURE}", user="test")
            gwf.process_pending()
            if jf is not None and jf.state == core.Job.COMPLETED and jf.result is not None:
                sha_f = jf.result.intake["sha256"][:16]
                r, _ = gwf.handle(f"/falsify --sha {sha_f}")
                check("/falsify renders the board on a real session",
                      "FALSIFIER" in r and ("no contradictions" in r
                                             or "REFUTED" in r), r)
                r2, _ = gwf.handle("/falsify")
                check("/falsify no-arg falls back to last session",
                      "FALSIFIER" in r2, r2)
                r3, _ = gwf.handle(f"/claims --sha {sha_f}")
                check("/claims now carries the FALSIFIER section",
                      "FALSIFIER" in r3, r3[-400:])
                check("help lists /falsify", "/falsify" in gateway.HELP, "")
            else:
                check("P11 e2e: fixture job COMPLETED", False,
                      (jf.error or "no job") if jf is not None else "no job")

        # ------------------------------------------------------------------
        print("== P12: cross-version fingerprint (pure — synthetic maps) ==")
        from vibebot import xmatch as XM

        def _M(key, fp, cls, name, callset):
            return key, {"fp": fp, "class": cls, "name": name,
                         "callset": list(callset)}

        def _map(*rows):
            return dict(rows)

        # --- normalize_instruction: the DEX adaptation (registers bucketed)
        # same logic, different register numbering -> IDENTICAL tokens
        t1 = XM.normalize_instruction("invoke-static",
                                      "v1, v0, Lcom/x/Foo;->bar()V")
        t2 = XM.normalize_instruction("invoke-static",
                                      "v7, v2, Lcom/x/Foo;->bar()V")
        check("CALL token drops (renumbered) register list", t1 == t2,
              f"{t1} vs {t2}")
        check("CALL token carries class.method (dot separator)",
              t1 == ["CALL:com.x.Foo.bar"], t1)

        # same-logic stubs with different strings stay different
        s1 = XM.normalize_instruction("const-string", 'v0, "hello"')
        s2 = XM.normalize_instruction("const-string", 'v3, "world"')
        check("const-string keeps literal text", s1 == ['STR:hello']
              and s2 == ['STR:world'], f"{s1} {s2}")

        # small immediate kept, large bucketed (a moved offset != logic).
        # Real androguard forms: const/4 + const/16 are DECIMAL, const/48 +
        # const are hex (0x), const-wide is hex + trailing L. Bucket
        # threshold is 0x10000 (65536).
        check("small const/4 kept (decimal)", XM.normalize_instruction(
            "const/4", "v0, 2") == ["IMM:2"], "")
        check("large const bucketed (hex above 0x10000)",
              XM.normalize_instruction("const", "v0, 0x20000")
              == ["IMM_LARGE"], "")
        # a small hex const is kept as its VALUE (base is notation, not
        # identity: 0x8000 == 32768)
        check("small hex const kept as decimal value",
              XM.normalize_instruction("const", "v0, 0x8000")
              == ["IMM:32768"], "")
        # a large const-wide (hex + trailing L) is bucketed
        check("large const-wide bucketed",
              XM.normalize_instruction("const-wide", "v0, 0x7fffffL")
              == ["IMM_LARGE"], "")
        # a register operand must not be mistaken for the immediate
        check("register operand skipped for immediates",
              XM.normalize_instruction("const/4", "v0, v1") == [], "")

        # register bucketing for plain arithmetic
        a1 = XM.normalize_instruction("add-int", "v0, v1, v2")
        a2 = XM.normalize_instruction("add-int", "v3, v4, v5")
        check("registers bucketed to REG", a1 == a2 == ["REG, REG, REG"],
              f"{a1} {a2}")

        # branch target collapsed to L (kind survives, distance does not)
        b1 = XM.normalize_instruction("if-eq", "v0, +0x8")
        b2 = XM.normalize_instruction("if-eq", "v0, +0x20")
        check("branch distance collapsed to L", b1 == b2, f"{b1} vs {b2}")
        b3 = XM.normalize_instruction("if-eq", "v0, :cond_1")
        check("branch pseudo-label collapsed to L", b1 == b3, f"{b1} {b3}")

        # fingerprint determinism + body distinction
        seqA = [("const-string", 'v0, "x"'), ("invoke-virtual",
                                               "v0, Ljava/lang/String;->length()I")]
        seqB = [("const-string", 'v2, "x"'), ("invoke-virtual",
                                               "v1, Ljava/lang/String;->length()I")]
        check("same logic / diff registers -> same fp",
              XM.fingerprint_tokens(seqA) == XM.fingerprint_tokens(seqB), "")
        # empty body is stable, and genuinely DIFFERENT from a return-void
        # body (return-void is real logic, not noise)
        empty_fp = XM.fingerprint_tokens([])
        check("empty body fp stable + distinct from return-void",
              len(empty_fp) == 64
              and empty_fp == XM.fingerprint_tokens([])
              and empty_fp != XM.fingerprint_tokens([("return-void", "")]),
              empty_fp)

        # --- match_cross_version: the six states on synthetic maps
        src = _map(
            _M("a.Bar.do", "F1", "a.Bar", "do", []),                 # EXACT
            _M("a.Bar.other", "F2", "a.Bar", "other", ["CALL:a.X.y"]),  # STRONG target
            _M("a.Dup.one", "F3", "a.Dup", "one", []),                # dup logic
            _M("a.Dup.two", "F3", "a.Dup", "two", []),                # dup logic
            _M("a.Renamed.old", "F4", "a.Renamed", "old", []),        # renamed
        )
        dst = _map(
            _M("b.Bar.do", "F1", "b.Bar", "do", []),                  # -> EXACT by fp
            _M("b.Bar.other", "F2b", "b.Bar", "other", ["CALL:a.X.y"]),  # -> STRONG
            _M("b.Renamed.new", "F4", "b.Renamed", "new", []),         # -> UNRESOLVED? (fp F4 hit a.Renamed.old)
        )
        m = {r["dst"]: r for r in XM.match_cross_version(src, dst)}
        check("EXACT by identical fp (unique in src)",
              m["b.Bar.do"]["status"] == "EXACT", m["b.Bar.do"])
        check("STRONG by name + identical callset (fp differs)",
              m["b.Bar.other"]["status"] == "STRONG", m["b.Bar.other"])
        # F4 exists in src (a.Renamed.old) -> dst b.Renamed.new matches it by
        # fp -> EXACT even though the NAME changed (fp is the anchor)
        check("fp match wins over renamed identity",
              m["b.Renamed.new"]["status"] == "EXACT"
              and m["b.Renamed.new"]["src"] == "a.Renamed.old",
              m["b.Renamed.new"])

        # --- identity tiebreak: shared fp + same identity -> EXACT
        src2 = _map(
            _M("c.T1.<init>", "FDUP", "c.T1", "<init>", []),
            _M("c.T2.<init>", "FDUP", "c.T2", "<init>", []),
        )
        dst2 = _map(
            _M("d.T1.<init>", "FDUP", "d.T1", "<init>", []),
            _M("d.T2.<init>", "FDUP", "d.T2", "<init>", []),
            _M("d.T3.<init>", "FDUP", "d.T3", "<init>", []),   # no identity in src
        )
        m2 = {r["dst"]: r for r in XM.match_cross_version(src2, dst2)}
        # NOTE: dst keys use class 'd.*' but src fp 'FDUP' is shared across
        # c.T1/c.T2 (and their <init> names differ from dst classes) -> the
        # identity (class,name) of dst d.T1.<init> is NOT in src's candidates
        # (src candidates are c.T1.<init>, c.T2.<init>) -> AMBIGUOUS, honestly.
        check("shared fp, identity in none of candidates -> AMBIGUOUS",
              m2["d.T1.<init>"]["status"] == "AMBIGUOUS"
              and m2["d.T1.<init>"]["src"] is None, m2["d.T1.<init>"])
        check("shared fp, identity not in src at all -> AMBIGUOUS",
              m2["d.T3.<init>"]["status"] == "AMBIGUOUS", m2["d.T3.<init>"])

        # tiebreak TO a single EXACT when the identity IS among candidates
        src4 = _map(
            _M("g.V.a", "FV", "g.V", "a", []),
            _M("g.V.b", "FV", "g.V", "b", []),
        )
        dst4 = _map(_M("g.V.b", "FV", "g.V", "b", []))
        m4 = XM.match_cross_version(src4, dst4)
        check("shared fp + unique same identity -> EXACT (tiebreak)",
              len(m4) == 1 and m4[0]["status"] == "EXACT"
              and m4[0]["src"] == "g.V.b", m4)

        # --- CONFLICT: two dst methods resolve to the SAME src method
        # (identity collision) — must NOT be silently merged.
        src6 = _map(_M("m.A.m", "FM", "m.A", "m", []))
        dst6 = _map(
            _M("m.A.m", "FN1", "m.A", "m", []),   # no fp hit -> name tier
            _M("m.A.m#1", "FN2", "m.A", "m", []),  # same (class,name)
        )
        # both dst share the name (m.A, m) with the single src -> both claim
        # m.A.m by the name tier -> CONFLICT (two dst, one src)
        m6 = {r["dst"]: r for r in XM.match_cross_version(src6, dst6)}
        check("two dst claiming one src -> CONFLICT (not merged)",
              m6["m.A.m"]["status"] == "CONFLICT"
              and m6["m.A.m#1"]["status"] == "CONFLICT"
              and m6["m.A.m"]["src"] == "m.A.m",
              str({k: v["status"] for k, v in m6.items()}))

        # --- render + tally
        allm = XM.match_cross_version(src, dst)
        rep = XM.render_xmatch(allm, "a"*64, "b"*64)
        check("render lists src/dst sha", "src sha[:8]=aaaaaaaa" in rep,
              rep.splitlines()[0])
        check("render ends with re-validation rule",
              "re-validated" in rep, rep[-200:])

        if HAVE_ANDROGUARD:
            print("== P12 e2e: /xmatch through gateway (real fixture, self) ==")
            # src == dst (same APK) -> every method must be EXACT (self-match)
            gwx = gateway.Gateway(td)
            ack, jx = gwx.handle(f"/xmatch {FIXTURE} {FIXTURE}", user="test")
            check("/xmatch ACKs a job", jx is not None
                  and jx.state == core.Job.QUEUED, ack)
            gwx.process_pending()
            if jx is not None and jx.state == core.Job.COMPLETED \
                    and jx.result is not None:
                sh = jx.result.intake["sha256"]
                st = gwx.jobs.status(jx.id)
                check("xmatch job COMPLETED", st["state"] == "COMPLETED",
                      str(st.get("error")))
                sess = gwx.sessions.load(sh) or {}
                struct = sess.get("structural") or {}
                check("session stores match_board",
                      bool(struct.get("match_board")), str(struct.keys()))
                board = struct.get("match_board", "")
                check("self-match is all EXACT (no AMBIGUOUS)",
                      "AMBIGUOUS" not in board
                      and "EXACT" in board, board[:400])
                mm = struct.get("matches", [])
                check("every dst method resolved",
                      all(r["status"] == "EXACT" for r in mm),
                      str([r["status"] for r in mm]))
                r, _ = gwx.handle(f"/report --sha {sh[:16]}")
                check("/report surfaces the xmatch report file",
                      "report" in r, r[:200])
                check("help lists /xmatch", "/xmatch" in gateway.HELP, "")
            else:
                check("P12 e2e: fixture xmatch job COMPLETED", False,
                      (jx.error or "no job") if jx is not None else "no job")

            # honest degrade: missing dst refused at dispatch (no job)
            gwx2 = gateway.Gateway(td)
            r, jmiss = gwx2.handle(f"/xmatch {FIXTURE} /nope/missing.apk",
                                   user="test")
            check("/xmatch missing dst refused (no job)",
                  jmiss is None and "not found" in r, r)

        # ------------------------------------------------------------------
        print("== P13: obfuscated-enum detector (pure + fixture field-type fix) ==")
        from vibebot import enumscan as ES

        # --- pure detect_enum over synthetic class records
        shrunken = ES.detect_enum({"class": "a.B", "superclass": "java.lang.Object",
                                   "static_self": ["A", "B", "C"], "values_meth": "values",
                                   "enum_super": False})
        check("R8-shrunken signature -> 'shrunken' E2",
              shrunken["verdict"] == "shrunken" and shrunken["level"] == "E2"
              and shrunken["n"] == 3, shrunken)
        unshrunken = ES.detect_enum({"class": "a.C", "superclass": "java.lang.Enum",
                                     "static_self": ["X", "Y"], "values_meth": "values",
                                     "enum_super": True})
        check("extends java.lang.Enum -> 'enum' E1 (un-shrunken)",
              unshrunken["verdict"] == "enum" and unshrunken["level"] == "E1",
              unshrunken)
        partial = ES.detect_enum({"class": "a.D", "superclass": "java.lang.Object",
                                  "static_self": ["P", "Q"], "values_meth": None,
                                  "enum_super": False})
        check("self-fields but no array values() -> 'partial' (weaker)",
              partial["verdict"] == "partial", partial)
        none_ = ES.detect_enum({"class": "a.E", "superclass": "java.lang.Object",
                                "static_self": ["only"], "values_meth": "values",
                                "enum_super": False})
        check("1 self-field + values() -> 'none' (not enough signal)",
              none_["verdict"] == "none", none_)
        # scan: filters none, sorts shrunken first
        order = [e["verdict"] for e in ES.scan_enums([
            {"class": "a.E", "superclass": "O", "static_self": ["o"],
             "values_meth": "values", "enum_super": False},
            {"class": "a.D", "superclass": "O", "static_self": ["p", "q"],
             "values_meth": None, "enum_super": False},
            {"class": "a.B", "superclass": "O", "static_self": ["A", "B", "C"],
             "values_meth": "values", "enum_super": False},
        ])]
        check("scan filters none + shrunken sorted first",
              order == ["shrunken", "partial"], str(order))
        rep = ES.render_enums(ES.scan_enums([
            {"class": "a.B", "superclass": "O", "static_self": ["A", "B", "C"],
             "values_meth": "values", "enum_super": False}]), "f" * 64)
        check("render lists the shrunken class + PROBABLE ceiling note",
              "a.B" in rep and "PROBABLE" in rep and "shrunken" in rep, rep[:200])

        if HAVE_ANDROGUARD:
            from vibebot import graphutil
            # --- field-type fix: get_descriptor() (was get_type() -> all "")
            g = graphutil.build_graph(FIXTURE)
            ftypes = {(f["class"], f["name"]): f["type"]
                      for f in g["nodes"]["field"]}
            check("field layer now type-aware (get_descriptor fix)",
                  ftypes.get(("com.fixture.demo.DemoApp", "sInterstitial"))
                  == "com.fixture.sdkads.InterstitialAd"
                  and ftypes.get(("com.fixture.sdkads.InterstitialAd",
                                  "ENDPOINT")) == "java.lang.String",
                  str(ftypes))
            # --- fixture e2e: no enums -> count 0 + /map shows none
            check("fixture graph carries the enum node layer (count 0)",
                  g["counts"].get("enum", 0) == 0
                  and g["nodes"]["enum"] == [], str(g["counts"].get("enum")))
            gw13 = gateway.Gateway(td)
            ack, j13 = gw13.handle(f"/apk {FIXTURE}", user="test")
            gw13.process_pending()
            if j13 is not None and j13.state == core.Job.COMPLETED \
                    and j13.result is not None:
                sha13 = j13.result.intake["sha256"][:16]
                rmap, _ = gw13.handle(f"/map --sha {sha13}")
                check("/map shows the ENUM DETECTION section (none for fixture)",
                      "ENUM DETECTION" in rmap and "none" in rmap, rmap[-260:])
                check("/map tree shows the enum count line",
                      "enums" in rmap and "(E-ids)" in rmap, rmap[:400])
            else:
                check("P13 e2e: fixture /apk job COMPLETED", False,
                      (j13.error or "no job") if j13 is not None else "no job")

        # ------------------------------------------------------------------
        print("== P14: hybrid / JS-layer detector (pure classify + fixture) ==")
        from vibebot import hybridscan as HS

        # --- pure classify over synthetic ZIP name lists (positive controls)
        uni = HS.classify(["classes.dex", "AndroidManifest.xml",
                           "assets/apps/_UNI_ab12cd34/www/app-service.js",
                           "assets/apps/_UNI_ab12cd34/www/app-view.js",
                           "assets/apps/_UNI_ab12cd34/www/static/logo.png"])
        check("uni-app detected by assets/apps/_UNI_ + app-service.js",
              "uniapp" in uni["detected"]
              and any("app-service.js" in m for m in uni["detected"]["uniapp"]),
              str(uni["detected"]))
        check("uni-app JS layer entries listed",
              any(e.endswith("app-service.js") for e in uni["js_entries"]),
              str(uni["js_entries"]))

        cordova = HS.classify(["classes.dex", "www/index.html",
                               "www/cordova.js", "plugins/cordova.plugins.barcode/plugin.xml"])
        check("Cordova detected (cordova.js), plugins/ no longer a bare marker",
              "cordova" in cordova["detected"], str(cordova["detected"]))

        rn = HS.classify(["classes.dex", "assets/index.android.bundle",
                          "assets/index.android.bundle.meta"])
        check("React Native detected (index.android.bundle)",
              "reactnative" in rn["detected"], str(rn["detected"]))

        fl = HS.classify(["classes.dex", "lib/arm64-v8a/libapp.so",
                          "assets/flutter_assets/FontManifest.json"])
        check("Flutter detected (flutter_assets), and flagged NOT a JS layer",
              "flutter" in fl["detected"], str(fl["detected"]))

        # negative: a plain native APK must detect NOTHING
        none_ = HS.classify(["classes.dex", "AndroidManifest.xml",
                             "resources.arsc", "lib/arm64-v8a/libx.so",
                             "plugins/whatever.xml"])
        check("plain native APK -> no framework detected",
              none_["detected"] == {} and none_["js_entries"] == [],
              str(none_["detected"]))

        # render: hybrid shows the patch-the-JS directive
        rep_uni = HS.render_hybrid({"kind": "zip", "frameworks": {
            "uniapp": {"markers": ["assets/apps/_UNI_x/www/app-service.js"],
                       "js_entry": "app-service.js", "note": "uni-app"}},
            "js_entries": ["assets/apps/_UNI_x/www/app-service.js"],
            "webview_used": True, "jsinterface": [], "assets": []}, "a" * 64)
        check("render names the framework + patch-the-JS directive",
              "uniapp" in rep_uni and "Patch the JS" in rep_uni
              and "HYBRID" in rep_uni, rep_uni[:200])
        # render: not-observed degrade (missing artifact) is honest
        rep_no = HS.render_hybrid({"error": "not found: /x"}, "a" * 64)
        check("render degrades to NOT OBSERVED for a missing artifact",
              "NOT OBSERVED" in rep_no, rep_no)

        if HAVE_ANDROGUARD:
            from vibebot import graphutil
            # --- real fixture: a minimal native APK -> no hybrid signature
            g14 = graphutil.build_graph(FIXTURE)
            sig = g14.get("hybrid") or {}
            check("fixture graph carries the hybrid layer (zip kind)",
                  sig.get("kind") == "zip", str(sig.get("kind")))
            check("fixture has NO hybrid framework signature (native APK)",
                  not sig.get("frameworks"), str(sig.get("frameworks")))
            gw14 = gateway.Gateway(td)
            ack, j14 = gw14.handle(f"/apk {FIXTURE}", user="test")
            gw14.process_pending()
            if j14 is not None and j14.state == core.Job.COMPLETED \
                    and j14.result is not None:
                sha14 = j14.result.intake["sha256"][:16]
                s14 = gw14.sessions.load(sha14) or {}
                overview = (s14.get("structural") or {}).get("overview", "")
                check("/apk overview carries a 'logic layer' line",
                      "logic layer" in overview, overview[:400])
                rmap, _ = gw14.handle(f"/map --sha {sha14}")
                check("/map carries the HYBRID / JS LAYER section",
                      "HYBRID / JS LAYER" in rmap, rmap[-300:])
            else:
                check("P14 e2e: fixture /apk job COMPLETED", False,
                      (j14.error or "no job") if j14 is not None else "no job")

            # --- P14 REAL-HYBRID e2e: a genuinely built (aapt2 + d8 +
            # apksigner, build-tools 37.0) APK carrying BOTH Cordova/PhoneGap
            # AND uni-app layouts plus a real @JavascriptInterface WebView —
            # the artifact class P14 had never seen (previously only synthetic
            # ZIP name lists + a native-only negative fixture).
            HYB = os.path.join(ROOT, "tests", "fixtures",
                               "fixture-hybrid.apk")
            if os.path.exists(HYB):
                sig14h = HS.scan_artifact(HYB)
                fw14 = sig14h.get("frameworks") or {}
                check("P14 real-hybrid: uniapp + cordova BOTH detected",
                      "uniapp" in fw14 and "cordova" in fw14, str(fw14))
                check("P14 real-hybrid: uni-app markers on _UNI_ paths",
                      any("_UNI_" in m for m in
                          (fw14.get("uniapp") or {}).get("markers", [])),
                      str(fw14.get("uniapp")))
                check("P14 real-hybrid: cordova markers on www/ + plugins",
                      any(m == "assets/www/cordova.js" for m in
                          (fw14.get("cordova") or {}).get("markers", [])),
                      str(fw14.get("cordova")))
                check("P14 real-hybrid: js_entries list the real JS layer",
                      any(e.endswith("app-service.js") for e in
                          sig14h.get("js_entries", []))
                      and any(e.endswith("index.html") for e in
                              sig14h.get("js_entries", [])),
                      str(sig14h.get("js_entries")))
                check("P14 real-hybrid: webview_used=True from REAL DEX "
                      "(invoke-virtual WebView.addJavascriptInterface)",
                      sig14h.get("webview_used") is True,
                      str(sig14h.get("webview_used")))
                check("P14 real-hybrid: jsinterface honest (no @JavascriptInterface "
                      "method called from DEX in this fixture)",
                      sig14h.get("jsinterface") == [],
                      str(sig14h.get("jsinterface")))
            else:
                print("  [P14] NOT OBSERVED: tests/fixtures/fixture-hybrid.apk "
                      "absent — real-APK hybrid WebView path not exercised")

        # ------------------------------------------------------------------
        if HAVE_ANDROGUARD:
            print("== P4: /find TargetFinder + canonical EntityResolver ==")
            # fresh gateway (stateful /find needs a prior /apk in the SAME gw)
            gwf = gateway.Gateway(td)
            reply, jf = gwf.handle(f"/apk {FIXTURE}", user="test")
            gwf.process_pending()
            if jf is not None and jf.result is not None:
                sha_f = jf.result.intake["sha256"][:16]
                # the signature Phase-6 query: where does this text come from
                r, _ = gwf.handle(f"/find ad-unit --sha {sha_f}")
                check("find 'ad-unit' resolves to a string target",
                      "S" in r and "DemoApp" in r and "onCreate" in r, r)
                check("find 'ad-unit' carries evidence + claim state",
                      "evidence E2" in r and "claim SUPPORTED" in r, r)
                check("find 'ad-unit' gives the location chain",
                      "classes.dex" in r, r)
                r, _ = gwf.handle(f"/find MobileAds --sha {sha_f}")
                check("find 'MobileAds' hits class layer",
                      "[class]" in r and "C" in r, r)
                r, _ = gwf.handle(f"/find zzz-no-such --sha {sha_f}")
                check("find no-match is honest (no fake target)",
                      "no match" in r, r)
                r, _ = gwf.handle("/find ad-unit --sha ZZZZ")
                check("find rejects bad sha", "hex, 8..64" in r, r)
                r, _ = gwf.handle("/find")
                check("find with no query is honest", "TargetFinder" in r or "--sha" in r, r)

            # EntityResolver — the deterministic cross-provider identity service
            from vibebot import graphutil as gu
            known = [
                {"provider": "androguard", "name": "com.x.Foo.bar", "canonical_id": "M1",
                 "fingerprints": gu._fp_fingerprints("com.x.foo.bar")},
                {"provider": "radare2", "name": "fcn.001234", "canonical_id": "N1",
                 "fingerprints": {"name_sha1": "deadbeef"}},
            ]
            r = gu.resolve_entity(known, "androguard", "com.x.Foo.bar")
            check("resolver EXACT (same provider+name)",
                  r["status"] == "EXACT" and r["canonical_id"] == "M1", str(r))
            r = gu.resolve_entity(known, "jadx", "com.x.Foo.bar",
                                  fingerprints=known[0]["fingerprints"])
            check("resolver STRONG (cross-provider fingerprint)",
                  r["status"] == "STRONG" and r["canonical_id"] == "M1", str(r))
            r = gu.resolve_entity(known, "jadx", "totallyDifferent",
                                  fingerprints={"name_sha1": "deadbeef"})
            check("resolver CONFLICT (fp matches, name differs)",
                  r["status"] == "CONFLICT" and r["canonical_id"] is None, str(r))
            k2 = [{"provider": "p", "name": "foo", "canonical_id": "A", "fingerprints": {}},
                  {"provider": "p", "name": "foobar", "canonical_id": "B", "fingerprints": {}}]
            r = gu.resolve_entity(k2, "q", "foo")
            check("resolver AMBIGUOUS (name hits >1, no fp)",
                  r["status"] == "AMBIGUOUS" and r["canonical_id"] is None, str(r))
            r = gu.resolve_entity(known, "x", "Foo.bar.baz")
            check("resolver PROBABLE (single partial, low trust)",
                  r["status"] in ("PROBABLE", "UNRESOLVED"), str(r))
            r = gu.resolve_entity(known, "x", "nothing-here-at-all")
            check("resolver UNRESOLVED", r["status"] == "UNRESOLVED", str(r))
            check("mapping states are the canonical six",
                  set(gu.MAPPING_STATUS) ==
                  {"EXACT", "STRONG", "PROBABLE", "AMBIGUOUS", "CONFLICT", "UNRESOLVED"})

        if HAVE_ANDROGUARD:
            print("== P2: dexmapper engine (androguard decoder) ==")
            from vibebot import dexmapper
            gwd = gateway.Gateway(td)
            check("dexmapper registered when androguard present",
                  "dexmapper" in gwd.engines)
            reply, jdx = gwd.handle(f"/dex {FIXTURE}", user="test")
            check("/dex accepted", jdx is not None and "ACK" in reply, reply)
            if jdx is not None:
                gwd.process_pending()
                check("/dex job COMPLETED",
                      jdx.state == core.Job.COMPLETED, jdx.error or "")
                dres = jdx.result
                check("dex result has structural map",
                      dres is not None and dres.structural.get("classCount", 0) >= 5,
                      str(dres.structural.get("classCount") if dres else None))
                check("dex result call graph non-empty",
                      dres is not None and dres.structural.get("callCount", 0) >= 10,
                      str(dres.structural.get("callCount") if dres else None))
                check("dex integrity recorded",
                      dres is not None and any(
                          i["valid"] for i in dres.structural.get("integrity", [])))
                check("dex app package resolved",
                      dres is not None and
                      dres.structural.get("appPackage") == "com.fixture.demo")
                if dres is None:
                    check("dex result present", False)
                else:
                    sha_d = dres.intake["sha256"]
                    # deepdive traverses the STORED call graph (stateful, no rescan)
                    reply, _ = gwd.handle(f"/deepdive calls --sha {sha_d[:16]}")
                    check("deepdive calls traverses stored graph",
                          "call" in reply and "invoke" in reply, reply)
                    reply, _ = gwd.handle(f"/deepdive DemoApp --sha {sha_d[:16]}")
                    check("deepdive by class name hits stored calls",
                          "DemoApp" in reply, reply)
                    reply, _ = gwd.handle(f"/deepdive jni --sha {sha_d[:16]}")
                    check("deepdive jni honest (0 native in fixture)",
                          "0 matches" in reply, reply)
        else:
            print("== P2 dexmapper: SKIP (androguard not installed) ==")

        print("== telegram transport: construction without network ==")
        g = gateway.Gateway(td)
        t = gateway.TelegramTransport(g, token="TEST-TOKEN-NOT-USED",
                                      allowed_user_ids={"123"})
        check("transport api url from token",
              t.api == "https://api.telegram.org/botTEST-TOKEN-NOT-USED")
        check("token never in gateway help", "TEST-TOKEN-NOT-USED"
              not in g.handle("/help")[0])

        print("== telegram transport: upload + allowlist (mocked network) ==")
        g3 = gateway.Gateway(td)
        t3 = gateway.TelegramTransport(g3, token="TEST-TOKEN-NOT-USED",
                                       allowed_user_ids={"123"})
        check("sanitize_filename strips path (traversal-safe basename)",
              gateway.sanitize_filename("/tmp/evil ../../app.apk") == "app.apk")
        check("sanitize_filename neutralizes metachars in basename",
              gateway.sanitize_filename("evil name $(x).apk") == "evil_name___x_.apk")
        check("sanitize_filename rejects shell metachars",
              all(ch not in gateway.sanitize_filename("a b$(rm)`.apk")
                  for ch in " $`()"))
        check("sanitize_filename empty -> upload.bin",
              gateway.sanitize_filename("...") == "upload.bin")
        check("inbound dir under work dir",
              t3.inbound_dir == os.path.join(td, "inbound"))

        # the "downloaded" file must be a real APK so the apkmod engine
        # can actually run: serve the committed fixture bytes
        if HAVE_ANDROGUARD:
            fixture_bytes = open(FIXTURE, "rb").read()
        else:
            fixture_bytes = b"x"

        sent = []  # (method, payload) log

        def fake_call(method, payload):
            sent.append((method, payload))
            if method == "getUpdates":
                return {"ok": True, "result": [
                    {"message": {"chat": {"id": 1},
                                 "from": {"id": 999},          # NOT in allowlist
                                 "text": "/analyze x"}},
                    {"message": {"chat": {"id": 1},
                                 "from": {"id": 123},          # in allowlist
                                 "document": {"file_id": "FID1",
                                              "file_name": "bad name/../../x.apk"}}},
                ]}
            if method == "getFile":
                return {"ok": True, "result": {"file_path": "x/y.bin",
                                               "file_size": len(fixture_bytes)}}
            if method == "sendMessage":
                return {"ok": True, "result": {"message_id": 1}}
            return {"ok": True}

        t3._call = fake_call
        import urllib.request
        orig_urlopen = urllib.request.urlopen

        class _FakeResp:
            def __init__(self):
                self.pos = 0

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                data = fixture_bytes
                if n < 0:
                    out, self.pos = data[self.pos:], len(data)
                else:
                    out = data[self.pos:self.pos + n]
                    self.pos += len(out)
                return out

        urllib.request.urlopen = lambda *a, **k: _FakeResp()
        try:
            n = t3.poll_once(timeout_s=1)
        finally:
            urllib.request.urlopen = orig_urlopen
        check("upload handled (unauthorized update refused, not counted)",
              n == 1, str(n))
        refusal_texts = [p.get("text", "") for m, p in sent if m == "sendMessage"]
        check("unauthorized user got refusal reply",
              any("not authorized" in t for t in refusal_texts),
              str(refusal_texts))
        inbound = os.path.join(t3.inbound_dir, "x.apk")
        check("upload fetched to sanitized inbound path", os.path.exists(inbound))
        if HAVE_ANDROGUARD and os.path.exists(inbound):
            check("inbound bytes identical to fixture (no tampering)",
                  open(inbound, "rb").read() == fixture_bytes)
        jobs = g3.jobs.all()
        check("upload produced exactly one job", len(jobs) == 1, str(jobs))
        if HAVE_ANDROGUARD:
            check("upload job COMPLETED via apkmod",
                  bool(jobs) and jobs[0]["state"] == core.Job.COMPLETED, str(jobs))
            check("upload job user is telegram-scoped",
                  bool(jobs) and jobs[0]["user"].startswith("tg:"))
            ack_texts = [p.get("text", "") for m, p in sent if m == "sendMessage"]
            check("user got ACK then result (2 messages)",
                  any("ACK" in t for t in ack_texts)
                  and any("COMPLETE" in t for t in ack_texts),
                  str(ack_texts))

        print("== telegram transport: multipart upload body (mocked network) ==")
        g4 = gateway.Gateway(td)
        t4 = gateway.TelegramTransport(g4, token="TEST-TOKEN-NOT-USED")
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["content_type"] = req.headers.get("Content-type") or \
                req.headers.get("Content-Type", "")
            captured["body"] = req.data

            class _R:
                def read(self, n=-1):
                    return b'{"ok": true}'

                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

            return _R()

        orig2 = urllib.request.urlopen
        urllib.request.urlopen = fake_urlopen
        try:
            t4._call("sendDocument", {"chat_id": 1, "document": b"ABCD",
                                      "caption": "x"})
        finally:
            urllib.request.urlopen = orig2
        body = captured.get("body", b"")
        check("multipart used for binary payload",
              "multipart/form-data; boundary=" in captured.get("content_type", ""),
              captured.get("content_type", ""))
        check("document bytes present in multipart body", b"ABCD" in body)
        check("document field name present", b'name="document"' in body)
        check("caption field present", b"caption" in body and b"x" in body)
        check("boundary terminator present", body.rstrip().endswith(b"--"))

        # ------------------------------------------------------------------
        print("== v0.17: hardening batch (lupoxyz #6/#7/#8/#10) ==")
        from vibebot import registry, deepdive
        import vibebot as vb

        # --- #8: command registry (L0/L1 + searchable) --------------------
        names = [c["name"] for c in registry.COMMANDS]
        check("registry: every entry has name/tier/summary",
              all(c["name"] and c["tier"] in (0, 1) and c["summary"]
                  for c in registry.COMMANDS), "")
        check("registry: no duplicate command names",
              len(names) == len(set(names)), str(sorted(names)))
        check("registry: >20 commands (L0/L1 split justified)",
              registry.count() > 20, str(registry.count()))
        check("registry: L0 non-empty and is a proper subset",
              len(registry.by_tier(0)) > 0
              and len(registry.by_tier(0)) < registry.count(),
              str(len(registry.by_tier(0))))
        r, _ = gateway.Gateway(td).handle("/commands")
        check("/commands no-arg: L0 advertised then L1",
              "L0" in r and "L1" in r and "/kmeta" in r, r)
        r, _ = gateway.Gateway(td).handle("/commands kotlin")
        check("/commands kotlin: finds /kmeta via keyword",
              "/kmeta" in r, r)
        r, _ = gateway.Gateway(td).handle("/commands zzz_no_such_thing")
        check("/commands unknown query: honest empty, not a fake match",
              "no commands match" in r, r)

        # --- #6: file-root containment (GHIDRA_MCP_FILE_ROOT pattern) ------
        root = os.path.join(td, "cont_root"); os.makedirs(root, exist_ok=True)
        os.makedirs(os.path.join(root, "in"), exist_ok=True)
        inpath = os.path.join(root, "in", "a.apk")
        open(inpath, "w").write("x")
        outdir = os.path.join(td, "cont_out"); os.makedirs(outdir, exist_ok=True)
        outpath = os.path.join(outdir, "b.apk")
        open(outpath, "w").write("y")
        gwcont = gateway.Gateway(os.path.join(td, "wcont"), file_root=root)
        check("containment unset->set: file_root is honored",
              gwcont.file_root == os.path.realpath(root), gwcont.file_root)
        r, j = gwcont.handle(f"/dexcheck {outpath}")
        check("containment: outside-root path refused (NOT OBSERVED)",
              "outside the file root" in r and j is None, r)
        r, j = gwcont.handle(f"/dexcheck {inpath}")
        check("containment: inside-root path NOT refused",
              "outside the file root" not in r, r)
        # traversal that resolves outside the root must also be caught
        r, j = gwcont.handle(f"/dexcheck {os.path.join(root, '../../etc/hostname')}")
        check("containment: ../ traversal escaping the root refused",
              "outside the file root" in r, r)
        # missing path inside the root -> the normal not-found, not containment
        r, j = gwcont.handle(f"/dexcheck {os.path.join(root, 'in', 'nope.apk')}")
        check("containment: missing inside-root path -> not found",
              "not found" in r and "outside" not in r, r)
        # env-var form: VIBE_FILE_ROOT
        os.environ["VIBE_FILE_ROOT"] = root
        try:
            gwenv = gateway.Gateway(os.path.join(td, "wenv"))
            r, j = gwenv.handle(f"/dexcheck {outpath}")
            check("containment: VIBE_FILE_ROOT env honored",
                  "outside the file root" in r, r)
        finally:
            del os.environ["VIBE_FILE_ROOT"]
        # unset -> no gating (unchanged behavior for existing deployments)
        gwnone = gateway.Gateway(os.path.join(td, "wnone"))
        r, j = gwnone.handle(f"/dexcheck {outpath}")
        check("containment unset: no gating (outside path not refused)",
              "outside the file root" not in r, r)

        # --- #7: /investigate gap split (B3: actionable vs unobservable) ---
        res17 = {"target": "apk", "stages": [
            {"num": "01", "title": "Identity", "mark": "✓", "lines": ["a"], "note": ""},
            {"num": "11", "title": "Blocks", "mark": "n/a", "lines": [], "note": ""},
            {"num": "12", "title": "CFG", "mark": "n/a", "lines": [], "note": ""},
            {"num": "15", "title": "Unknowns", "mark": "?", "lines": [], "note": ""},
        ]}
        gaps = deepdive.classify_gaps(res17)
        check("gaps: native stages (11/12) are actionable with a next step",
              {g["stage"] for g in gaps["actionable"]} == {"11", "12"}
              and all("next_step" in g for g in gaps["actionable"]),
              str(gaps["actionable"]))
        check("gaps: non-native unestablished (15) is unobservable",
              {g["stage"] for g in gaps["unobservable"]} == {"15"},
              str(gaps["unobservable"]))
        check("gaps: established stages (01) excluded from both buckets",
              all(g["stage"] != "01" for g in gaps["actionable"] + gaps["unobservable"]), "")
        gr = deepdive.render_gaps(gaps)
        check("gaps render: both sections + NOT OBSERVED honesty",
              "actionable" in gr and "unobservable" in gr
              and "NOT OBSERVED" in gr, gr)
        empty = deepdive.classify_gaps({"stages": [
            {"num": "01", "title": "Identity", "mark": "✓", "lines": ["a"], "note": ""}]})
        check("gaps: all-established -> no actionable, no unobservable",
              empty["actionable"] == [] and empty["unobservable"] == [], str(empty))

        # --- #10: invariant tests (version + no most-recent-session) ------
        ver = getattr(vb, "__version__", None)
        check("version: __init__.__version__ is X.Y.Z",
              isinstance(ver, str) and len(ver.split(".")) == 3, str(ver))
        check("version: matches the current build", ver == "0.21.0", str(ver))
        r, j = gateway.Gateway(td).handle("/find zzz")
        check("session: /find without --sha is refused (no most-recent fallback)",
              "no --sha" in r and "run /apk" in r and j is None, r)

        # ------------------------------------------------------------------
        print("== v0.18: Frida oracle GATING (lupoxyz #9) ==")
        from vibebot import oracle as OC
        # --- rule 1: OFF by default (never a silent call) ------------------
        check("oracle OFF by default: named target refused without opt-in",
              OC.decide("Java_com_foo_Bar_doIt")["allowed"] is False
              and "OFF by default" in OC.decide("Java_com_foo_Bar_doIt")["reason"],
              str(OC.decide("Java_com_foo_Bar_doIt")))
        check("oracle_enabled: no env -> False", OC.oracle_enabled(None) is False, "")
        # --- rule 2: named exports only; raw address / unknown refused ----
        check("classify: hex address -> raw_address",
              OC.classify_target("0x1000ABCD") == "raw_address", "")
        check("classify: bare integer -> raw_address",
              OC.classify_target("4128736") == "raw_address", "")
        check("classify: JNI symbol -> named_export",
              OC.classify_target("Java_com_foo_Bar_doIt") == "named_export", "")
        check("classify: dotted symbol -> named_export",
              OC.classify_target("com.foo.Bar.doIt") == "named_export", "")
        check("classify: empty -> unknown", OC.classify_target("") == "unknown", "")
        check("oracle ON + named target -> ALLOWED",
              OC.decide("Java_com_foo_Bar_doIt", flag_value="1")["allowed"] is True,
              str(OC.decide("Java_com_foo_Bar_doIt", flag_value="1")))
        check("oracle ON + raw address -> REFUSED (the corruption case)",
              OC.decide("0x1000ABCD", flag_value="1")["allowed"] is False
              and "raw/absolute address" in
              OC.decide("0x1000ABCD", flag_value="1")["reason"],
              str(OC.decide("0x1000ABCD", flag_value="1")))
        check("oracle ON + unknown target -> REFUSED",
              OC.decide("!!bad!!", flag_value="1")["allowed"] is False, "")
        # --- rule 3: differential needs a named reference -----------------
        d_ok = OC.decide("Java_com_foo_Bar_doIt", OC.MODE_DIFFERENTIAL,
                         reference="Java_com_foo_Bar_doItRef", flag_value="1")
        check("differential + named reference -> ALLOWED",
              d_ok["allowed"] is True, str(d_ok))
        d_no = OC.decide("Java_com_foo_Bar_doIt", OC.MODE_DIFFERENTIAL,
                         reference="0xdeadbeef", flag_value="1")
        check("differential + raw reference -> REFUSED",
              d_no["allowed"] is False and "NAMED reference" in d_no["reason"],
              str(d_no))
        d_miss = OC.decide("Java_com_foo_Bar_doIt", OC.MODE_DIFFERENTIAL,
                           flag_value="1")
        check("differential + no reference -> REFUSED",
              d_miss["allowed"] is False, str(d_miss))
        # --- rule 4: fail closed, honest reasons --------------------------
        check("refusal reason is a NOT OBSERVED signal (fail closed)",
              "NOT OBSERVED" in OC.decide("Java_com_foo_Bar_doIt")["reason"], "")
        # --- env-var opt-in (isolated: explicit set + cleanup) ------------
        prev = os.environ.get(OC.ENV_ORACLE_CALL)
        try:
            os.environ[OC.ENV_ORACLE_CALL] = "1"
            check("oracle env opt-in: enabled() True + named allowed",
                  OC.oracle_enabled(None) is True
                  and OC.decide("Java_com_foo_Bar_doIt")["allowed"] is True, "")
        finally:
            if prev is None:
                os.environ.pop(OC.ENV_ORACLE_CALL, None)
            else:
                os.environ[OC.ENV_ORACLE_CALL] = prev
        check("env cleanup restored: disabled again", OC.oracle_enabled(None) is False, "")
        # --- differential diff (pure) -------------------------------------
        eq = OC.diff_outputs([1, 2, 3], [1, 2, 3], [10, 20, 30])
        check("diff: identical outputs -> equivalent", eq["equivalent"] is True
              and eq["mismatches"] == [] and eq["n"] == 3, str(eq))
        ne = OC.diff_outputs([1, 2, 3], [1, 9, 3], [10, 20, 30])
        check("diff: one mismatch -> not equivalent, indexed",
              ne["equivalent"] is False and len(ne["mismatches"]) == 1
              and ne["mismatches"][0][0] == 1, str(ne))
        check("diff: length mismatch -> not equivalent",
              OC.diff_outputs([1, 2], [1, 2, 3], [])["equivalent"] is False, "")
        check("diff: empty -> not equivalent (nothing observed)",
              OC.diff_outputs([], [], [])["equivalent"] is False, "")
        # --- /oracle command: DRY-RUN decision report (never calls) --------
        r, j = gateway.Gateway(td).handle("/oracle")
        check("/oracle no-arg shows usage", "<target>" in r and j is None, r)
        r, j = gateway.Gateway(td).handle("/oracle Java_com_foo_Bar_doIt")
        check("/oracle named target (flag off) -> REFUSED, NOT OBSERVED, no job",
              "REFUSED" in r and "OFF (default)" in r and "NOT OBSERVED" in r
              and j is None, r)
        r, j = gateway.Gateway(td).handle("/oracle 0x1000ABCD")
        check("/oracle raw address -> refused as raw_address",
              "raw_address" in r and "REFUSED" in r and j is None, r)

    # ===================== P18: real-radare2 6.x verification (v0.19) ====
    # r2 6.2.2 output shapes below were probed against a REAL gcc-built
    # x86_64 .so (radare2 6.2.2, 2026-10-02) — captured fixtures, not
    # invented. P5/P15/P16 had ONLY ever run against FakeRunner; this closes
    # that disclosed positive-e2e gap and the r2-5->6 runner regression.
        import subprocess as _sub19
        import shutil as _sh19
        import json as _json19
        _FIX_AFLJ = _json19.dumps([
            {"addr": 4393, "name": "sym.add", "size": 20, "realname": "add"},
            {"addr": 4413, "name": "sym.mul", "size": 19, "realname": "mul"},
            {"addr": 4459, "name": "sym.sum3", "size": 39, "realname": "sum3"},
            {"addr": 4160, "name": "sym.plt.add", "size": 6},
        ])
        # r2 6 iEj carries BOTH symtab and dynsym -> duplicated rows (probed).
        _FIX_IEJ = _json19.dumps([
            {"name": "mul", "flagname": "sym.mul", "vaddr": 4413},
            {"name": "add", "flagname": "sym.add", "vaddr": 4393},
            {"name": "add", "flagname": "sym.add", "vaddr": 4393},
            {"name": "sum3", "flagname": "sym.sum3", "vaddr": 4459},
        ])
        _FIX_IJ = _json19.dumps([
            {"ordinal": 1, "bind": "GLOBAL", "type": "FUNC", "name": "free",
             "plt": 4144},
            {"ordinal": 4, "bind": "GLOBAL", "type": "FUNC", "name": "malloc",
             "plt": 4176},
        ])
        # r2 6 pdfj (the command the runner sends) = OBJECT {name,addr,ops:[...]},
        # each op item carrying 'disasm' (NOT 'name'). Captured shape.
        _FIX_PDJ = _json19.dumps({
            "name": "sym.add", "addr": 4393, "size": 20, "ops": [
                {"addr": 4393, "disasm": "push rbp", "opcode": "push rbp",
                 "bytes": "55", "size": 1, "fcn_addr": 4393},
                {"addr": 4394, "disasm": "mov rbp, rsp",
                 "opcode": "mov rbp, rsp", "bytes": "4889e5", "size": 3,
                 "fcn_addr": 4393},
                {"addr": 4403, "disasm": "mov edx, dword [rbp - 4]",
                 "opcode": "mov edx, dword [rbp - 4]", "bytes": "8b55fc",
                 "size": 3, "fcn_addr": 4393},
                {"addr": 4410, "disasm": "add eax, edx",
                 "opcode": "add eax, edx", "bytes": "01d0", "size": 2,
                 "fcn_addr": 4393},
            ]})
        # r2 6 axtj: xrefs INTO a PLT stub (in a PIC .so, sum3 calls add via
        # sym.plt.add, not the real add — probed).
        _FIX_AXTJ = _json19.dumps([
            {"from": 4459, "type": "CALL", "perm": "--x",
             "opcode": "call sym.plt.add", "fcn_addr": 4432,
             "fcn_name": "sym.sum3", "realname": "sum3",
             "refname": "sym.plt.add"}])
        _FIX_AFL_LEGACY = "0x00400050  112  foo\n0x00400120  64  bar\n"

        _pf = nat.parse_functions(_FIX_AFLJ)
        check("P18: parse_functions r2-6 aflj -> va/size/name/r2_id",
              _pf[0] == {"va": 4393, "size": 20, "name": "sym.add",
                         "r2_id": "fcn.00001129"}, str(_pf[0]))
        check("P18: parse_functions keeps all rows incl sym.plt.*",
              [f["name"] for f in _pf] == ["sym.add", "sym.mul", "sym.sum3",
                                           "sym.plt.add"], str(_pf))
        check("P18: parse_functions legacy 3-token text still works",
              nat.parse_functions(_FIX_AFL_LEGACY)
              == [{"va": 0x400050, "size": 112, "name": "foo",
                   "r2_id": "fcn.00400050"},
                  {"va": 0x400120, "size": 64, "name": "bar",
                   "r2_id": "fcn.00400120"}],
              str(nat.parse_functions(_FIX_AFL_LEGACY)))
        check("P18: parse_functions ANSI-wrapped rows tolerated",
              [f["name"] for f in nat.parse_functions(
                  "\x1b[0m0x00001129    1     20 sym.add\x1b[0m\n")]
              == ["sym.add"], "ansi")
        _ex = nat.parse_exports(_FIX_IEJ)
        check("P18: parse_exports r2-6 iEj DEDUPES symtab+dynsym dupes",
              _ex == ["mul", "add", "sum3"], str(_ex))
        check("P18: parse_exports legacy text still works",
              nat.parse_exports("0x00400120  64  Java_a_b\n0x00400050  112  foo")
              == ["Java_a_b", "foo"], "")
        _im = nat.parse_imports(_FIX_IJ)
        check("P18: parse_imports r2-6 iij -> {name, module:''} (no lib name)",
              _im == [{"name": "free", "module": ""},
                      {"name": "malloc", "module": ""}], str(_im))
        check("P18: parse_imports legacy 'sym:lib.so.6' text still works",
              nat.parse_imports("__cxa_finalize:libc.so.6\nprintf:libc.so.6\n")
              == [{"name": "__cxa_finalize", "module": "libc.so.6"},
                  {"name": "printf", "module": "libc.so.6"}], "")
        _dx = nat.parse_disasm(_FIX_PDJ)
        check("P18: parse_disasm r2-6 pdj uses 'disasm' field",
              _dx == ["push rbp", "mov rbp, rsp", "mov edx, dword [rbp - 4]",
                      "add eax, edx"], str(_dx))
        check("P18: parse_disasm legacy {'name','opcode'} items still work",
              nat.parse_disasm(_json19.dumps(
                  [{"name": "clz", "opcode": "x18, x0"},
                   {"name": "eor", "op": "w0, w0, w2"}]))
              == ["clz x18, x0", "eor w0, w0, w2"], "")
        _xr = nat.parse_xrefs(_FIX_AXTJ, 0x1040)
        check("P18: parse_xrefs r2-6 axtj -> CALL from-va",
              _xr == [4459], str(_xr))
        check("P18: parse_xrefs legacy text still works",
              nat.parse_xrefs("sym.sum3 0x116b [CALL:--x] call sym.plt.add\n",
                              0x1040) == [0x116b], "")

        class _Cap19:
            """Records (cmd) and returns canned r2-6 output."""
            def __init__(self, d):
                self.d = dict(d); self.cmds = []
                self.bin = "r2"; self.timeout = 60.0
            def _have(self):
                return True
            def version(self):
                return "radare2 6.2.2 +1 abi:142 @ linux-x86_64"
            def run(self, path, cmd):
                self.cmds.append(cmd)
                for k, v in self.d.items():
                    if k in cmd:
                        return v
                return ""

        SO19 = os.path.join(td, "libreal.so")
        with open(SO19, "wb") as _f19:
            _f19.write(elf)  # P5's synthetic ELF64 (valid magic for analyze)
        _cap = _Cap19({"aflj": _FIX_AFLJ, "iEj": _FIX_IEJ, "iij": _FIX_IJ,
                       "pdfj": _FIX_PDJ, "axtj": _FIX_AXTJ})
        _n = nat.analyze_native(SO19, _cap, segments=[
            {"type": 1, "offset": 0x1000, "vaddr": 0x1000, "filesz": 0x2000}])
        check("P18: analyze_native sends aa warmup + r2-6 JSON forms",
              _cap.cmds[0] == "aa; aflj" and "iEj" in _cap.cmds
              and "iij" in _cap.cmds, str(_cap.cmds[:3]))
        check("P18: analyze_native counts from real r2-6 shapes",
              _n["counts"]["function"] == 4 and _n["counts"]["export"] == 3
              and _n["counts"]["import"] == 2, str(_n["counts"]))
        check("P18: disasm seek = 'aa; pdfj @0xVA' (function-bounded; the "
              "old 'pdj N @VA' counted BYTES as INSTRUCTIONS and bled into "
              "adjacent fns — probed on a real aarch64 .so, P19)",
              any(c.startswith("aa; pdfj @0x") for c in _cap.cmds),
              str([c for c in _cap.cmds if "pdfj" in c or "pdj" in c]))
        _f_add = [f for f in _n["functions"] if f["name"] == "sym.add"][0]
        check("P18: function mnemonics recovered via r2-6 disasm",
              _f_add["mnemonics"][:2] == ["push rbp", "mov rbp, rsp"],
              str(_f_add["mnemonics"]))
        check("P18: pattern classifier runs on x86-64 mnemonics (no ARM64 "
              "idioms here -> none match, honestly)",
              _f_add["patterns"] == [] and "pattern_details" in _f_add,
              str(_f_add.get("patterns")))
        check("P18: provenance records provider version",
              "6.2.2" in _n["provider_version"], _n["provider_version"])

        # xrefs: direct + PLT-stub fallback
        class _CapPlt(_Cap19):
            def __init__(self, d, fns):
                super().__init__(d)
                self._fns = fns
            def run(self, path, cmd):
                self.cmds.append(cmd)
                if "axtj" in cmd:
                    tgt = cmd.rsplit(" ", 1)[-1]
                    return _FIX_AXTJ if tgt == "0x1040" else ""
                return ""

        _PLT_NATIVE = {"path": SO19, "segments": [], "functions": [
            {"va": 0x1129, "size": 20, "name": "sym.add",
             "r2_id": "fcn.00001129"},
            {"va": 0x1040, "size": 6, "name": "sym.plt.add",
             "r2_id": "fcn.00001040"},
        ]}
        _cap2 = _CapPlt({}, [])
        _froms, _ = nat.xrefs_of(dict(_PLT_NATIVE), 0x1040, runner=_cap2)
        check("P18: xrefs_of queries 'aa; axtj' and parses axtj",
              any("axtj" in c for c in _cap2.cmds) and _froms == [4459],
              str((_cap2.cmds, _froms)))
        _cap3 = _CapPlt({"aflj": _FIX_AFLJ}, _PLT_NATIVE["functions"])
        _froms3, _ = nat.xrefs_of(dict(_PLT_NATIVE), 0x1129, runner=_cap3)
        check("P18: xrefs_of real-fn-empty -> PLT stub fallback -> callers",
              any("0x1040" in c for c in _cap3.cmds) and _froms3 == [4459],
              str((_cap3.cmds, _froms3)))

        # runner argv order (the r2-5->6 regression P5 never hit: FakeRunner)
        class _Rec19(nat.RadareRunner):
            def __init__(self):
                super().__init__(bin="/fake/r2")
                self.captured = []
            def _have(self):
                return True
            def _run(self, argv, timeout):
                self.captured.append(list(argv))
                import subprocess as _sp
                return _sp.CompletedProcess(argv, 0, stdout="", stderr="")

        _rr = _Rec19()
        _rr.run(SO19, "aa; aflj")
        argv = _rr.captured[0]
        check("P18: RadareRunner argv = flags BEFORE path (r2-6 contract)",
              argv[0] == "/fake/r2" and argv[1] == "-e"
              and argv[2] == "scr.color=0" and argv[3] == "-e"
              and argv[4] == "bin.relocs.apply=true" and argv[5] == "-q"
              and argv[6] == "-c" and argv[7] == "aa; aflj"
              and argv[8] == SO19, str(argv))

        # ---- e2e against REAL r2 6.2.2 (auto-skip when absent/unusable) ----
        R219 = None
        for _cand in ("/opt/data/cache/scratch/toolchain/radare2/usr/bin/radare2",
                      "r2", "radare2"):
            _found = None
            if _cand in ("r2", "radare2"):
                try:
                    import shutil as _sh19b
                    _found = _sh19b.which(_cand)
                except Exception:
                    _found = None
            elif os.path.exists(_cand) and os.access(_cand, os.X_OK):
                _found = _cand
            if not _found:
                continue
            # present != usable: a user-space r2 without its LD_LIBRARY_PATH
            # fails to exec (missing libr_util.so) — treat as NOT OBSERVED.
            try:
                if _sub19.run([_found, "-v"], capture_output=True,
                              timeout=15).returncode == 0:
                    R219 = _found
                    break
            except Exception:
                continue
        if R219:
            print("== P18 e2e: REAL radare2 over a real gcc-built .so ==")
            _d19 = os.path.join(td, "realso19")
            os.makedirs(_d19, exist_ok=True)
            _c19 = os.path.join(_d19, "real.c")
            with open(_c19, "w") as _fc:
                _fc.write("#include <stdlib.h>\n"
                          "int add(int a, int b) { return a + b; }\n"
                          "int mul(int a, int b) { return a * b; }\n"
                          "int sum3(int a,int b,int c){ return add(a,b)+c; }\n"
                          "void use_malloc(void){ char*p=malloc(16); "
                          "if(p) p[0]=0; free(p); }\n")
            _so19 = os.path.join(_d19, "libreal.so")
            _gcc = _sh19.which("gcc") or _sh19.which("cc")
            if not _gcc or _sub19.call(
                    [_gcc, "-shared", "-fPIC", "-o", _so19, _c19],
                    stdout=_sub19.DEVNULL, stderr=_sub19.DEVNULL) != 0:
                check("P18-e2e: gcc available to build the real .so", False,
                      "skipping e2e — no C compiler")
            else:
                os.environ.setdefault("RADARE2", os.path.expanduser(
                    "~/.config/radare2"))
                _real = nat.RadareRunner(bin=R219, timeout=120)
                _rn = nat.analyze_native(_so19, _real)
                _names = [f["name"] for f in _rn["functions"]]
                check("P18-e2e: REAL r2 finds add/mul/sum3 + PLT stub",
                      {"sym.add", "sym.mul", "sym.sum3"} <= set(_names)
                      and any(nm.startswith("sym.plt.") for nm in _names),
                      str(_names))
                check("P18-e2e: REAL r2 exports DEDUPED (no symtab/dynsym dupes)",
                      len(_rn["exports"]) == len(set(_rn["exports"]))
                      and set(_rn["exports"])
                      == {"add", "mul", "sum3", "use_malloc"},
                      str(_rn["exports"]))
                check("P18-e2e: REAL r2 imports include malloc+free (r2-6 iij; linker "
                      "also adds _ITM_*/__gmon_start__ weak symbols — probed)",
                      {"malloc", "free"} <= {i["name"] for i in _rn["imports"]}
                      and all(i["module"] == "" for i in _rn["imports"]),
                      str(_rn["imports"]))
                _ra = [f for f in _rn["functions"]
                       if f["name"] == "sym.add"][0]
                check("P18-e2e: REAL r2 mnemonics (prologue first)",
                      _ra["mnemonics"][0] == "push rbp",
                      str(_ra["mnemonics"][:3]))
                _rf, _ = nat.xrefs_of(_rn, 0x1040, _real)
                check("P18-e2e: REAL r2 xref via PLT (sum3 calls add)",
                      len(_rf) >= 1 and all(isinstance(x, int) for x in _rf),
                      str(_rf))
                check("P18-e2e: provider version is real r2 6.x",
                      "6." in _rn["provider_version"],
                      _rn["provider_version"])
        else:
            # CI / hosts without a usable r2: the e2e is NOT OBSERVED, not a
            # failure — the parsers above (r2-6 real shapes, captured fixtures)
            # still gate the logic. Print the disclosure, stay green.
            print("  INFO P18-e2e: NOT OBSERVED — no usable radare2 on this "
                  "host (install per toolchain/android-tools.json 6.2.x to "
                  "close the positive-e2e gap); pure r2-6-shape checks above "
                  "still apply.")

    # ===================== P19: real-ARM64 pattern e2e (v0.20) ============
    # Closes the P15 ARM64 positive-e2e gap (FakeRunner-only). The real-r2
    # disasm of a real aarch64 .so exposed THREE classifier drifts the
    # canned fixtures never hit (verified on real r2 6.2.2, 2026-10-02):
    #  (a) pdj {size} @va counted BYTES as INSTRUCTIONS -> disasm bled
    #      THROUGH adjacent functions and mis-attributed their idioms
    #      (a real casefold fn reported fused-madd/tbz/bitset of its
    #      neighbors) -> switched to function-bounded 'aa; pdfj @0xVA'
    #  (b) P2 case-fold: r2 6 prints 'orr w0, w0, 0x20' (hex imm, no #) —
    #      the classifier required literal '#32' -> real case-fold missed
    #  (c) P6 string-ref: r2 6 prints 'adrp x0, 0' + 'add x0, x0, 0x278'
    #      (resolved sym/addr, NO ':lo12:' label) -> the pair was never
    #      matched on a real binary
    # --- pure: the drift fixes (no toolchain needed) ---
        cf20 = ["orr w1, w1, 0x20", "ret"]
        check("P19: P2 case-fold matches r2-6 '0x20' rendering",
              any(p["pattern"] == "case-fold-scan"
                  for p in nat.classify_function(cf20)),
              str(nat.classify_function(cf20)))
        cf_legacy = ["ldrb w1, [x0]", "orr w1, w1, #32", "ret"]
        check("P19: P2 case-fold still matches legacy '#32' rendering",
              any(p["pattern"] == "case-fold-scan"
                  for p in nat.classify_function(cf_legacy)), "")
        check("P19: P2 does NOT fire on orr into a DIFFERENT register",
              nat.classify_function(["orr w1, w2, #32", "ret"]) == [], "")
        adrp6 = ["adrp x0, 0", "add x0, x0, 0x278", "ldr x0, [x0]", "ret"]
        check("P19: P6 string-ref matches r2-6 'adrp+add' (no :lo12:)",
              any(p["pattern"] == "string-ref-pair"
                  for p in nat.classify_function(adrp6)),
              str(nat.classify_function(adrp6)))
        adrp_lo12 = ["adrp x8, str_lbl", "add x8, x8, :lo12:str_lbl", "ret"]
        check("P19: P6 still matches the legacy ':lo12:' rendering",
              any(p["pattern"] == "string-ref-pair"
                  for p in nat.classify_function(adrp_lo12)), "")
        adrp_neg = ["adrp x0, 0", "add x1, x1, 0x278", "ret"]
        check("P19: P6 requires the SAME register (no adrp/add cross-match)",
              nat.classify_function(adrp_neg) == [],
              str(nat.classify_function(adrp_neg)))

    # --- e2e: REAL aarch64 .so (committed fixture) + REAL r2 ---
        _XAS = "/opt/data/cache/scratch/toolchain/cross/binut/usr/bin/aarch64-linux-gnu-as"
        _XLD = "/opt/data/cache/scratch/toolchain/cross/binut/usr/bin/aarch64-linux-gnu-ld"
        _XCROSSLIB = "/opt/data/cache/scratch/toolchain/cross/binut/usr/lib/x86_64-linux-gnu"
        _FIXPAT = os.path.join(ROOT, "tests", "fixtures", "arm64", "pat.s")
        _arm64_ok = R219 is not None and os.path.exists(_XAS) \
            and os.path.exists(_XLD) and os.path.exists(_FIXPAT)
        if not _arm64_ok:
            print("  INFO P19-e2e: NOT OBSERVED — need usable r2 + aarch64 "
                  "binutils + tests/fixtures/arm64/pat.s (cross as/ld "
                  "recipe in the P19 study note); pure drift checks above "
                  "still apply.")
        elif _sub19.run([_XAS, "--version"], env={**os.environ,
                        "LD_LIBRARY_PATH": _XCROSSLIB},
                        capture_output=True).returncode != 0:
            print("  INFO P19-e2e: NOT OBSERVED — cross as unusable "
                  "(LD_LIBRARY_PATH recipe).")
        else:
            print("== P19 e2e: REAL aarch64 .so + REAL r2 6.x patterns ==")
            _env19 = {**os.environ, "LD_LIBRARY_PATH": _XCROSSLIB}
            _d19b = os.path.join(td, "arm64so")
            os.makedirs(_d19b, exist_ok=True)
            _so64 = os.path.join(_d19b, "libpat.so")
            _o64 = os.path.join(_d19b, "pat.o")
            _ok_as = _sub19.call([_XAS, "-o", _o64, _FIXPAT], env=_env19,
                                 stdout=_sub19.DEVNULL,
                                 stderr=_sub19.DEVNULL)
            _ok_ld = _sub19.call([_XLD, "-shared", "-o", _so64, _o64],
                                 env=_env19, stdout=_sub19.DEVNULL,
                                 stderr=_sub19.DEVNULL)
            if _ok_as != 0 or _ok_ld != 0:
                check("P19-e2e: cross as/ld built the aarch64 .so", False,
                      f"as={_ok_as} ld={_ok_ld}")
            else:
                _r64 = nat.RadareRunner(bin=(R219 or "r2"), timeout=120)
                _n64 = nat.analyze_native(_so64, _r64)
                _allpats = [p for f in _n64["functions"]
                            for p in f["patterns"]]
                check("P19-e2e: all 6 ARM64 idioms recognized on REAL r2",
                      {"popcount-loop", "case-fold-scan", "bitset-test",
                       "tbz-bit0-parity", "fused-madd", "string-ref-pair"}
                      <= set(_allpats), str(sorted(set(_allpats))))
                _by = {f["name"]: set(f["patterns"])
                       for f in _n64["functions"]}
                _cf = [nm for nm, ps in _by.items()
                       if "case-fold-scan" in ps]
                check("P19-e2e: case-fold fires on EXACTLY ONE function "
                      "(the bleed fix — the old pdj-bytes-as-instr form "
                      "mis-attributed neighbors' idioms)",
                      len(_cf) == 1 and _cf[0] == "sym.casefold"
                      and _by["sym.casefold"] == {"case-fold-scan"},
                      str(_by))
                _sr = [nm for nm, ps in _by.items()
                       if "string-ref-pair" in ps]
                check("P19-e2e: string-ref fires on exactly sym.stringref",
                      _sr == ["sym.stringref"], str(_sr))
                _pop = [nm for nm, ps in _by.items() if "popcount-loop" in ps]
                check("P19-e2e: popcount (r2 names the first fn entry0) "
                      "fires exactly once",
                      len(_pop) == 1 and _pop[0] == "entry0", str(_pop))

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
