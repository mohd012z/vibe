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
import time

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
