"""P16 — native-harness validation: prove a native (ARM64) change BEHAVIORALLY.

This is the top of the evidence chain. The /360 rule: a native change is
proven by running a C test harness under qemu-aarch64 and OBSERVING the
test result (E5 runtime observation) — never by "the diff looks right".
The P15 pattern classifier tells you WHERE to change (E3, static); this
module proves the change actually BEHAVES (E5, dynamic).

The build recipe is NOT hand-rolled: it mirrors the public exercism
arm64-assembly track Makefile (2026-10-02 study), verbatim:
  cross-compile   aarch64-linux-gnu-gcc / aarch64-linux-gnu-as
  CFLAGS          -g -Wall -Wextra -pedantic -Werror -std=c99 -fPIE
  LDFLAGS         -pie -Wl,--fatal-warnings
  run             qemu-aarch64 -L /usr/aarch64-linux-gnu  (unless host is
                            aarch64, in which case run the binary directly)
The mnemonic vocabulary and build recipe are public, stable toolchain
facts (documented), not reverse-engineered constants.

Design (same discipline as P5/P15):
- PURE core: toolchain detection, command construction, and output parsing
  are pure functions, testable with a FakeRunner and no toolchain at all.
- thin runner seam: a HarnessLike (subprocess, or a test FakeRunner)
  executes the commands; a failure at any stage is an honest result,
  never a crash.
- verdicts: SUCCESS / FAILURE / NOT OBSERVED (toolchain absent or build
  failed -> the behavioral claim is NOT OBSERVED, which is NOT the same as
  the change being wrong — NOT OBSERVED != IMPOSSIBLE).
- E5 ceiling: a green harness is runtime evidence that THIS build behaves
  as the test expects; it is not a claim the change is correct in general
  (the test's coverage is the ceiling on the claim).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from typing import Protocol

from . import core

PROVIDER_NAME = "harness"

# --- exercism arm64-assembly Makefile recipe (verbatim, 2026-10-02 study) ----
C_CROSS = "aarch64-linux-gnu-gcc"
AS_CROSS = "aarch64-linux-gnu-as"
CFLAGS = ["-g", "-Wall", "-Wextra", "-pedantic", "-Werror",
          "-std=c99", "-fPIE"]
LDFLAGS = ["-pie", "-Wl,--fatal-warnings"]
QEMU = "qemu-aarch64"
QEMU_SYSROOT = "/usr/aarch64-linux-gnu"


class HarnessLike(Protocol):
    """Runs one command (argv list) and returns (returncode, combined_output).
    RealSubprocess is the production impl; a test FakeRunner intercepts by
    argv prefix so the whole pipeline is unit-testable with no toolchain."""
    def run(self, argv: list[str]) -> tuple[int, str]: ...


class RealSubprocess:
    bin = "sh"

    def run(self, argv: list[str]) -> tuple[int, str]:
        p = subprocess.run(list(argv), capture_output=True,
                           text=True, timeout=120)
        return p.returncode, (p.stdout or "") + (p.stderr or "")


def detect_toolchain(which=shutil.which) -> dict:
    """Detect the host arch + presence of each required tool. Pure (the
    `which` is injectable so tests can fabricate a full or empty
    toolchain). Returns per-tool path-or-None + `host` + `needs_qemu`."""
    host = sys.platform if "linux" in sys.platform else os.uname().machine
    try:
        host = os.uname().machine
    except Exception:
        host = "unknown"
    needs_qemu = host != "aarch64"
    return {
        "host": host,
        "needs_qemu": needs_qemu,
        "cc": which(C_CROSS),
        "as": which(AS_CROSS),
        "qemu": which(QEMU) if needs_qemu else None,
    }


def _missing(toolchain: dict) -> list[str]:
    out = []
    for k in ("cc", "as"):
        if not toolchain.get(k):
            out.append(k)
    if toolchain.get("needs_qemu") and not toolchain.get("qemu"):
        out.append("qemu")
    return out


def build_cmd_asm(as_bin: str, src: str, dst: str) -> list[str]:
    """exercism: $(AS) -o $@ $<  (arm64 .s -> .o)."""
    return [as_bin, "-o", dst, src]


def build_cmd_c(cc_bin: str, src: str, dst: str,
                sysroot: str | None = None) -> list[str]:
    """exercism: $(CC) $(CFLAGS) -c -o $@ $<  (C -> .o).

    `sysroot` (optional) is passed as `--sysroot` so a user-space cross
    toolchain whose internal as/ld/headers live under an extract dir (not
    the baked-in `/usr/aarch64-linux-gnu`) can compile+link. Default None
    keeps the command byte-identical to the exercism recipe.
    """
    if sysroot:
        return [cc_bin, "--sysroot", sysroot, *CFLAGS, "-c", "-o", dst, src]
    return [cc_bin, *CFLAGS, "-c", "-o", dst, src]


def build_cmd_link(cc_bin: str, objs: list[str], out: str,
                   sysroot: str | None = None) -> list[str]:
    """exercism: $(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(ALL_OBJS)."""
    if sysroot:
        return [cc_bin, "--sysroot", sysroot, *CFLAGS, *LDFLAGS,
                "-o", out, *objs]
    return [cc_bin, *CFLAGS, *LDFLAGS, "-o", out, *objs]


def run_cmd(toolchain: dict, binary: str, sysroot: str | None = None) -> list[str]:
    """exercism: $(MAYBE_QEMU) ./tests — on an aarch64 host run the binary
    directly; otherwise under qemu-aarch64 with the cross sysroot. `sysroot`
    (optional) overrides the default /usr/aarch64-linux-gnu (for a user-space
    extract)."""
    if toolchain.get("needs_qemu") and toolchain.get("qemu"):
        sr = sysroot or QEMU_SYSROOT
        return [toolchain["qemu"], "-L", sr, binary]
    return [binary]


# --- output parsing --------------------------------------------------------
def parse_harness(out: str) -> dict:
    """Parse a C test-harness summary into counts + a verdict. Handles the
    two common shapes (PURE — no process):
      unity / CMocka style :  'x passed, y failed' (and 'z tests')
      plain main() style   :  'FAIL: name' / 'PASS: name' / 'N passed'
    Verdict:
      SUCCESS      at least one test observed, none failed
      FAILURE      at least one test failed
      NOT OBSERVED no parseable test result (empty output / not a harness)
    """
    passed = 0
    failed = 0
    s = out or ""
    # 'x passed, y failed'
    m = re.search(r"(\d+)\s+passed,\s*(\d+)\s+failed", s, re.I)
    if m:
        passed = int(m.group(1)); failed = int(m.group(2))
    else:
        # count per-line markers
        for ln in s.splitlines():
            t = ln.strip().lower()
            if t.startswith("pass") or "passed" in t:
                passed += 1
            if t.startswith("fail") or "failed" in t or "assert" in t:
                failed += 1
        # 'N passed' summary
        mp = re.search(r"(\d+)\s+passed\b", s, re.I)
        if mp:
            passed = max(passed, int(mp.group(1)))
    observed = (passed + failed) > 0
    if not observed:
        verdict = "NOT_OBSERVED"
    elif failed > 0:
        verdict = "FAILURE"
    else:
        verdict = "SUCCESS"
    return {"passed": passed, "failed": failed,
            "observed": observed, "verdict": verdict}


def validate_native(inputs: dict, runner: HarnessLike | None = None,
                    toolchain: dict | None = None) -> dict:
    """Build the C/asm harness for a native change and run it (under qemu if
    needed), then judge the result. `inputs` is {'c': [files], 'asm':
    [files], 'out': build dir, 'binary': name}. Pure glue over the runner
    seam; every stage failure is an honest result, never an exception.

    Returns {verdict, passed, failed, observed, build:{ok,stage,error},
             toolchain, commands, logs}.
    """
    runner = runner or RealSubprocess()
    tc = toolchain or detect_toolchain()
    sysroot = inputs.get("sysroot") or None
    outdir = inputs.get("out") or "/tmp"
    binary = os.path.join(outdir, inputs.get("binary", "tests"))
    c_files = inputs.get("c") or []
    asm_files = inputs.get("asm") or []
    commands: list[list[str]] = []
    logs: dict[str, str] = {}

    missing = _missing(tc)
    if missing:
        return {"verdict": "NOT_OBSERVED", "passed": 0, "failed": 0,
                "observed": False,
                "build": {"ok": False, "stage": "toolchain",
                          "error": "missing: " + ", ".join(missing)},
                "toolchain": tc, "commands": commands, "logs": logs,
                "note": "toolchain incomplete — behavioral validation NOT "
                        "OBSERVED (NOT OBSERVED != the change is wrong)"}

    cc, asb = tc["cc"], tc["as"]
    objs: list[str] = []

    # 1) C -> .o
    for i, src in enumerate(c_files):
        dst = os.path.join(outdir, f"c{i}.o")
        cmd = build_cmd_c(cc, src, dst, sysroot)
        commands.append(cmd)
        rc, out = runner.run(cmd)
        logs["c:%s" % os.path.basename(src)] = out[-500:]
        if rc != 0:
            return _buildfail("c:%s" % os.path.basename(src), out, tc,
                              commands, logs)
        objs.append(dst)
    # 2) asm -> .o
    for i, src in enumerate(asm_files):
        dst = os.path.join(outdir, f"s{i}.o")
        cmd = build_cmd_asm(asb, src, dst)
        commands.append(cmd)
        rc, out = runner.run(cmd)
        logs["asm:%s" % os.path.basename(src)] = out[-500:]
        if rc != 0:
            return _buildfail("asm:%s" % os.path.basename(src), out, tc,
                              commands, logs)
        objs.append(dst)
    if not objs:
        return _buildfail("link:no-objects", "no .c or .s inputs", tc,
                          commands, logs)
    # 3) link (pie)
    cmd = build_cmd_link(cc, objs, binary, sysroot)
    commands.append(cmd)
    rc, out = runner.run(cmd)
    logs["link"] = out[-500:]
    if rc != 0:
        return _buildfail("link", out, tc, commands, logs)
    # 4) run (under qemu if needed)
    cmd = run_cmd(tc, binary, sysroot)
    commands.append(cmd)
    rc, out = runner.run(cmd)
    logs["run"] = out[-2000:]
    p = parse_harness(out)
    return {"verdict": p["verdict"], "passed": p["passed"],
            "failed": p["failed"], "observed": p["observed"],
            "build": {"ok": True, "stage": "run", "error": None},
            "toolchain": tc, "commands": commands, "logs": logs,
            "run_rc": rc,
            "note": ("harness run observed (E5 runtime)" if p["observed"]
                     else "build succeeded but harness produced no parseable "
                          "test result — NOT OBSERVED")}


def _buildfail(stage: str, out: str, tc: dict, commands: list,
               logs: dict) -> dict:
    return {"verdict": "NOT_OBSERVED", "passed": 0, "failed": 0,
            "observed": False,
            "build": {"ok": False, "stage": stage,
                      "error": (out or "").strip()[-400:]},
            "toolchain": tc, "commands": commands, "logs": logs,
            "note": f"build failed at {stage} — behavioral validation NOT "
                    f"OBSERVED (compile/link error, see build.error)"}


# --- rendering -------------------------------------------------------------
def render_harness(res: dict) -> str:
    lines = []
    if res.get("verdict") == "SUCCESS":
        lines.append(f"VALIDATE-NATIVE  SUCCESS  "
                     f"({res['passed']} passed, {res['failed']} failed) "
                     f"[E5 runtime]")
    elif res.get("verdict") == "FAILURE":
        lines.append(f"VALIDATE-NATIVE  FAILURE  "
                     f"({res['passed']} passed, {res['failed']} failed) "
                     f"[E5 runtime] — the change did NOT behave as tested")
    else:
        stage = (res.get("build") or {}).get("stage", "?")
        err = (res.get("build") or {}).get("error")
        lines.append(f"VALIDATE-NATIVE  NOT OBSERVED  "
                     f"(stage={stage})" + (f" — {err[:120]}" if err else ""))
    tc = res.get("toolchain") or {}
    if tc:
        lines.append(f"  host={tc.get('host')} needs_qemu={tc.get('needs_qemu')}")
    if res.get("note"):
        lines.append(f"  {res['note']}")
    if res.get("observed"):
        lines.append("  ceiling: E5 runtime — proves THIS build passes THIS "
                     "test; not a claim the change is generally correct.")
    return "\n".join(lines)


# --- engine ----------------------------------------------------------------
def _artifact_sha(inputs: dict) -> str:
    """A stable sha for the session store: hash of the input file paths (the
    behavioral contract), since the 'artifact' is a source dir, not one file."""
    import hashlib
    paths = sorted((inputs.get("c") or []) + (inputs.get("asm") or []))
    blob = os.path.join("---", *paths)
    return hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()


class HarnessEngine(core.Engine):
    """Engine: prove a native (ARM64) change behaviorally via a C harness
    under qemu-aarch64 (E5). Artifact = a source directory; params carry the
    c/asm file lists + build dir + binary name. Degrades honestly: a
    missing cross-compiler or qemu -> a NOT OBSERVED result (never a
    fabricated pass)."""

    spec = core.EngineSpec(
        name="harness",
        description="Native-harness validation: build a C/asm test harness "
                    "for an ARM64 change + run it under qemu-aarch64 (E5)",
        formats=("dir", "c", "s", "so"),
    )

    def __init__(self, report_dir: str, runner: HarnessLike | None = None,
                 toolchain: dict | None = None):
        self.report_dir = report_dir
        self.runner = runner or RealSubprocess()
        self.toolchain = toolchain  # None -> detect_toolchain() at run time

    def can_run(self, artifact: str) -> bool:
        # handles a source dir (job.artifact) — the files come from params
        return os.path.isdir(artifact) or artifact.lower().endswith(
            (".c", ".s", ".so"))

    def run(self, job: core.Job) -> core.EngineResult:
        import json as _json
        job.progress("intake", 10, "harness inputs")
        p = job.params or {}
        # default: auto-discover the .c / .s sources in the artifact dir
        # (so `/harness <dir>` is self-contained); explicit params override.
        c_files = list(p.get("c", []))
        asm_files = list(p.get("asm", []))
        if not c_files and not asm_files and os.path.isdir(job.artifact):
            for fn in sorted(os.listdir(job.artifact)):
                full = os.path.join(job.artifact, fn)
                if os.path.isfile(full) and fn.endswith(".c"):
                    c_files.append(full)
                elif os.path.isfile(full) and fn.endswith(".s"):
                    asm_files.append(full)
        inputs = {
            "c": c_files,
            "asm": asm_files,
            "out": p.get("out") or os.path.join(self.report_dir, "build"),
            "binary": p.get("binary") or "tests",
        }
        os.makedirs(inputs["out"], exist_ok=True)
        sha = _artifact_sha(inputs)
        job.checkpoint("intake", {"sha256": sha, "inputs": inputs})

        job.progress("build+run", 50, "cross-compile + run under qemu")
        res = validate_native(inputs, self.runner,
                              toolchain=self.toolchain)

        job.progress("report", 100, "done")
        os.makedirs(self.report_dir, exist_ok=True)
        ts = core.time.strftime("%Y%m%d-%H%M%S")
        rep = os.path.join(self.report_dir, f"vibe-harness-{ts}.json")
        _json.dump(res, open(rep, "w"), indent=2)
        job.checkpoint("report", rep)

        card = render_harness(res)

        findings = []
        v = res.get("verdict")
        if v == "SUCCESS":
            raw = {
                "sdk": "NATIVE-HARNESS",
                "title": f"native harness PASS "
                         f"({res['passed']} passed) — change behaves [E5]",
                "classification": "NATIVE_VALIDATION",
                "evidence": [{"level": "E5", "artifact": "qemu-aarch64 run",
                              "detail": f"{res['passed']} passed, "
                                        f"{res['failed']} failed"}],
                "falsification": ["E5 ceiling: proves this build passes this "
                                  "test — not that the change is generally "
                                  "correct (test coverage = the ceiling)"],
            }
        elif v == "FAILURE":
            raw = {
                "sdk": "NATIVE-HARNESS",
                "title": f"native harness FAIL "
                         f"({res['failed']} failed) — change misbehaves [E5]",
                "classification": "NATIVE_VALIDATION",
                "evidence": [{"level": "E5", "artifact": "qemu-aarch64 run",
                              "detail": f"{res['passed']} passed, "
                                        f"{res['failed']} failed"}],
                "falsification": ["a green on other builds is NOT claimed; "
                                  "this build is falsified by its own test"],
            }
        else:  # NOT_OBSERVED
            stage = (res.get("build") or {}).get("stage", "?")
            raw = {
                "sdk": "NATIVE-HARNESS",
                "title": f"native validation NOT OBSERVED (stage={stage})",
                "classification": "NATIVE_VALIDATION",
                "evidence": [{"level": "E0", "artifact": "toolchain/build",
                              "detail": res.get("note", "")[:200]}],
                "falsification": ["NOT OBSERVED != IMPOSSIBLE — no toolchain "
                                  "/ build failure, so no behavioral claim "
                                  "is made either way"],
            }
        findings.append(core.normalize_finding(raw, self.spec.name, 1))

        return core.EngineResult(
            intake={"sha256": sha, "package": None, "dexCount": 0,
                    "classCount": 0, "methodCount": 0,
                    "nativeLibs": []},
            structural={"harness": res},
            findings=findings,
            report_md=card,
            outputs={"report": rep, "card": card},
        )
