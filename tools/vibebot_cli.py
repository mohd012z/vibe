#!/usr/bin/env python3
"""vibe vibebot — VibeBot CLI (v0.1).

RevEngi-style analysis gateway for the vibe workbench: command router +
async job queue + normalized evidence + stateful /deepdive. The Telegram
transport is optional (--serve, token via VIBE_TELEGRAM_TOKEN only).
"""
from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.dirname(os.path.abspath(__file__))
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

from vibebot import gateway as gway  # noqa: E402


def run_command(gw: gway.Gateway, line: str, user: str = "cli") -> str:
    reply, job = gw.handle(line, user=user)
    if job is not None:
        print(f"[job {job.id} accepted — working queue]")
        for j in gw.process_pending():
            if j.state == gway.core.Job.FAILED:
                reply += f"\n[job {j.id} FAILED: {j.error}]"
            elif j.state == gway.core.Job.COMPLETED:
                res = j.result
                if res is not None:
                    sha16 = (res.intake.get("sha256") or "")[:16]
                    reply += (f"\n[job {j.id} COMPLETE: {len(res.findings)} findings; "
                              f"sha {sha16}…; /deepdive callers --sha {sha16}]")
                else:
                    reply += f"\n[job {j.id} COMPLETE (no result recorded)]"
    return reply


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--commands", default=None)
    ap.add_argument("--work-dir", default=os.path.join(ROOT, "vibebot-runs"))
    ap.add_argument("--fingerprints", default=None)
    ap.add_argument("--serve", action="store_true")
    args = ap.parse_args()

    engines_map = None
    if args.fingerprints:
        from vibebot import engines as eng
        engines_map = {"apkmod": eng.ApkModEngine(
            os.path.join(args.work_dir, "reports"),
            fingerprints=os.path.abspath(args.fingerprints)),
            "mock": eng.MockEngine()}
    gw = gway.Gateway(args.work_dir, engines_map)

    if args.demo:
        fixture = os.path.join(ROOT, "tests", "fixtures", "fixture-demo.apk")
        extra_fp = os.path.join(ROOT, "apk", "fingerprints.example-extra.json")
        if not os.path.exists(fixture):
            print(f"demo fixture missing: {fixture}", file=sys.stderr)
            return 3
        print(run_command(gw, f"/analyze {fixture} --engine apkmod --fingerprints {extra_fp}"))
        print("\n" + run_command(gw, "/sessions"))
        keys = gw.sessions.list()
        if keys:
            print("\n" + run_command(gw, f"/deepdive callers --sha {keys[-1]}"))
        return 0

    if args.commands:
        lines = [l.strip() for l in open(args.commands, encoding="utf-8")
                 if l.strip() and not l.startswith("#")]
        for line in lines:
            print("\n" + run_command(gw, line))
        return 0

    if args.serve:
        token = os.environ.get("VIBE_TELEGRAM_TOKEN")
        if not token:
            print("--serve needs VIBE_TELEGRAM_TOKEN in the environment "
                  "(never pass the token as an argument)", file=sys.stderr)
            return 3
        allowed_env = os.environ.get("VIBE_BOT_ALLOWED_USERS", "").strip()
        allowed = {s.strip() for s in allowed_env.split(",") if s.strip()} or None
        from vibebot.telegram_runtime import CategoryTelegramTransport
        transport = CategoryTelegramTransport(gw, token, allowed, worker=True)
        print(f"vibebot serving Telegram category console (allowlist "
              f"{'on: ' + str(sorted(allowed)) if allowed else 'OFF — open; set VIBE_BOT_ALLOWED_USERS'})")
        try:
            while True:
                try:
                    transport.poll_once(timeout_s=25)
                except Exception as exc:
                    # Keep the long-poll service alive across transient API/runtime failures.
                    print(f"telegram poll error: {type(exc).__name__}: {exc}", file=sys.stderr)
        except KeyboardInterrupt:
            print("\nstopped")
            return 0

    print("vibebot REPL — type /help (Ctrl-D to quit)")
    try:
        while True:
            try:
                line = input("vibe> ").strip()
            except EOFError:
                break
            if line:
                print(run_command(gw, line))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
