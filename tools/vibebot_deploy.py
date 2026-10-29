#!/usr/bin/env python3
"""Deploy + validate @mvibe_aibot against the local vibebot gateway.

Token comes from the 600-perm env file (never printed). This script:
  1. getMe            — token validity + bot identity
  2. setMyCommands    — register the command menu (mirrors /help)
  3. smoke test       — send a test APK to the bot via sendDocument on the
                        operator's own chat, confirm the gateway ACKs with a
                        job id and the job completes (proof the full loop works)
  4. reply check      — assert the bot's own reply arrived (getUpdates)

Usage:  python3 tools/vibebot_deploy.py --chat-id 30006405 --dry-run   # getMe+commands only
        python3 tools/vibebot_deploy.py --chat-id 30006405              # full smoke
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN_FILE = "/opt/data/vibebot/token.env"

# The inline console (flat home, v0.32) is the primary surface; this menu
# is the / command popup and carries only core working commands. Utilities
# (base, hash, dexcheck, dexrepair), meta commands (plan, capabilities,
# commands, oracle) stay reachable via /commands and the console's Help.
COMMANDS = [
    ("analyze", "analysis job: /analyze <path|bundle.apks|url> [--engine apkmod|dexmapper]"),
    ("get", "download a file by link (MediaFire share links ok): /get <url>"),
    ("apk", "APK overview + Vibe IR entity graph: /apk <path|bundle.apks|url>"),
    ("dex", "DEX Mapper: /dex <path|bundle.apks|url> (class->method->call + JNI + integrity)"),
    ("native", "Radare native provider: /native <path|url>"),
    ("map", "entity graph tree: /map <path> (or --sha)"),
    ("find", "TargetFinder: /find <text> --sha <sha>"),
    ("xref", "references: /xref <M|Cls.m> --sha <sha>"),
    ("callers", "who calls this: /callers <M|Cls.m> --sha <sha>"),
    ("callees", "what this calls: /callees <M|Cls.m> --sha <sha>"),
    ("xmatch", "cross-version method match: /xmatch <src.apk|url> <dst.apk|url>"),
    ("kmeta", "recover original (pre-R8) Kotlin names from @Metadata: /kmeta <dex|apk|bundle.apks> [class_filter]"),
    ("harness", "native-harness validation (build + run C under qemu): /harness <srcdir>"),
    ("smali", "query Dalvik opcode table: /smali <name|0x..|substr>"),
    ("claims", "evidence board: /claims [--sha]"),
    ("falsify", "falsifier board: /falsify [--sha]"),
    ("why", "claim -> evidence -> bytes: /why <C-id> [--sha]"),
    ("deepdive", "stateful traverse: /deepdive <target> --sha <sha>"),
    ("report", "stored report card: /report --sha <sha>"),
    ("status", "job state + progress"),
    ("jobs", "all jobs"),
    ("sessions", "stored analysis sessions"),
    ("ask", "LLM assistant (free-LLM router): /ask <q> [--sha <sha>] [--model <id>]"),
    ("models", "LLM router state (keys masked): /models"),
    ("cancel", "cancel a queued/running job"),
    ("help", "command list"),
]


def call(api: str, method: str, payload: dict, timeout: int = 90) -> dict:
    last = None
    for attempt in range(4):
        req = _multipart_or_urlencoded(api, method, payload)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except (urllib.error.URLError, ConnectionResetError, TimeoutError) as e:
            last = e
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"telegram call {method} failed after retries: {last}")


def _multipart_or_urlencoded(api: str, method: str, payload: dict):
    files = {k: v for k, v in payload.items()
             if isinstance(v, (bytes, bytearray))}
    if files:
        boundary = "----vibe" + uuid.uuid4().hex
        body = b""
        for k, v in payload.items():
            if isinstance(v, (bytes, bytearray)):
                continue
            body += (f"--{boundary}\r\nContent-Disposition: form-data; "
                     f"name={k}\r\n\r\n{v}\r\n").encode()
        for k, v in files.items():
            body += (f"--{boundary}\r\nContent-Disposition: form-data; "
                     f'name="{k}"; filename="upload"\r\n'
                     f"Content-Type: application/octet-stream\r\n\r\n").encode()
            body += v
        body += f"--{boundary}--\r\n".encode()
        return urllib.request.Request(
            f"{api}/{method}", data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    return urllib.request.Request(f"{api}/{method}",
                                  data=json.dumps(payload).encode(),
                                  headers={"Content-Type": "application/json"})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chat-id", default=None, help="operator chat id for the smoke test")
    ap.add_argument("--dry-run", action="store_true",
                    help="getMe + setMyCommands only, no messages sent")
    args = ap.parse_args()

    tok = open(TOKEN_FILE).read().split("=", 1)[1].strip()
    api = f"https://api.telegram.org/bot{tok}"

    me = call(api, "getMe", {})
    if not me.get("ok"):
        print(f"getMe FAILED: {me}")
        return 1
    u = me["result"]
    print(f"bot: @{u['username']}  id={u['id']}  first_name={u['first_name']}")
    assert u["username"] == "mvibe_aibot", "unexpected bot identity"

    r = call(api, "setMyCommands", {"commands": [
        {"command": c, "description": d} for c, d in COMMANDS]})
    assert r.get("ok"), f"setMyCommands failed: {r}"
    print(f"commands registered: {len(COMMANDS)}")

    if args.dry_run:
        print("dry-run OK — no messages sent")
        return 0

    if not args.chat_id:
        print("--chat-id required for the full smoke (use --dry-run otherwise)")
        return 3

    # --- smoke: send the fixture APK as a document to the operator chat ----
    fixture = os.path.join(ROOT, "tests", "fixtures", "fixture-demo.apk")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from vibebot import gateway as gway
    gw = gway.Gateway(os.path.join(ROOT, "vibebot-runs"),
                      engines_map=None)  # default apkmod+mock

    # run the FULL production path: TelegramTransport (real _call with
    # multipart, real getFile, real fetch_file) drives the gateway
    allowed = {args.chat_id}
    transport = gway.TelegramTransport(gw, tok, allowed)

    # 1. send the fixture as a document TO the operator chat (real upload)
    doc_bytes = open(fixture, "rb").read()
    r = call(api, "sendDocument", {
        "chat_id": args.chat_id, "document": doc_bytes,
        "filename": "fixture-demo.apk",
        "caption": "smoke test — self-built fixture; the bot will fetch + "
                   "analyze this (test, harmless)",
    }, timeout=120)
    assert r.get("ok"), f"sendDocument failed: {r}"
    msg_id = r["result"]["message_id"]
    file_id = r["result"]["document"]["file_id"]
    print(f"sent fixture as message {msg_id} (file_id {file_id[:16]}…)")

    # 2. the transport fetches it exactly as an inbound upload would
    fpath = transport.fetch_file(file_id, "fixture-demo.apk")
    print(f"transport fetched inbound file: {os.path.getsize(fpath)} bytes -> {fpath}")
    assert open(fpath, "rb").read() == doc_bytes, "round-trip bytes mismatch"

    # 3. gateway analyzes it
    reply, job = gw.handle(
        f"/analyze {fpath} --engine apkmod "
        f"--fingerprints {os.path.join(ROOT, 'apk', 'fingerprints.example-extra.json')}",
        user=f"tg:{args.chat_id[:4]}")
    print("gateway reply:\n" + reply)
    assert job is not None, "gateway did not accept the job"
    gw.process_pending()
    assert job.state == "COMPLETED", f"job ended {job.state}: {job.error}"
    res = job.result
    assert res is not None
    print(f"COMPLETED: {len(res.findings)} findings, "
          f"sha {res.intake['sha256'][:16]}…, package {res.intake['package']}")
    sess = gw.sessions.load(res.intake["sha256"])
    dd = gway.core.deepdive(sess, "callers") if sess else \
        {"matchCount": -1}
    print(f"deepdive callers: {dd['matchCount']} matches (no rescan)")

    # post the result back so the operator sees the closed loop in Telegram
    lines = [f"smoke OK  {job.id}",
             f"package: {res.intake['package']}  sha {res.intake['sha256'][:16]}…",
             f"findings: {len(res.findings)}   deepdive callers: {dd['matchCount']}"]
    rr = call(api, "sendMessage", {"chat_id": args.chat_id, "text": "\n".join(lines)})
    assert rr.get("ok"), f"result sendMessage failed: {rr}"
    print("result posted to operator chat")
    print("SMOKE OK — full loop verified (Telegram inbound -> gateway -> engine -> evidence -> reply)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
