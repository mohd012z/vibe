"""Command registry: single source of truth for the bot command surface.

Backlog #8 (lupoxyz): when the command surface crosses ~20, split the
"always-advertised" tier (L0) from the searchable registry (L1) so /help
stays short and /commands <query> finds the rest. This module is the
registry — pure over plain dicts (no androguard, unit-testable).

Tiers:
  0 = L0 — always shown in /help (core + cheap self-contained commands)
  1 = L1 — full surface, found via /commands <query>

The live Telegram menu is still built from vibebot_deploy.COMMANDS (do not
re-order it without redeploy); this registry is the in-bot searchable
surface and the canonical tier annotation.
"""
from __future__ import annotations

# (name, tier, summary, keywords) — keywords extend search beyond name+summary.
COMMANDS: list[dict] = [
    # ---- L0: always advertised (core + self-contained) ---------------------
    {"name": "help", "tier": 0, "summary": "command list (short)",
     "kw": ["?" , "menu", "commands", "usage"]},
    {"name": "commands", "tier": 0, "summary": "searchable command registry: /commands [query]",
     "kw": ["registry", "search", "list", "find command"]},
    {"name": "base", "tier": 0, "summary": "convert number bases (2..36)",
     "kw": ["number", "hex", "decimal", "octal", "radix", "convert"]},
    {"name": "hash", "tier": 0, "summary": "sha256 of a text string",
     "kw": ["sha", "digest", "checksum", "sum"]},
    {"name": "smali", "tier": 0, "summary": "query the Dalvik opcode table",
     "kw": ["opcode", "dalvik", "mnemonic", "instruction"]},
    {"name": "dexcheck", "tier": 0, "summary": "validate a DEX header",
     "kw": ["header", "magic", "adler", "sha-1", "integrity", "checksum"]},
    {"name": "dexrepair", "tier": 0, "summary": "dry-run DEX repair report",
     "kw": ["fix", "repair", "checksum", "sig", "restore"]},
    {"name": "capabilities", "tier": 0, "summary": "what's installed here",
     "kw": ["providers", "tools", "available", "installed", "environment"]},
    {"name": "plan", "tier": 0, "summary": "cheapest-capable method plan for a goal",
     "kw": ["goal", "method", "route", "strategy", "which tool"]},
    {"name": "status", "tier": 0, "summary": "job state + progress",
     "kw": ["progress", "queued", "running", "cancelled"]},
    {"name": "jobs", "tier": 0, "summary": "all jobs",
     "kw": ["history", "queue", "list jobs"]},
    {"name": "cancel", "tier": 0, "summary": "cancel a queued/running job",
     "kw": ["stop", "abort", "kill job"]},
    {"name": "report", "tier": 0, "summary": "stored report card by sha",
     "kw": ["card", "output", "result"]},
    # ---- L1: full surface (found via /commands <query>) --------------------
    {"name": "apk", "tier": 1, "summary": "APK overview + Vibe IR entity graph",
     "kw": ["overview", "ir", "entity", "graph", "package", "components"]},
    {"name": "analyze", "tier": 1, "summary": "analysis job (apkmod|dexmapper)",
     "kw": ["run", "job", "pipeline", "fingerprint"]},
    {"name": "dex", "tier": 1, "summary": "DEX Mapper: class->method->call + JNI + integrity",
     "kw": ["call graph", "jni", "method", "class", "bridge"]},
    {"name": "map", "tier": 1, "summary": "entity graph tree",
     "kw": ["tree", "structure", "hierarchy", "navigate"]},
    {"name": "find", "tier": 1, "summary": "TargetFinder: locate a string/class/method",
     "kw": ["search", "locate", "string", "reference"]},
    {"name": "xref", "tier": 1, "summary": "references to a method/class",
     "kw": ["cross-reference", "refs", "used by"]},
    {"name": "callers", "tier": 1, "summary": "who calls this method",
     "kw": ["incoming", "reverse", "call graph"]},
    {"name": "callees", "tier": 1, "summary": "what this method calls",
     "kw": ["outgoing", "forward", "call graph"]},
    {"name": "claims", "tier": 1, "summary": "evidence board (claims by state)",
     "kw": ["evidence", "states", "validated", "supported", "proposed"]},
    {"name": "falsify", "tier": 1, "summary": "deterministic falsifier board",
     "kw": ["refute", "contradiction", "challenge", "f1"]},
    {"name": "why", "tier": 1, "summary": "claim -> evidence -> bytes trace",
     "kw": ["trace", "provenance", "lineage", "explain"]},
    {"name": "deepdive", "tier": 1, "summary": "stateful traverse from a node",
     "kw": ["walk", "traverse", "follow", "calls"]},
    {"name": "investigate", "tier": 1, "summary": "orchestrated 18-stage investigation (job)",
     "kw": ["18", "stages", "deep", "full analysis"]},
    {"name": "native", "tier": 1, "summary": "Radare native provider: ELF fns/imports/exports + JNI",
     "kw": ["elf", "radare", "r2", "so", "library", "import", "export", "jni"]},
    {"name": "xmatch", "tier": 1, "summary": "cross-version method match (two builds)",
     "kw": ["cross-version", "diff", "fingerprint", "carry findings"]},
    {"name": "harness", "tier": 1, "summary": "native-harness validation (build + run C under qemu, E5)",
     "kw": ["qemu", "aarch64", "arm64", "behavior", "runtime test", "prove"]},
    {"name": "kmeta", "tier": 1, "summary": "recover original (pre-R8) Kotlin names from @Metadata (E2)",
     "kw": ["kotlin", "metadata", "rename", "r8", "obfuscated", "original names"]},
    {"name": "sessions", "tier": 1, "summary": "stored analysis sessions",
     "kw": ["stored", "cache", "sha", "previous"]},
]


def _score(cmd: dict, q: str) -> int:
    """0 = no match, else a rank weight (higher = better)."""
    if not q:
        return 1  # any query -> everything matches (list by tier)
    n = cmd["name"].lower()
    s = cmd["summary"].lower()
    kws = [k.lower() for k in cmd["kw"]]
    if n == q:
        return 200
    if n.startswith(q):
        return 100
    if q in n:
        return 80
    if q in kws:
        return 60
    if q in s:
        return 30
    return 0


def search(query: str) -> list[dict]:
    """Commands matching query, best first. Empty query -> L0 then L1."""
    q = query.strip().lower()
    if not q:
        return sorted(COMMANDS, key=lambda c: c["tier"])
    hits = [(c, _score(c, q)) for c in COMMANDS]
    hits = [(c, s) for c, s in hits if s > 0]
    hits.sort(key=lambda t: (-t[1], t[0]["name"]))
    return [c for c, _ in hits]


def by_tier(tier: int) -> list[dict]:
    return [c for c in COMMANDS if c["tier"] == tier]


def get(name: str) -> dict | None:
    return next((c for c in COMMANDS if c["name"] == name), None)


def render(query: str = "", limit: int = 12) -> str:
    """Human rendering for /commands [query]."""
    q = query.strip()
    hits = search(q)
    if q and not hits:
        return f"no commands match '{q}' — try /commands (L0 list)"
    lines = []
    if not q:
        lines.append("COMMANDS  (L0 always in /help · L1 searchable)")
        lines.append("  L0 (core):")
        for c in by_tier(0):
            lines.append(f"    /{c['name']:<12} {c['summary']}")
        lines.append("  L1 (full surface — /commands <query> to search):")
        for c in by_tier(1):
            lines.append(f"    /{c['name']:<12} {c['summary']}")
        return "\n".join(lines)
    lines.append(f"COMMANDS matching '{q}':")
    for c in hits[:limit]:
        lines.append(f"  /{c['name']:<12} {c['summary']}")
    if len(hits) > limit:
        lines.append(f"  … {len(hits) - limit} more")
    return "\n".join(lines)


def count() -> int:
    return len(COMMANDS)
