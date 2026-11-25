"""vibebot.llm — in-process free-LLM router (study 2026-10-28-freellmapi-*,
Path B). Stdlib + cryptography only; NO new bot dependency.

Design (port of the freellmapi router mechanisms, verified against
yawo/freellmapi-proxy server-rs + tashfeenahmed/freellmapi docs):
  * ONE OpenAI-compatible request/response shape — so the full FreeLLMAPI
    router (Path A, docker) or any other /v1 endpoint can replace a
    candidate transparently later.
  * Fallback chain ordered by (priority, penalty). penalty += PENALTY_429 on
    HTTP 429/5xx, -= 1 on success, capped, time-decayed (yawo router.rs).
  * 4-window quota per candidate (RPM/TPM/RPD/TPD) + in-flight LEASES that
    release in a finally (closes the tashfeenahmed concurrency gap).
  * SSE streaming parsed line-by-line (data: {json}); JSON path for small
    replies. Gemini-native candidates get a request translator.
  * Keys from env (one per candidate name) or a JSON file; keys are MASKED
    in all human output (never echo a key into Telegram).
  * /ask <question> [--sha <2+hex>] [--model <id>] [--stream] — when a
    session is given, the model is fed that session's STRUCTURED findings
    (claims/overview/falsifications), not raw bytes (grounded + cheap).
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request

# --------------------------------------------------------------------------- constants
#: seconds a candidate is skipped after a rate-limit/5xx hit
COOLDOWN_S = 90
PENALTY_429 = 10
PENALTY_5XX = 6
PENALTY_SUCCESS = -1
PENALTY_CAP = 100
#: wall-clock budget for the WHOLE fallback chain (one hop per candidate)
CHAIN_BUDGET_S = 90
#: per-candidate HTTP timeout
HOP_TIMEOUT_S = 45
#: token estimate ~ 4 chars (freellmapi's own estimate_tokens formula)
_CHARS_PER_TOKEN = 4
#: max context text fed to the model from a session
MAX_CONTEXT_CHARS = 12000
#: default model when the candidate has none pinned
DEFAULT_MODEL = "openai/gpt-4o-mini"

#: built-in candidate list (seeded from open-free-llm-api/awesome-freellm-apis
#: QUICK_REF + BEST_MODELS, 2026-10-28). Add/override via VIBE_LLM_CANDIDATES
#: (JSON) or the VIBE_LLM_<NAME>_API_KEY env contract. priority: lower = tried
#: first. No key set for a candidate -> it is skipped, not an error.
BUILTIN_CANDIDATES = [
    # team's own endpoint — always primary (private, 512K ctx, no free-tier
    # quota ceiling of its own)
    {"name": "minda", "api_base": "https://minda.cyberaman.my/v1",
     "model": "llm_model_fp8", "priority": 0,
     "rpm": 30, "tpm": 400_000, "rpd": 3000, "tpd": 40_000_000},
    # free public tiers (no-card), in rough priority order:
    {"name": "openrouter", "api_base": "https://openrouter.ai/api/v1",
     "model": "meta-llama/llama-3.3-70b-instruct:free", "priority": 10,
     "rpm": 20, "tpm": 100_000, "rpd": 5000, "tpd": 50_000_000},
    {"name": "groq", "api_base": "https://api.groq.com/openai/v1",
     "model": "llama-3.3-70b-versatile", "priority": 20,
     "rpm": 18, "tpm": 14_000, "rpd": 300, "tpd": 2_000_000},
    {"name": "cerebras", "api_base": "https://api.cerebras.ai/v1",
     "model": "llama3.3-70b", "priority": 30,
     "rpm": 30, "tpm": 100_000, "rpd": 1000, "tpd": 10_000_000},
    {"name": "google", "api_base": "https://generativelanguage.googleapis.com",
     "model": "gemini-2.0-flash", "priority": 40, "gemini_native": True,
     "rpm": 10, "tpm": 250_000, "rpd": 250, "tpd": 25_000_000},
    {"name": "mistral", "api_base": "https://api.mistral.ai/v1",
     "model": "mistral-small-latest", "priority": 50,
     "rpm": 13, "tpm": 200_000, "rpd": 1000, "tpd": 10_000_000},
    {"name": "cfw", "api_base": "https://api.cloudflare.com",
     "model": "@cf/mistralai/mistral-small-3.2-24b-instruct", "priority": 60,
     "rpm": 30, "tpm": 100_000, "rpd": 1000, "tpd": 10_000_000},
]

ENV_KEY_TMPL = "VIBE_LLM_{name}_API_KEY"
ENV_CANDIDATES = "VIBE_LLM_CANDIDATES"
ENV_KEYS_FILE = "VIBE_LLM_KEYS"
ENV_BASE_URL = "VIBE_LLM_BASE_URL"      #: M1: point ALL candidates at one
ENV_BASE_URL_KEY = "VIBE_LLM_BASE_URL_KEY"  #: OpenAI-compatible box via env
ENV_MODEL = "VIBE_LLM_MODEL"

DEFAULT_SYSTEM_PROMPT = (
    "You are VibeBot's assistant inside an Android RE workbench. Answer "
    "concisely (max ~180 words) unless told otherwise. When grounded in the "
    "provided session findings, cite finding IDs like [E3] and say plainly "
    "what is OBSERVED vs INFERRED vs UNKNOWN. Never invent artifacts, "
    "offsets, or finding IDs that are not in the context. If you do not "
    "know, say so.")


def _est_tokens(text: str) -> int:
    return max(1, (len(text or "") + _CHARS_PER_TOKEN - 1) // _CHARS_PER_TOKEN)


def mask_key(key: str | None) -> str:
    """Display form of a key: sk-abc...wxyz (first 6 / last 4)."""
    if not key:
        return "(no key)"
    if len(key) <= 10:
        return "***"
    return f"{key[:6]}...{key[-4:]}"


# --------------------------------------------------------------------------- state
class _State:
    """Per-candidate runtime: penalties, cooldowns, 4-window counters,
    in-flight leases. Thread-safe (bot worker threads call in parallel)."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.penalty: dict[str, int] = {}
        self.cooldown_until: dict[str, float] = {}
        self.req_window: dict[str, list[float]] = {}     # ts per minute
        self.tok_window: dict[str, list[tuple[float, int]]] = {}
        self.req_day: dict[str, list[float]] = {}
        self.tok_day: dict[str, list[tuple[float, int]]] = {}
        self.inflight: dict[str, int] = {}

    def decay(self, now: float | None = None) -> None:
        now = now or time.time()
        with self.lock:
            for name, p in list(self.penalty.items()):
                if p > 0 and now - self._last_hit.get(name, 0) > 120:
                    self.penalty[name] = max(0, p - 1)

    _last_hit: dict[str, float] = {}

    def on_429(self, name: str, now: float) -> None:
        with self.lock:
            self.penalty[name] = min(PENALTY_CAP,
                                     self.penalty.get(name, 0) + PENALTY_429)
            self.cooldown_until[name] = now + COOLDOWN_S
            self._last_hit[name] = now

    def on_5xx(self, name: str, now: float) -> None:
        with self.lock:
            self.penalty[name] = min(PENALTY_CAP,
                                     self.penalty.get(name, 0) + PENALTY_5XX)
            self._last_hit[name] = now

    def on_success(self, name: str) -> None:
        with self.lock:
            self.penalty[name] = max(0,
                                     self.penalty.get(name, 0) + PENALTY_SUCCESS)

    def cooled(self, name: str, now: float | None = None) -> bool:
        now = now or time.time()
        with self.lock:
            return self.cooldown_until.get(name, 0) > now

    def quota_ok(self, name: str, est_tok: int, cand: dict,
                 now: float | None = None) -> bool:
        now = now or time.time()
        minute = now - 60
        day = now - 86400
        with self.lock:
            rq = [t for t in self.req_window.get(name, []) if t > minute]
            tk = [(t, n) for (t, n) in self.tok_window.get(name, []) if t > minute]
            rd = [t for t in self.req_day.get(name, []) if t > day]
            td = [(t, n) for (t, n) in self.tok_day.get(name, []) if t > day]
            if len(rq) >= int(cand.get("rpm", 0)):
                return False
            if sum(n for _, n in tk) + est_tok > int(cand.get("tpm", 0)):
                return False
            if len(rd) >= int(cand.get("rpd", 0)):
                return False
            if sum(n for _, n in td) + est_tok > int(cand.get("tpd", 0)):
                return False
            return True

    def quota_note(self, name: str, est_tok: int, cand: dict,
                   now: float | None = None) -> None:
        now = now or time.time()
        with self.lock:
            self.req_window.setdefault(name, []).append(now)
            self.tok_window.setdefault(name, []).append((now, est_tok))
            self.req_day.setdefault(name, []).append(now)
            self.tok_day.setdefault(name, []).append((now, est_tok))

    def lease(self, name: str) -> None:
        with self.lock:
            self.inflight[name] = self.inflight.get(name, 0) + 1

    def release(self, name: str) -> None:
        with self.lock:
            self.inflight[name] = max(0, self.inflight.get(name, 0) - 1)

    def inflight_count(self, name: str) -> int:
        with self.lock:
            return self.inflight.get(name, 0)


# --------------------------------------------------------------------------- candidates
#: per-candidate key aliases: candidate name -> list of env vars tried in
#: order (besides VIBE_LLM_<NAME>_API_KEY). Minda's team key already lives
#: in /opt/data/.env (HERMES_CUSTOM_MINDA_CYBERAMAN_MY_API_KEY) — reuse it.
KEY_ALIASES = {
    "minda": ["HERMES_CUSTOM_MINDA_CYBERAMAN_MY_API_KEY"],
}


def _candidate_key(name: str, keys: dict[str, str]) -> str | None:
    env = os.environ.get(ENV_KEY_TMPL.format(name=name.upper()))
    if env:
        return env
    for alias in KEY_ALIASES.get(name, []):
        if os.environ.get(alias):
            return os.environ[alias]
    return keys.get(name)


def load_candidates() -> tuple[list[dict], str]:
    """Resolve the active candidate list + keys source label.

    Order of precedence per candidate:
      1. VIBE_LLM_BASE_URL (+ VIBE_LLM_BASE_URL_KEY / VIBE_LLM_BASE_URL_MODEL)
         -> a single 'override' candidate (M1 env-redirect).
      2. VIBE_LLM_CANDIDATES (JSON list) merged over the built-ins by name.
      3. keys: VIBE_LLM_<NAME>_API_KEY env, else VIBE_LLM_KEYS json file.
    """
    keys: dict[str, str] = {}
    keys_file = os.environ.get(ENV_KEYS_FILE)
    keys_src = "env"
    if keys_file and os.path.exists(keys_file):
        try:
            with open(keys_file, encoding="utf-8") as fh:
                keys = {k: v for k, v in json.load(fh).items() if v}
            keys_src = "file"
        except (OSError, json.JSONDecodeError):
            keys = {}

    cands = {c["name"]: dict(c) for c in BUILTIN_CANDIDATES}
    custom = os.environ.get(ENV_CANDIDATES)
    if custom:
        try:
            for c in json.loads(custom):
                name = str(c.get("name", "")).strip()
                if not name:
                    continue
                base = cands.get(name, {})
                base.update({k: v for k, v in c.items() if v is not None})
                base["name"] = name
                # defaults so a bare {"name","api_base","model"} entry is
                # usable (0 would make quota_ok() always reject)
                base.setdefault("rpm", 30)
                base.setdefault("tpm", 100_000)
                base.setdefault("rpd", 1000)
                base.setdefault("tpd", 10_000_000)
                cands[name] = base
        except json.JSONDecodeError:
            pass  # bad JSON -> fall back to built-ins, /models reports it

    base_url = os.environ.get(ENV_BASE_URL)
    if base_url:
        cands = {"override": {
            "name": "override",
            "api_base": base_url.rstrip("/"),
            "model": os.environ.get(ENV_MODEL) or DEFAULT_MODEL,
            "priority": -10,
            "rpm": 60, "tpm": 1_000_000, "rpd": 100_000, "tpd": 100_000_000,
        }}

    out = []
    for name, c in cands.items():
        key = _candidate_key(name, keys) if name != "override" else \
            (os.environ.get(ENV_BASE_URL_KEY) or _candidate_key("override", keys))
        if not key and name == "override":
            # base-url override without a key: still allow (some boxes are
            # keyless) but mark it.
            c["key"] = ""
        elif not key:
            continue  # no key -> skipped at route time, not an error
        else:
            c["key"] = key
        out.append(c)
    out.sort(key=lambda c: (int(c.get("priority", 999)), c["name"]))
    src_label = f"env+file({keys_src})" if keys else "env"
    if base_url:
        src_label = f"override({base_url})"
    return out, src_label


# --------------------------------------------------------------------------- transport
def _http_post_json(url: str, headers: dict, body: dict, timeout: float):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body_txt = e.read().decode("utf-8", "replace")
        except Exception:
            body_txt = ""
        return e.code, body_txt


def _parse_sse(text: str) -> tuple[str, str | None]:
    """SSE body -> (final full text, error-or-None). Handles both a complete
    stream and a truncated one (we read a bounded body)."""
    parts: list[str] = []
    err = None
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload == "[DONE]":
            break
        try:
            j = json.loads(payload)
        except json.JSONDecodeError:
            if len(payload) > 2:  # mid-line truncation at our read bound
                break
            continue
        if j.get("error"):
            err = str(j["error"].get("message") or j["error"])[:200]
            break
        try:
            ch = j["choices"][0]
            delta = ch.get("delta") or ch.get("message") or {}
            piece = delta.get("content")
            if piece:
                parts.append(piece)
        except (KeyError, IndexError, TypeError):
            continue
    return "".join(parts), err


def _to_gemini(cand: dict, model: str, messages: list[dict]) -> dict:
    """OpenAI chat messages -> Gemini v1beta :generateContent body."""
    system = [m["content"] for m in messages if m.get("role") == "system"]
    contents = [{"role": "user" if m.get("role") != "assistant" else "model",
                 "parts": [{"text": m["content"]}] }
                for m in messages if m.get("role") in ("user", "assistant")]
    body: dict = {"contents": contents or
                  [{"role": "user", "parts": [{"text": ""}]}]}
    if system:
        body["systemInstruction"] = {"parts": [{"text": "\n".join(system)}]}
    return body


def _from_gemini(text: str) -> str:
    try:
        j = json.loads(text)
        parts = (j.get("candidates") or [{}])[0].get("content", {}).get("parts") or []
        return "".join(p.get("text", "") for p in parts)
    except (json.JSONDecodeError, IndexError, TypeError, AttributeError):
        return ""


# --------------------------------------------------------------------------- router
class LLMRouter:
    """One process-wide router; the gateway keeps a single instance."""

    def __init__(self) -> None:
        self.state = _State()

    def _route_order(self, cands: list[dict]) -> list[dict]:
        now = time.time()
        self.state.decay(now)
        scored = sorted(
            cands,
            key=lambda c: (int(c.get("priority", 999)),
                           self.state.penalty.get(c["name"], 0), c["name"]))
        return [c for c in scored if not self.state.cooled(c["name"], now)]

    def ask(self, question: str, *,
            context: str | None = None,
            system: str | None = None,
            model: str | None = None,
            candidates: list[dict] | None = None) -> dict:
        """Route one chat question across the fallback chain.

        Returns {ok, text, candidate, model, hops:[{name,ms,status,reason}],
        error}. Never raises on route failure (the caller renders it)."""
        cands = candidates if candidates is not None else load_candidates()[0]
        if not cands:
            return {"ok": False, "text": "", "candidate": None, "model": None,
                    "hops": [], "error": "no LLM candidate has a key — set "
                            + ENV_KEY_TMPL.format(name="<NAME>")
                            + " (e.g. VIBE_LLM_MINDA_API_KEY) or "
                            + ENV_BASE_URL + " for an OpenAI-compatible box"}
        messages = [{"role": "system", "content": system or DEFAULT_SYSTEM_PROMPT}]
        if context:
            messages.append({"role": "user",
                             "content": f"GROUNDING CONTEXT (session findings, "
                                        f"cite IDs, do not invent):\n{context}"})
        messages.append({"role": "user", "content": question})
        est = _est_tokens(json.dumps(messages))

        start = time.time()
        hops: list[dict] = []
        for cand in self._route_order(cands):
            if time.time() - start > CHAIN_BUDGET_S:
                hops.append({"name": cand["name"], "ms": 0, "status": "budget",
                             "reason": "chain budget exhausted"})
                break
            name = cand["name"]
            m = model or cand.get("model") or DEFAULT_MODEL
            if not self.state.quota_ok(name, est, cand):
                hops.append({"name": name, "ms": 0, "status": "quota",
                             "reason": "per-window quota or in-flight limit"})
                continue
            self.state.lease(name)
            t0 = time.time()
            status, reason, text = "ok", None, ""
            try:
                text, status, reason = self._hop(cand, m, messages)
            finally:
                self.state.release(name)
            ms = int((time.time() - t0) * 1000)
            hops.append({"name": name, "ms": ms, "status": status,
                         "reason": reason, "model": m})
            if status == "ok" and text.strip():
                self.state.on_success(name)
                self.state.quota_note(name, est + _est_tokens(text), cand)
                return {"ok": True, "text": text.strip(), "candidate": name,
                        "model": m, "hops": hops, "error": None}
            if status == "429":
                self.state.on_429(name, time.time())
            elif status == "5xx":
                self.state.on_5xx(name, time.time())
            # 'quota' was pre-checked; fallthrough means retry next candidate
        return {"ok": False, "text": "", "candidate": None, "model": None,
                "hops": hops, "error": "all candidates failed (see /models)"}

    def _hop(self, cand: dict, model: str, messages: list[dict]) -> tuple[str, str, str | None]:
        """One candidate attempt -> (text, status, reason). status in
        ok|429|5xx|bad|nokey|err."""
        name = cand["name"]
        key = cand.get("key") or ""
        base = cand["api_base"].rstrip("/")
        if cand.get("gemini_native"):
            url = (f"{base}/v1beta/models/{model}:generateContent")
            headers = {"x-goog-api-key": key}
            body = _to_gemini(cand, model, messages)
        else:
            url = f"{base}/chat/completions"
            headers = {"Authorization": f"Bearer {key}"}
            body = {"model": model, "messages": messages,
                    "max_tokens": 700, "temperature": 0.3}
        st, raw = _http_post_json(url, headers, body, HOP_TIMEOUT_S)
        if st == 200:
            text = raw
            if cand.get("gemini_native"):
                text = _from_gemini(text)
            elif "data:" in raw[:200]:  # some boxes force SSE
                text, sse_err = _parse_sse(raw)
                if not text.strip():
                    return "", "bad", sse_err or "empty SSE stream"
            else:
                try:
                    text = json.loads(raw)["choices"][0]["message"]["content"]
                except (json.JSONDecodeError, KeyError, IndexError):
                    text, sse_err = _parse_sse(raw)
                    if not text.strip():
                        return "", "bad", sse_err or "unparseable 200 body"
            return (text or "").strip(), "ok", None
        if st == 429:
            return "", "429", None
        if st >= 500:
            return "", "5xx", f"HTTP {st}"
        if st in (401, 403):
            return "", "nokey", f"HTTP {st} (key rejected)"
        return "", "bad", f"HTTP {st}: {raw[:160]}"

    # ---------------------------------------------------------------- introspect
    def status(self) -> dict:
        cands, src = load_candidates()
        now = time.time()
        self.state.decay(now)
        return {
            "keys_source": src,
            "candidates": [
                {"name": c["name"],
                 "api_base": c["api_base"],
                 "model": c.get("model") or DEFAULT_MODEL,
                 "priority": int(c.get("priority", 999)),
                 "penalty": self.state.penalty.get(c["name"], 0),
                 "cooldown": "yes" if self.state.cooled(c["name"], now) else "no",
                 "inflight": self.state.inflight_count(c["name"]),
                 "key": mask_key(c.get("key"))}
                for c in cands],
            "budget_s": CHAIN_BUDGET_S,
        }


# module singleton (the gateway uses this)
ROUTER = LLMRouter()


# --------------------------------------------------------------------------- prompt build
def session_context(session: dict | None, max_chars: int = MAX_CONTEXT_CHARS) -> str:
    """Structured findings -> compact grounding block (NOT raw bytes)."""
    if not session:
        return ""
    lines: list[str] = []
    art = (session.get("artifact") or {})
    lines.append(f"artifact: {art.get('name', '?')} "
                 f"(sha256 {str(art.get('sha256', '?'))[:16]})")
    ov = session.get("overview")
    if isinstance(ov, dict) and ov:
        keep = {k: ov.get(k) for k in
                ("package", "versionName", "versionCode", "minSdk", "targetSdk")
                if ov.get(k) is not None}
        if keep:
            lines.append("overview: " + json.dumps(keep))
    claims = session.get("claims") or []
    if isinstance(claims, list):
        top = [c for c in claims if isinstance(c, dict)][:25]
        if top:
            lines.append(f"claims ({len(top)} of {len(claims)}):")
            for c in top:
                cid = c.get("id", "?")
                lines.append(
                    f"  [{cid}] {c.get('statement') or c.get('claim') or ''}"
                    .rstrip() +
                    (f"  conf={c.get('confidence')}" if c.get("confidence") is not None else ""))
    fals = session.get("falsifications") or []
    if isinstance(fals, list) and fals:
        top = [f for f in fals if isinstance(f, dict)][:10]
        lines.append(f"falsifications ({len(top)}):")
        for f in top:
            lines.append(f"  [{f.get('id', '?')}] {f.get('statement') or f.get('note') or ''}"
                         .rstrip())
    findings = session.get("findings") or []
    if isinstance(findings, list) and findings:
        top = [f for f in findings if isinstance(f, dict)][:15]
        lines.append(f"findings ({len(top)} of {len(findings)}):")
        for f in top:
            loc = f.get("location") or {}
            loc_s = loc.get("symbol") or loc.get("class") or loc.get("file") or \
                loc.get("offset") or ""
            lines.append(f"  [{f.get('id', '?')}] {f.get('evidence') or f.get('claim') or ''}"
                         .rstrip() + (f" @ {loc_s}" if loc_s else ""))
    out = "\n".join(lines)
    return out[:max_chars]
