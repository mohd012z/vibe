# VibeBot — P6: CapabilityRouter + AnalysisBudget + stop-controller
#
# The /360 correction: "Use the cheapest method capable of resolving the
# current unknown" + "No bounded investigation -> agent loops". This module
# is the deterministic bottom of that: a live provider registry (what can
# actually run on THIS host), a method catalog with evidence-gain/cost,
# and a Budget that a Job enforces at every progress boundary so no command
# can hang. No AI, no network — stdlib only.
from __future__ import annotations

import importlib.util
import shutil
import threading
import time
from typing import Callable


# ---------------------------------------------------------------- providers
def _has_module(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _which(cmd: str) -> bool:
    return shutil.which(cmd) is not None


# (provider, detect_fn, what it enables) — detect_fn is called at detection
# time (never pre-evaluated), so the router reflects the CURRENT host.
PROVIDERS: list[tuple[str, Callable[[], bool], str]] = [
    ("androguard", lambda: _has_module("androguard"), "DEX / manifest / resources"),
    ("radare2", lambda: _which("r2") or _which("radare2"), "native ELF XREF / blocks"),
    ("jadx", lambda: _which("jadx"), "JADX readable reconstruction"),
    ("ghidra", lambda: _which("ghidraHeadless"), "independent native cross-check"),
    ("frida", lambda: _has_module("frida"), "runtime observation"),
    ("apktool", lambda: _which("apktool"), "resource decompile"),
    ("apksigner", lambda: _which("apksigner"), "signing (P21+)"),
    ("adb", lambda: _which("adb"), "runtime install / test (P23+)"),
]


def detect_providers() -> dict[str, bool]:
    """Snapshot of what is actually installed on this host. Honest: this is
    the ground truth the router degrades against, never a guess."""
    return {name: bool(detect()) for name, detect, _ in PROVIDERS}


PROVIDER_NOTES: dict[str, str] = {name: note for name, _, note in PROVIDERS}


# ------------------------------------------------------------------ catalog
LOW, MED, HIGH = "LOW", "MED", "HIGH"
COST_RANK = {LOW: 1, MED: 2, HIGH: 3}

# capability -> [method, evidence-level, cost, provider-or-None, note]
METHOD_CATALOG: dict[str, list[tuple[str, str, str, str | None, str]]] = {
    "identify": [
        ("sha256 + manifest inventory", "E1", LOW, None, "always available"),
        ("aapt2 dump badging", "E1", LOW, "apktool", "external badge dump"),
    ],
    "locate_string": [
        ("resource lookup", "E1", LOW, None, "AndroidManifest / res"),
        ("DEX string search", "E2", LOW, "androguard", "const-string corpus"),
        ("native string search", "E3", MED, "radare2", "r2 `ss`"),
    ],
    "find_references": [
        ("DEX XREF", "E2", LOW, "androguard", "const-string / invoke refs"),
        ("Radare XREF", "E3", MED, "radare2", "afl / axt"),
        ("Ghidra XREF", "E4", HIGH, "ghidra", "independent cross-check"),
    ],
    "cross_layer": [
        ("component→class→method path", "E2", LOW, "androguard", "Vibe IR"),
        ("JNI bridge", "E2", MED, "androguard", "native decl → .so boundary"),
        ("native function resolution", "E3", HIGH, "radare2", ".so → N → B → I"),
    ],
    "native_analysis": [
        ("ELF section / import / export", "E3", LOW, "radare2", "iS / iE / iI"),
        ("function / block / CFG", "E3", MED, "radare2", "afl / pdf"),
        ("Ghidra independent pass", "E4", HIGH, "ghidra", "11-blocks cross-check"),
    ],
    "runtime_observe": [
        ("Frida hook", "E5", HIGH, "frida", "observed in ONE test run"),
        ("ADB install + tap", "E5", MED, "adb", "requires device"),
    ],
    "readable_reconstruction": [
        ("androguard decode", "E1", LOW, "androguard", "structure"),
        ("JADX decompile", "E1", MED, "jadx", "≈ reconstructed, NOT original source"),
    ],
}


def method_available(method: str, provider: str | None,
                     providers: dict[str, bool]) -> bool:
    return provider is None or providers.get(provider, False)


def _value(evidence: str, cost: str) -> float:
    """expected useful evidence / analysis cost (correction #16). Higher
    evidence tier + lower cost = higher value. The E-tier scales because a
    native XREF (E3) / independent cross-check (E4) establishes more than a
    structural declaration (E1). Deliberately crude — the point is the
    RANKING, not a precise number."""
    tier = int(evidence[1]) if evidence[:2] in ("E1", "E2", "E3", "E4", "E5") else 1
    return round((tier / COST_RANK[cost]), 3)


def plan(goal: str, providers: dict[str, bool] | None = None) -> dict:
    """Deterministic method plan for a goal. Available methods first,
    ranked by value/cost; unavailable ones listed last with an honest
    'not installed' note (degrade, never fake)."""
    provs = providers if providers is not None else detect_providers()
    rows = METHOD_CATALOG.get(goal) or []
    available, unavailable = [], []
    for name, ev, cost, provider, note in rows:
        row = {"method": name, "evidence": ev, "cost": cost,
               "provider": provider, "note": note,
               "value": round(_value(ev, cost), 3)}
        if method_available(name, provider, provs):
            available.append(row)
        else:
            row["note"] = f"NOT AVAILABLE on this host ({provider} not installed) — {note}"
            unavailable.append(row)
    available.sort(key=lambda r: (-r["value"], COST_RANK[r["cost"]], r["method"]))
    return {"goal": goal, "available": available, "unavailable": unavailable,
            "providers": provs,
            "summary": (f"cheapest capable for '{goal}': "
                        + (available[0]["method"] if available
                           else "NONE available (install a provider)"))}


# ------------------------------------------------------------------ budget
class BudgetExceeded(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class Budget:
    """Bounded investigation: wall-time, provider calls, depth, and a
    stall detector (repeated identical progress step within a window).

    `now` is injectable for tests. The stop-controller raises
    BudgetExceeded at the enforcement points (job.progress/checkpoint).
    """

    def __init__(self, max_wall: float | None = None,
                 max_calls: int | None = None, max_depth: int | None = None,
                 stall_repeats: int = 4, stall_window: float = 20.0,
                 now=None):
        self.max_wall = max_wall
        self.max_calls = max_calls
        self.max_depth = max_depth
        self.stall_repeats = stall_repeats
        self.stall_window = stall_window
        self._now = now or time.monotonic
        self._t0 = self._now()
        self._calls = 0
        self._depth = 0
        self._recent: list[tuple[str, int, float]] = []

    @property
    def calls(self) -> int:
        return self._calls

    @property
    def depth(self) -> int:
        return self._depth

    def elapsed(self) -> float:
        return self._now() - self._t0

    def note_call(self) -> None:
        self._calls += 1
        if self.max_calls is not None and self._calls > self.max_calls:
            raise BudgetExceeded(f"provider-call budget exceeded ({self.max_calls})")

    def enter_depth(self) -> None:
        self._depth += 1
        if self.max_depth is not None and self._depth > self.max_depth:
            raise BudgetExceeded(f"depth budget exceeded ({self.max_depth})")

    def exit_depth(self) -> None:
        self._depth = max(0, self._depth - 1)

    def check_wall(self) -> None:
        if self.max_wall is not None and self.elapsed() > self.max_wall:
            raise BudgetExceeded(f"wall-time budget exceeded ({self.max_wall}s)")

    def record_progress(self, step: str, pct: int, note: str = "") -> None:
        self.check_wall()
        ts = self._now()
        self._recent.append((step, pct, ts))
        # drop events older than the stall window
        cutoff = ts - self.stall_window
        self._recent = [e for e in self._recent if e[2] >= cutoff]
        # stall: the same (step, pct) firing repeatedly with no change
        if self.stall_repeats:
            last = (step, pct)
            matches = [e for e in self._recent if (e[0], e[1]) == last]
            if len(matches) >= self.stall_repeats:
                raise BudgetExceeded(
                    f"stall detected: step '{step}@{pct}%' repeated "
                    f"{self.stall_repeats}x within {self.stall_window}s")

    def summary(self) -> str:
        def _f(v):
            return f"{v}s" if v is not None else "∞"
        return (f"wall≤{_f(self.max_wall)} calls≤{self.max_calls or '∞'} "
                f"depth≤{self.max_depth or '∞'} stall={self.stall_repeats}x/"
                f"{self.stall_window}s  [now: {self.elapsed():.1f}s/"
                f"{self._calls}c/d{self._depth}]")


# A sane default wall cap: even a huge APK should not hang a job for
# minutes. Cooperative stops (progress/checkpoint) fire inside this; the
# watchdog catches non-cooperative engines at max_wall + grace.
DEFAULT_MAX_WALL = 300.0


def budget_from_params(params: dict) -> Budget:
    """Build a Budget from a Job's params. Every job gets a wall cap (the
    user can raise it explicitly); calls/depth stay unbounded unless set."""
    return Budget(
        max_wall=params.get("max_wall", DEFAULT_MAX_WALL),
        max_calls=params.get("max_calls"),
        max_depth=params.get("max_depth"),
        stall_repeats=params.get("stall_repeats", 4),
        stall_window=params.get("stall_window", 20.0),
    )


def run_with_watchdog(fn, budget: Budget, *, grace: float = 30.0) -> object:
    """Run fn in a worker thread; if fn does not cooperate (never calls
    progress) and exceeds max_wall + grace, abandon it as a daemon and raise.
    Cooperative stops (fn calls budget.check_wall) raise normally. Returns
    fn's return value."""
    result: dict = {}

    def _worker() -> None:
        try:
            result["value"] = fn()
        except BaseException as e:  # noqa: BLE001 — re-raise on main thread
            result["error"] = e

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    # The watchdog only enforces its OWN deadline: if the job is non-
    # cooperative (never calls budget.progress) and outlives max_wall + grace,
    # abandon it. Cooperative jobs raise BudgetExceeded themselves (via
    # progress/checkpoint), which propagates through result["error"].
    while t.is_alive():
        t.join(timeout=0.2)
        if budget.max_wall is not None and \
                budget.elapsed() > budget.max_wall + grace:
            raise BudgetExceeded(
                f"watchdog: non-cooperative job exceeded {budget.max_wall}s + "
                f"{grace}s grace (abandoned)")
    if "error" in result:
        raise result["error"]
    return result.get("value")
