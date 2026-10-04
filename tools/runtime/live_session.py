"""Platform-neutral live runtime session for authorized app testing.

This layer records only caller-supplied observable runtime evidence. It does
not attach to a process, read another app's private memory, inject code, or
bypass Android isolation. Platform adapters (Android/ADB/debug builds) are
responsible for collecting observations they are legitimately allowed to see.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping


_FORBIDDEN_SNAPSHOT_KEYS = frozenset({
    "private_memory",
    "private_memory_bytes",
    "process_memory",
    "memory_dump",
    "heap_dump",
})


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


@dataclass(frozen=True)
class RuntimeEvent:
    timestamp_ms: int
    kind: str
    summary: str
    data: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.timestamp_ms < 0:
            raise ValueError("timestamp_ms must be non-negative")
        if not self.kind.strip():
            raise ValueError("event kind is required")
        object.__setattr__(self, "data", MappingProxyType(dict(self.data)))


class LiveRuntimeSession:
    """Deterministic lifecycle + evidence timeline for one authorized target."""

    def __init__(self, package_name: str, *, authorized: bool) -> None:
        package = (package_name or "").strip()
        if not package:
            raise ValueError("package_name is required")
        if not authorized:
            raise PermissionError("explicit authorization is required for live runtime testing")
        self.package_name = package
        self.authorized = True
        self.state = "ready"
        self.timeline: list[RuntimeEvent] = []

    def _timestamp(self, timestamp_ms: int | None) -> int:
        ts = _now_ms() if timestamp_ms is None else int(timestamp_ms)
        if ts < 0:
            raise ValueError("timestamp_ms must be non-negative")
        if self.timeline and ts < self.timeline[-1].timestamp_ms:
            raise ValueError("runtime events must be chronological")
        return ts

    def _append(
        self,
        kind: str,
        summary: str,
        data: Mapping[str, Any] | None = None,
        *,
        timestamp_ms: int | None = None,
    ) -> RuntimeEvent:
        event = RuntimeEvent(
            self._timestamp(timestamp_ms),
            kind,
            str(summary),
            data or {},
        )
        self.timeline.append(event)
        return event

    def _require_active(self) -> None:
        if self.state not in {"running", "paused"}:
            raise RuntimeError(f"runtime capture unavailable while session is {self.state}")

    def start(self, *, timestamp_ms: int | None = None) -> RuntimeEvent:
        if self.state != "ready":
            raise RuntimeError(f"cannot start session from {self.state}")
        self.state = "running"
        return self._append("session", "started", {"package": self.package_name}, timestamp_ms=timestamp_ms)

    def pause(self, *, timestamp_ms: int | None = None) -> RuntimeEvent:
        if self.state != "running":
            raise RuntimeError(f"cannot pause session from {self.state}")
        self.state = "paused"
        return self._append("session", "paused", timestamp_ms=timestamp_ms)

    def resume(self, *, timestamp_ms: int | None = None) -> RuntimeEvent:
        if self.state != "paused":
            raise RuntimeError(f"cannot resume session from {self.state}")
        self.state = "running"
        return self._append("session", "resumed", timestamp_ms=timestamp_ms)

    def stop(self, *, timestamp_ms: int | None = None) -> RuntimeEvent:
        if self.state not in {"running", "paused"}:
            raise RuntimeError(f"cannot stop session from {self.state}")
        event = self._append("session", "stopped", timestamp_ms=timestamp_ms)
        self.state = "stopped"
        return event

    def observe(
        self,
        kind: str,
        summary: str,
        data: Mapping[str, Any] | None = None,
        *,
        timestamp_ms: int | None = None,
    ) -> RuntimeEvent:
        self._require_active()
        return self._append(kind, summary, data, timestamp_ms=timestamp_ms)

    def mark_issue(self, summary: str, *, timestamp_ms: int | None = None) -> RuntimeEvent:
        self._require_active()
        text = (summary or "").strip()
        if not text:
            raise ValueError("issue summary is required")
        return self._append("issue", text, {"evidence_checkpoint": True}, timestamp_ms=timestamp_ms)

    def snapshot(
        self,
        metrics: Mapping[str, Any],
        *,
        timestamp_ms: int | None = None,
    ) -> RuntimeEvent:
        self._require_active()
        data = dict(metrics)
        forbidden = _FORBIDDEN_SNAPSHOT_KEYS.intersection(data)
        if forbidden:
            raise ValueError("private process-memory capture is outside the live-session boundary")
        return self._append("snapshot", "runtime metrics", data, timestamp_ms=timestamp_ms)
