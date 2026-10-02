"""Runtime evidence abstraction for Vibe.

This module defines a provider-neutral boundary for authorized runtime
instrumentation. It does not inject, patch, bypass controls, or execute target
code itself. Backends (for example Frida/Gum) supply observations through the
RuntimeBackend protocol and Vibe normalizes them into its evidence model.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from tools.vibe_evidence import Observation


class RuntimeState(str, Enum):
    CREATED = "created"
    CONNECTING = "connecting"
    READY = "ready"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass(frozen=True)
class RuntimeTarget:
    process: str
    artifact_sha256: str
    architecture: str | None = None


@dataclass
class RuntimeSession:
    session_id: str
    target: RuntimeTarget
    state: RuntimeState = RuntimeState.CREATED
    backend: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuntimeEvent:
    kind: str
    value: Any
    source: str | None = None


class RuntimeBackend(Protocol):
    name: str

    def supports(self, capability: str) -> bool: ...

    def collect(self, capability: str, target: str | None) -> list[RuntimeEvent]: ...


class RuntimeEvidenceProvider:
    """Adapt a runtime backend to Vibe's EvidenceProvider interface."""
    name = "runtime"

    ALLOWED = {
        "RUNTIME_MODULES",
        "RUNTIME_SYMBOL_LOOKUP",
        "RUNTIME_TRACE",
        "RUNTIME_BACKTRACE",
        "RUNTIME_MEMORY_MAP",
        "RUNTIME_THREAD_MAP",
    }

    def __init__(self, backend: RuntimeBackend) -> None:
        self.backend = backend
        self.name = backend.name

    def supports(self, capability: str) -> bool:
        return capability in self.ALLOWED and self.backend.supports(capability)

    def observe(self, capability: str, target: str | None) -> list[Observation]:
        if capability not in self.ALLOWED:
            return []
        events = self.backend.collect(capability, target)
        return [
            Observation(
                capability=capability,
                provider=self.name,
                target=target,
                kind=event.kind,
                value=event.value,
                source=event.source,
            )
            for event in events
        ]


class StaticRuntimeBackend:
    """Deterministic backend for tests and replay of previously captured events."""
    name = "runtime-replay"

    def __init__(self, events: dict[tuple[str, str | None], list[RuntimeEvent]]) -> None:
        self.events = events

    def supports(self, capability: str) -> bool:
        return any(cap == capability for cap, _ in self.events)

    def collect(self, capability: str, target: str | None) -> list[RuntimeEvent]:
        return list(self.events.get((capability, target), ()))
