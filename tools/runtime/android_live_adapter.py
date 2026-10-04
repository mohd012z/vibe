"""Android-facing boundary for authorized live app testing.

This module deliberately models only capabilities an Android integration may
legitimately expose to Vibe. It does not read another app's private process
memory, inject code, bypass platform isolation, or fabricate unavailable
runtime evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .live_session import LiveRuntimeSession, RuntimeEvent


@dataclass(frozen=True)
class InstalledApp:
    package_name: str
    label: str
    launchable: bool = True

    def __post_init__(self) -> None:
        if not (self.package_name or "").strip():
            raise ValueError("package_name is required")


@dataclass(frozen=True)
class AndroidLiveCapabilities:
    process_status: bool = False
    observable_metrics: bool = False
    debug_logs: bool = False
    private_process_memory: bool = False


class AndroidLiveTestAdapter:
    """Thin Android adapter over the platform-neutral LiveRuntimeSession."""

    _CONTROLS = ("mark_issue", "snapshot", "pause_resume", "stop")
    _PRIVATE_KEYS = frozenset({
        "private_memory",
        "private_memory_bytes",
        "process_memory",
        "memory_dump",
        "heap_dump",
    })

    def __init__(
        self,
        *,
        installed_apps: Iterable[InstalledApp] = (),
        running_packages: Iterable[str] = (),
        capabilities: AndroidLiveCapabilities | None = None,
    ) -> None:
        apps = tuple(installed_apps)
        self._apps = {app.package_name: app for app in apps}
        self._app_order = tuple(app.package_name for app in apps)
        self._running_packages = frozenset(str(p) for p in running_packages)
        self._capabilities = capabilities or AndroidLiveCapabilities()
        self._target: InstalledApp | None = None
        self.session: LiveRuntimeSession | None = None

    def list_installed_apps(self) -> tuple[InstalledApp, ...]:
        return tuple(self._apps[p] for p in self._app_order)

    def select_target(self, package_name: str, *, authorized: bool) -> InstalledApp:
        if not authorized:
            raise PermissionError("explicit authorization is required for live runtime testing")
        try:
            app = self._apps[package_name]
        except KeyError:
            raise KeyError(f"installed app is not visible to adapter: {package_name}") from None
        self._target = app
        self.session = None
        return app

    def detect_capabilities(self) -> AndroidLiveCapabilities:
        # The Android adapter boundary must never advertise arbitrary access to
        # another app's private process memory, even if a caller supplied a
        # contradictory capability object.
        caps = self._capabilities
        return AndroidLiveCapabilities(
            process_status=bool(caps.process_status),
            observable_metrics=bool(caps.observable_metrics),
            debug_logs=bool(caps.debug_logs),
            private_process_memory=False,
        )

    def floating_controls(self) -> tuple[str, ...]:
        return self._CONTROLS

    def start_live_test(self, *, timestamp_ms: int | None = None) -> LiveRuntimeSession:
        if self._target is None:
            raise RuntimeError("select an authorized installed app before starting a live test")
        if not self._target.launchable and self._target.package_name not in self._running_packages:
            raise RuntimeError("target is not launchable and is not currently running")
        self.session = LiveRuntimeSession(self._target.package_name, authorized=True)
        self.session.start(timestamp_ms=timestamp_ms)
        return self.session

    def _session(self) -> LiveRuntimeSession:
        if self.session is None:
            raise RuntimeError("live test has not started")
        return self.session

    def mark_issue(self, summary: str, *, timestamp_ms: int | None = None) -> RuntimeEvent:
        return self._session().mark_issue(summary, timestamp_ms=timestamp_ms)

    def snapshot(
        self,
        metrics: Mapping[str, Any],
        *,
        timestamp_ms: int | None = None,
    ) -> RuntimeEvent:
        if not self.detect_capabilities().observable_metrics:
            raise RuntimeError("observable runtime metrics are unavailable")
        filtered = {k: v for k, v in dict(metrics).items() if k not in self._PRIVATE_KEYS}
        return self._session().snapshot(filtered, timestamp_ms=timestamp_ms)

    def pause_resume(self, *, timestamp_ms: int | None = None) -> RuntimeEvent:
        session = self._session()
        if session.state == "running":
            return session.pause(timestamp_ms=timestamp_ms)
        if session.state == "paused":
            return session.resume(timestamp_ms=timestamp_ms)
        raise RuntimeError(f"cannot pause/resume session from {session.state}")

    def stop(self, *, timestamp_ms: int | None = None) -> RuntimeEvent:
        return self._session().stop(timestamp_ms=timestamp_ms)
