"""Read-only UI/provider projection for authorized Android live testing.

The provider owns presentation orchestration only. Runtime behavior remains in
AndroidLiveTestAdapter/LiveRuntimeSession so a future native Android UI can bind
to this boundary without duplicating analysis state.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .android_live_adapter import (
    AndroidLiveCapabilities,
    AndroidLiveTestAdapter,
    InstalledApp,
)
from .live_session import RuntimeEvent


@dataclass(frozen=True)
class ProviderApp:
    package_name: str
    label: str
    launchable: bool = True
    running: bool = False

    def __post_init__(self) -> None:
        if not (self.package_name or "").strip():
            raise ValueError("package_name is required")


@dataclass(frozen=True)
class RuntimeSample:
    cpu_pct: float | int | None = None
    rss_mb: float | int | None = None
    frame_ms: float | int | None = None

    def observable(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in (
                ("cpu_pct", self.cpu_pct),
                ("rss_mb", self.rss_mb),
                ("frame_ms", self.frame_ms),
            )
            if value is not None
        }


@dataclass(frozen=True)
class LiveTestScreenModel:
    target_package: str | None
    state: str
    foreground_session: bool
    timeline: tuple[RuntimeEvent, ...]


class AndroidLiveProvider:
    """Stable application-facing boundary above AndroidLiveTestAdapter."""

    _HOME_ACTIONS = ("test_installed_app", "test_apk_file", "live_test")

    def __init__(self, *, apps: Iterable[ProviderApp] = ()) -> None:
        visible = tuple(apps)
        self._apps = visible
        installed = tuple(
            InstalledApp(app.package_name, app.label, launchable=app.launchable)
            for app in visible
        )
        running = {app.package_name for app in visible if app.running}
        self._adapter = AndroidLiveTestAdapter(
            installed_apps=installed,
            running_packages=running,
            capabilities=AndroidLiveCapabilities(
                process_status=True,
                observable_metrics=True,
                debug_logs=False,
                private_process_memory=False,
            ),
        )
        self._target_package: str | None = None

    def home_actions(self) -> tuple[str, ...]:
        return self._HOME_ACTIONS

    def app_picker(self) -> tuple[ProviderApp, ...]:
        return self._apps

    def floating_controls(self) -> tuple[str, ...]:
        return self._adapter.floating_controls()

    def start(
        self,
        package_name: str,
        *,
        authorized: bool,
        timestamp_ms: int | None = None,
    ) -> LiveTestScreenModel:
        target = self._adapter.select_target(package_name, authorized=authorized)
        self._target_package = target.package_name
        self._adapter.start_live_test(timestamp_ms=timestamp_ms)
        return self.screen_model()

    def record_sample(
        self,
        sample: RuntimeSample,
        *,
        timestamp_ms: int | None = None,
    ) -> RuntimeEvent:
        if not isinstance(sample, RuntimeSample):
            raise TypeError("sample must be RuntimeSample")
        return self._adapter.snapshot(sample.observable(), timestamp_ms=timestamp_ms)

    def mark_issue(self, summary: str, *, timestamp_ms: int | None = None) -> RuntimeEvent:
        return self._adapter.mark_issue(summary, timestamp_ms=timestamp_ms)

    def pause_resume(self, *, timestamp_ms: int | None = None) -> RuntimeEvent:
        return self._adapter.pause_resume(timestamp_ms=timestamp_ms)

    def stop(self, *, timestamp_ms: int | None = None) -> RuntimeEvent:
        return self._adapter.stop(timestamp_ms=timestamp_ms)

    def screen_model(self) -> LiveTestScreenModel:
        session = self._adapter.session
        if session is None:
            return LiveTestScreenModel(
                target_package=self._target_package,
                state="idle",
                foreground_session=False,
                timeline=(),
            )
        return LiveTestScreenModel(
            target_package=self._target_package,
            state=session.state,
            foreground_session=session.state in {"running", "paused"},
            timeline=tuple(session.timeline),
        )
