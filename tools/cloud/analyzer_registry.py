from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

_WORKLOADS = frozenset({"light", "compute", "heavy"})
_ASSIST_SIZE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class AnalyzerSpec:
    name: str
    workload: str = "light"
    local: bool = True
    github_assist: bool = False
    checkpoint: bool = False
    tools: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("analyzer name is required")
        if self.workload not in _WORKLOADS:
            raise ValueError("unsupported workload class")
        object.__setattr__(self, "tools", tuple(self.tools))


@dataclass(frozen=True)
class WorkloadProfile:
    workload: str
    local_viable: bool
    github_assist_beneficial: bool


class AnalyzerRegistry:
    def __init__(self, specs: Iterable[AnalyzerSpec] = ()) -> None:
        self._specs: dict[str, AnalyzerSpec] = {}
        for spec in specs:
            if spec.name in self._specs:
                raise ValueError(f"duplicate analyzer capability: {spec.name}")
            self._specs[spec.name] = spec

    def get(self, name: str) -> AnalyzerSpec:
        try:
            return self._specs[name]
        except KeyError:
            raise KeyError(f"unknown analyzer capability: {name}") from None

    def profile(
        self,
        name: str,
        *,
        artifact_size_bytes: int = 0,
        cached: bool = False,
        available_tools: set[str] | None = None,
    ) -> WorkloadProfile:
        if artifact_size_bytes < 0:
            raise ValueError("artifact_size_bytes must be non-negative")

        spec = self.get(name)
        tools = set(available_tools) if available_tools is not None else None
        tools_available = tools is None or set(spec.tools).issubset(tools)
        local_viable = spec.local and tools_available

        assist = False
        if spec.github_assist:
            if not local_viable:
                assist = True
            elif spec.workload == "heavy":
                assist = True
            elif spec.workload == "compute" and not cached and artifact_size_bytes >= _ASSIST_SIZE_BYTES:
                assist = True

        return WorkloadProfile(
            workload=spec.workload,
            local_viable=local_viable,
            github_assist_beneficial=assist,
        )
