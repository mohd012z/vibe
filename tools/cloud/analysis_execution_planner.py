from __future__ import annotations

from dataclasses import dataclass

from .analyzer_registry import AnalyzerRegistry
from .capability_router import CapabilityRouter


@dataclass(frozen=True)
class AnalysisExecutionPlan:
    analyzer: str
    route: str
    reason: str
    workload: str
    local_viable: bool
    github_assist_beneficial: bool
    checkpoint: bool


class AnalysisExecutionPlanner:
    """Bridge analyzer workload profiling into deterministic execution routing.

    The registry remains the source of truth for analyzer existence, workload,
    tool requirements and checkpoint support. The router remains the source of
    truth for local/GitHub/held routing. This class only composes those two
    decisions so policy is not duplicated.
    """

    def __init__(self, registry: AnalyzerRegistry, router: CapabilityRouter) -> None:
        self.registry = registry
        self.router = router

    def plan(
        self,
        analyzer: str,
        *,
        artifact_size_bytes: int = 0,
        cached: bool = False,
        available_tools: set[str] | None = None,
        requested_mode: str = "auto",
        network_available: bool = True,
        cloud_budget_available: bool = True,
    ) -> AnalysisExecutionPlan:
        # get/profile intentionally raise on an unknown analyzer: callers must
        # not silently invent a capability that is absent from the registry.
        spec = self.registry.get(analyzer)
        profile = self.registry.profile(
            analyzer,
            artifact_size_bytes=artifact_size_bytes,
            cached=cached,
            available_tools=available_tools,
        )

        decision = self.router.route(
            analyzer,
            requested_mode,
            network_available,
            cloud_budget_available,
            local_heavy_available=profile.local_viable,
            github_assist_beneficial=profile.github_assist_beneficial,
        )

        return AnalysisExecutionPlan(
            analyzer=analyzer,
            route=decision.route,
            reason=decision.reason,
            workload=profile.workload,
            local_viable=profile.local_viable,
            github_assist_beneficial=profile.github_assist_beneficial,
            checkpoint=spec.checkpoint,
        )
