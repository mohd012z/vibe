from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RouteDecision:
    route: str
    reason: str


class CapabilityRouter:
    """Deterministic, free-first execution router.

    Light work stays local. Heavy work may also stay local when the runtime has
    the capability; GitHub is an optional assistant or fallback. A missing
    network/free budget never blocks capable local heavy execution.
    """

    _MODES = frozenset({"auto", "local", "github"})

    def __init__(self, *, local_operations: set[str], heavy_operations: set[str]) -> None:
        self.local_operations = frozenset(local_operations)
        self.heavy_operations = frozenset(heavy_operations)
        overlap = self.local_operations & self.heavy_operations
        if overlap:
            raise ValueError(f"operations cannot be both light and heavy: {sorted(overlap)!r}")

    def route(
        self,
        operation: str,
        requested_mode: str,
        network_available: bool,
        cloud_budget_available: bool,
        *,
        local_heavy_available: bool = False,
        github_assist_beneficial: bool = False,
    ) -> RouteDecision:
        if requested_mode not in self._MODES:
            return RouteDecision("rejected", "unknown_mode")

        is_light = operation in self.local_operations
        is_heavy = operation in self.heavy_operations
        if not (is_light or is_heavy):
            return RouteDecision("rejected", "unknown_operation")

        if requested_mode == "github":
            if not network_available:
                return RouteDecision("held", "network_unavailable")
            if not cloud_budget_available:
                return RouteDecision("held", "cloud_budget_exhausted")
            return RouteDecision("github", "explicit_github")

        if is_light:
            return RouteDecision("local", "local_capability_available")

        # Heavy operation: local-first whenever the local heavy engine exists.
        if local_heavy_available:
            if requested_mode == "local":
                return RouteDecision("local", "local_heavy_capability_available")
            if github_assist_beneficial:
                if not network_available:
                    return RouteDecision("local", "github_assist_network_unavailable")
                if not cloud_budget_available:
                    return RouteDecision("local", "github_assist_budget_exhausted")
                return RouteDecision("local+github", "github_assist_beneficial")
            return RouteDecision("local", "local_heavy_capability_available")

        if requested_mode == "local":
            return RouteDecision("held", "local_capability_unavailable")

        # Auto fallback: GitHub is used only when local heavy execution is not
        # available and the free remote path can actually run.
        if not network_available:
            return RouteDecision("held", "network_unavailable")
        if not cloud_budget_available:
            return RouteDecision("held", "cloud_budget_exhausted")
        return RouteDecision("github", "local_capability_unavailable")
