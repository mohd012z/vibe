"""Capability registry and read-only investigation planner for Vibe.

Commands and natural-language requests compile into capabilities. The planner
never grants authorization: write capabilities remain explicit and gated by the
existing APK pipeline/patch policy.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from tools.vibe_conversation import Intent, VibeRequest


class Access(str, Enum):
    READ = "read"
    WRITE = "write"


@dataclass(frozen=True)
class Capability:
    id: str
    description: str
    access: Access = Access.READ
    requires_target: bool = False
    providers: tuple[str, ...] = ()
    prerequisites: tuple[str, ...] = ()


@dataclass(frozen=True)
class PlanStep:
    capability: str
    target: str | None
    reason: str


@dataclass
class InvestigationPlan:
    intent: Intent
    target: str | None
    steps: list[PlanStep] = field(default_factory=list)
    blocked: bool = False
    reason: str | None = None


class CapabilityRegistry:
    def __init__(self, capabilities: Iterable[Capability] | None = None) -> None:
        self._items: dict[str, Capability] = {}
        for capability in capabilities or default_capabilities():
            self.register(capability)

    def register(self, capability: Capability) -> None:
        if capability.id in self._items:
            raise ValueError(f"duplicate capability: {capability.id}")
        self._items[capability.id] = capability

    def get(self, capability_id: str) -> Capability | None:
        return self._items.get(capability_id)

    def all(self) -> tuple[Capability, ...]:
        return tuple(self._items.values())


class CapabilityMatcher:
    """Map typed requests to primitive capabilities, not shell commands."""

    _RECIPES: dict[Intent, tuple[str, ...]] = {
        Intent.FIND: ("ARTIFACT_INDEX", "STRING_SEARCH", "REFERENCE_RESOLVE"),
        Intent.EXPLAIN: ("EVIDENCE_READ", "CLAIM_EXPLAIN"),
        Intent.VALIDATE: ("EVIDENCE_READ", "CLAIM_VALIDATE"),
        Intent.FALSIFY: ("EVIDENCE_READ", "CONTRADICTION_SEARCH"),
        Intent.DEEP_DIVE: (
            "TARGET_RESOLVE",
            "REFERENCE_IN",
            "REFERENCE_OUT",
            "DEPENDENCY_MAP",
            "EVIDENCE_VALIDATE",
        ),
        Intent.ASK: ("EVIDENCE_READ",),
        Intent.FOLLOW_UP: ("EVIDENCE_READ",),
    }

    def match(self, request: VibeRequest) -> tuple[str, ...]:
        return self._RECIPES.get(request.intent, ())


class InvestigationPlanner:
    def __init__(self, registry: CapabilityRegistry | None = None) -> None:
        self.registry = registry or CapabilityRegistry()
        self.matcher = CapabilityMatcher()

    def plan(self, request: VibeRequest) -> InvestigationPlan:
        if request.needs_clarification:
            return InvestigationPlan(request.intent, request.target, blocked=True, reason=request.clarification)

        if request.pending_action is not None:
            cap = self.registry.get(request.pending_action.capability)
            if cap is None:
                return InvestigationPlan(request.intent, request.target, blocked=True, reason=f"Capability unavailable: {request.pending_action.capability}")
            if cap.access is Access.WRITE:
                return InvestigationPlan(request.intent, request.target, blocked=True, reason="Write capability requires the explicit authorization workflow.")
            return InvestigationPlan(request.intent, request.target, [PlanStep(cap.id, request.target, "approved pending read-only action")])

        capability_ids = self.matcher.match(request)
        if not capability_ids:
            return InvestigationPlan(request.intent, request.target, blocked=True, reason="No validated capability recipe exists for this intent yet.")

        steps: list[PlanStep] = []
        for capability_id in capability_ids:
            cap = self.registry.get(capability_id)
            if cap is None:
                return InvestigationPlan(request.intent, request.target, blocked=True, reason=f"Capability unavailable: {capability_id}")
            if cap.access is Access.WRITE:
                return InvestigationPlan(request.intent, request.target, blocked=True, reason=f"Recipe unexpectedly requested write capability: {capability_id}")
            if cap.requires_target and not request.target:
                return InvestigationPlan(request.intent, request.target, blocked=True, reason=f"{capability_id} requires a selected target.")
            steps.append(PlanStep(cap.id, request.target, cap.description))
        return InvestigationPlan(request.intent, request.target, steps)


def default_capabilities() -> tuple[Capability, ...]:
    return (
        Capability("ARTIFACT_INDEX", "Index artifact entities", providers=("androguard", "apktool", "jadx")),
        Capability("STRING_SEARCH", "Search indexed strings", providers=("androguard", "radare2", "jadx")),
        Capability("REFERENCE_RESOLVE", "Resolve search results to canonical targets", providers=("vibe",)),
        Capability("TARGET_RESOLVE", "Resolve the selected target", requires_target=True, providers=("vibe",)),
        Capability("REFERENCE_IN", "Find incoming references", requires_target=True, providers=("radare2", "ghidra", "androguard")),
        Capability("REFERENCE_OUT", "Find outgoing references", requires_target=True, providers=("radare2", "ghidra", "androguard")),
        Capability("DEPENDENCY_MAP", "Map target dependencies", requires_target=True, providers=("vibe", "radare2", "ghidra")),
        Capability("EVIDENCE_READ", "Read existing evidence", providers=("vibe",)),
        Capability("EVIDENCE_VALIDATE", "Validate evidence supporting the target", requires_target=True, providers=("vibe",)),
        Capability("CLAIM_EXPLAIN", "Explain the selected claim from evidence", providers=("vibe",)),
        Capability("CLAIM_VALIDATE", "Validate the selected claim", providers=("vibe",)),
        Capability("CONTRADICTION_SEARCH", "Search for contradictory evidence", providers=("vibe",)),
        Capability("ANALYZE_IMPACT", "Analyze dependency impact", requires_target=True, providers=("vibe",)),
        Capability("PATCH_COMMIT", "Commit an authorized ChangeSet", access=Access.WRITE, requires_target=True, providers=("apk_pipeline",)),
    )
