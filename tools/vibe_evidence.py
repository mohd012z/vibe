"""Normalized evidence execution for Vibe investigation plans.

Providers return observations only. This layer assigns stable evidence records,
keeps provider failures visible, and prevents read-only plans from silently
crossing into mutation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Protocol

from tools.vibe_capabilities import CapabilityRegistry, InvestigationPlan


@dataclass(frozen=True)
class Observation:
    capability: str
    provider: str
    target: str | None
    kind: str
    value: Any
    source: str | None = None


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    capability: str
    provider: str
    target: str | None
    kind: str
    value: Any
    source: str | None


@dataclass(frozen=True)
class ProviderFailure:
    capability: str
    provider: str
    reason: str


@dataclass
class ExecutionResult:
    evidence: list[EvidenceRecord] = field(default_factory=list)
    failures: list[ProviderFailure] = field(default_factory=list)
    blocked: bool = False
    reason: str | None = None


class EvidenceProvider(Protocol):
    name: str

    def supports(self, capability: str) -> bool: ...

    def observe(self, capability: str, target: str | None) -> list[Observation]: ...


class ProviderSelector:
    def __init__(self, providers: list[EvidenceProvider]) -> None:
        self.providers = providers

    def candidates(self, preferred: tuple[str, ...], capability: str) -> list[EvidenceProvider]:
        by_name = {p.name: p for p in self.providers}
        ordered = [by_name[name] for name in preferred if name in by_name and by_name[name].supports(capability)]
        extras = [p for p in self.providers if p.name not in preferred and p.supports(capability)]
        return ordered + extras


class EvidenceNormalizer:
    @staticmethod
    def normalize(observation: Observation) -> EvidenceRecord:
        canonical = "|".join([
            observation.capability,
            observation.provider,
            observation.target or "",
            observation.kind,
            repr(observation.value),
            observation.source or "",
        ])
        eid = "E-" + sha256(canonical.encode("utf-8")).hexdigest()[:16]
        return EvidenceRecord(
            evidence_id=eid,
            capability=observation.capability,
            provider=observation.provider,
            target=observation.target,
            kind=observation.kind,
            value=observation.value,
            source=observation.source,
        )


class InvestigationExecutor:
    def __init__(self, providers: list[EvidenceProvider], registry: CapabilityRegistry | None = None) -> None:
        self.registry = registry or CapabilityRegistry()
        self.selector = ProviderSelector(providers)
        self.normalizer = EvidenceNormalizer()

    def execute(self, plan: InvestigationPlan) -> ExecutionResult:
        if plan.blocked:
            return ExecutionResult(blocked=True, reason=plan.reason)

        result = ExecutionResult()
        seen: set[str] = set()
        for step in plan.steps:
            capability = self.registry.get(step.capability)
            if capability is None:
                result.blocked = True
                result.reason = f"Unknown capability in plan: {step.capability}"
                return result
            if capability.access.value != "read":
                result.blocked = True
                result.reason = f"Execution layer refuses write capability: {step.capability}"
                return result

            candidates = self.selector.candidates(capability.providers, step.capability)
            if not candidates:
                result.failures.append(ProviderFailure(step.capability, "none", "No provider available"))
                continue

            produced = False
            for provider in candidates:
                try:
                    observations = provider.observe(step.capability, step.target)
                except Exception as exc:  # provider boundary: preserve failure, try fallback
                    result.failures.append(ProviderFailure(step.capability, provider.name, f"{type(exc).__name__}: {exc}"))
                    continue
                for observation in observations:
                    record = self.normalizer.normalize(observation)
                    if record.evidence_id not in seen:
                        seen.add(record.evidence_id)
                        result.evidence.append(record)
                        produced = True
                if produced:
                    break
            if not produced and not any(f.capability == step.capability for f in result.failures):
                result.failures.append(ProviderFailure(step.capability, "available", "Providers returned no observations"))
        return result


class StaticProvider:
    """Small adapter useful for tests and deterministic Vibe-owned evidence."""
    def __init__(self, name: str, data: dict[tuple[str, str | None], list[tuple[str, Any]]]) -> None:
        self.name = name
        self.data = data

    def supports(self, capability: str) -> bool:
        return any(key[0] == capability for key in self.data)

    def observe(self, capability: str, target: str | None) -> list[Observation]:
        return [Observation(capability, self.name, target, kind, value) for kind, value in self.data.get((capability, target), [])]
