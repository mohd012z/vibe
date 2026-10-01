"""Evidence graph and claim evaluation for Vibe.

This layer converts normalized observations into inspectable claims. It avoids
invented confidence scores: status is derived from supporting/contradicting
records and explicit unknowns.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from tools.vibe_evidence import EvidenceRecord


class ClaimStatus(str, Enum):
    SUPPORTED = "supported"
    CONFLICTED = "conflicted"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Claim:
    claim_id: str
    subject: str
    predicate: str
    object: str


@dataclass
class ClaimAssessment:
    claim: Claim
    status: ClaimStatus
    supporting: list[EvidenceRecord] = field(default_factory=list)
    contradicting: list[EvidenceRecord] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)


class EvidenceGraph:
    def __init__(self, records: Iterable[EvidenceRecord] = ()) -> None:
        self._records: dict[str, EvidenceRecord] = {}
        for record in records:
            self.add(record)

    def add(self, record: EvidenceRecord) -> None:
        self._records[record.evidence_id] = record

    def records(self) -> tuple[EvidenceRecord, ...]:
        return tuple(self._records.values())

    def for_target(self, target: str) -> list[EvidenceRecord]:
        return [r for r in self._records.values() if r.target == target]

    def find(self, *, kind: str | None = None, target: str | None = None) -> list[EvidenceRecord]:
        out = list(self._records.values())
        if kind is not None:
            out = [r for r in out if r.kind == kind]
        if target is not None:
            out = [r for r in out if r.target == target]
        return out


class ClaimEvaluator:
    """Evaluate claims against explicit support/contradiction observations.

    Providers may emit kinds `claim_support` and `claim_contradiction` with a
    value equal to the claim id. Other evidence remains available for human/AI
    explanation but is not silently converted into proof.
    """

    def assess(self, claim: Claim, graph: EvidenceGraph, unknowns: Iterable[str] = ()) -> ClaimAssessment:
        support = [r for r in graph.find(kind="claim_support") if r.value == claim.claim_id]
        contradict = [r for r in graph.find(kind="claim_contradiction") if r.value == claim.claim_id]
        unresolved = list(unknowns)
        if support and contradict:
            status = ClaimStatus.CONFLICTED
        elif support:
            status = ClaimStatus.SUPPORTED
        else:
            status = ClaimStatus.UNKNOWN
        return ClaimAssessment(claim, status, support, contradict, unresolved)


class Falsifier:
    """Expose evidence that challenges a claim; never hide contradictory data."""

    def challenge(self, assessment: ClaimAssessment) -> dict[str, object]:
        return {
            "claim_id": assessment.claim.claim_id,
            "status": assessment.status.value,
            "contradictions": [r.evidence_id for r in assessment.contradicting],
            "unknowns": list(assessment.unknowns),
            "needs_more_evidence": not assessment.contradicting and assessment.status is not ClaimStatus.SUPPORTED,
        }


class AnswerComposer:
    """Produce a compact structured answer suitable for Telegram/Web adapters."""

    def compose(self, assessment: ClaimAssessment) -> dict[str, object]:
        return {
            "claim": {
                "id": assessment.claim.claim_id,
                "subject": assessment.claim.subject,
                "predicate": assessment.claim.predicate,
                "object": assessment.claim.object,
            },
            "status": assessment.status.value,
            "supporting_evidence": [r.evidence_id for r in assessment.supporting],
            "contradicting_evidence": [r.evidence_id for r in assessment.contradicting],
            "unknowns": list(assessment.unknowns),
            "next": self._next(assessment),
        }

    @staticmethod
    def _next(assessment: ClaimAssessment) -> list[str]:
        if assessment.status is ClaimStatus.CONFLICTED:
            return ["resolve_conflict", "inspect_evidence"]
        if assessment.status is ClaimStatus.UNKNOWN:
            return ["collect_evidence", "inspect_unknowns"]
        if assessment.unknowns:
            return ["resolve_unknown", "falsify"]
        return ["falsify", "inspect_evidence"]
