"""End-to-end orchestration for Vibe's read-only investigation cycle."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.vibe_capabilities import InvestigationPlanner
from tools.vibe_claims import AnswerComposer, Claim, ClaimEvaluator, EvidenceGraph
from tools.vibe_conversation import ConversationRouter, InvestigationContext
from tools.vibe_evidence import EvidenceProvider, InvestigationExecutor
from tools.vibe_memory import InvestigationMemory, MemoryItem, MemoryStore, Provenance


@dataclass
class OrchestrationResult:
    answer: dict[str, Any]
    blocked: bool = False
    failures: list[dict[str, str]] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)


class VibeOrchestrator:
    """Route → recall → plan → execute → evaluate → persist.

    Recalled claims are stale-by-default. This orchestrator never converts them
    back to supported without fresh explicit claim-support evidence.
    """

    def __init__(self, providers: list[EvidenceProvider], memory_root: str | Path) -> None:
        self.router = ConversationRouter()
        self.planner = InvestigationPlanner()
        self.executor = InvestigationExecutor(providers)
        self.store = MemoryStore(memory_root)

    def run(
        self,
        text: str,
        artifact_sha256: str,
        context: InvestigationContext,
        claim: Claim | None = None,
        label: str = "default",
    ) -> OrchestrationResult:
        iid = self.store.investigation_id(artifact_sha256, label)
        memory = self.store.recall(artifact_sha256, iid) or InvestigationMemory(iid, artifact_sha256)

        request = self.router.route(text, context)
        plan = self.planner.plan(request)
        if plan.blocked:
            return OrchestrationResult({"status": "blocked", "reason": plan.reason}, blocked=True)

        execution = self.executor.execute(plan)
        if execution.blocked:
            return OrchestrationResult({"status": "blocked", "reason": execution.reason}, blocked=True)

        for record in execution.evidence:
            memory.add(
                "targets",
                MemoryItem(
                    item_id=f"OBS:{record.evidence_id}",
                    kind="observation",
                    value={"target": record.target, "kind": record.kind, "value": record.value},
                    status="observed",
                    provenance=Provenance(record.provider, (record.evidence_id,)),
                ),
            )

        answer: dict[str, Any] = {
            "status": "observed" if execution.evidence else "unknown",
            "target": request.target,
            "evidence": [r.evidence_id for r in execution.evidence],
        }

        if claim is not None:
            graph = EvidenceGraph(execution.evidence)
            assessment = ClaimEvaluator().assess(claim, graph)
            answer = AnswerComposer().compose(assessment)
            memory.add(
                "claims",
                MemoryItem(
                    claim.claim_id,
                    "claim",
                    {"subject": claim.subject, "predicate": claim.predicate, "object": claim.object},
                    assessment.status.value,
                    Provenance("claim_evaluator", tuple(r.evidence_id for r in assessment.supporting + assessment.contradicting)),
                ),
            )

        for failure in execution.failures:
            memory.add(
                "unknowns",
                MemoryItem(
                    item_id=f"FAIL:{failure.capability}:{failure.provider}",
                    kind="provider_failure",
                    value=failure.reason,
                    status="unknown",
                    provenance=Provenance(failure.provider),
                ),
            )

        self.store.save(memory)
        return OrchestrationResult(
            answer,
            failures=[{"capability": f.capability, "provider": f.provider, "reason": f.reason} for f in execution.failures],
            evidence_ids=[r.evidence_id for r in execution.evidence],
        )
