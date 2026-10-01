from tools.vibe_claims import AnswerComposer, Claim, ClaimEvaluator, ClaimStatus, EvidenceGraph, Falsifier
from tools.vibe_evidence import EvidenceRecord


def ev(eid, kind, value, target="M81", provider="vibe"):
    return EvidenceRecord(eid, "EVIDENCE_VALIDATE", provider, target, kind, value, None)


def test_supported_claim_requires_explicit_support_record():
    claim = Claim("C17", "M81", "handles", "request")
    graph = EvidenceGraph([ev("E1", "claim_support", "C17")])
    result = ClaimEvaluator().assess(claim, graph)
    assert result.status is ClaimStatus.SUPPORTED
    assert [x.evidence_id for x in result.supporting] == ["E1"]


def test_support_plus_contradiction_is_conflicted_not_supported():
    claim = Claim("C17", "M81", "handles", "request")
    graph = EvidenceGraph([
        ev("E1", "claim_support", "C17"),
        ev("E2", "claim_contradiction", "C17", provider="ghidra"),
    ])
    result = ClaimEvaluator().assess(claim, graph)
    assert result.status is ClaimStatus.CONFLICTED
    assert [x.evidence_id for x in result.contradicting] == ["E2"]


def test_unrelated_observation_does_not_become_proof():
    claim = Claim("C17", "M81", "handles", "request")
    graph = EvidenceGraph([ev("E1", "xref_in", ["M72"])])
    result = ClaimEvaluator().assess(claim, graph, unknowns=["runtime_not_observed"])
    assert result.status is ClaimStatus.UNKNOWN
    assert result.supporting == []
    assert result.unknowns == ["runtime_not_observed"]


def test_falsifier_surfaces_conflicts_and_unknowns():
    claim = Claim("C17", "M81", "handles", "request")
    assessment = ClaimEvaluator().assess(
        claim,
        EvidenceGraph([ev("E1", "claim_support", "C17"), ev("E2", "claim_contradiction", "C17")]),
        unknowns=["runtime_not_observed"],
    )
    challenge = Falsifier().challenge(assessment)
    assert challenge["contradictions"] == ["E2"]
    assert challenge["unknowns"] == ["runtime_not_observed"]


def test_answer_composer_recommends_conflict_resolution_first():
    claim = Claim("C17", "M81", "handles", "request")
    assessment = ClaimEvaluator().assess(
        claim,
        EvidenceGraph([ev("E1", "claim_support", "C17"), ev("E2", "claim_contradiction", "C17")]),
    )
    answer = AnswerComposer().compose(assessment)
    assert answer["status"] == "conflicted"
    assert answer["next"][0] == "resolve_conflict"


def test_evidence_graph_deduplicates_by_evidence_id():
    graph = EvidenceGraph([ev("E1", "claim_support", "C17"), ev("E1", "claim_support", "C17")])
    assert len(graph.records()) == 1
