from tools.vibe_claims import Claim
from tools.vibe_conversation import InvestigationContext
from tools.vibe_evidence import Observation, StaticProvider
from tools.vibe_memory import MemoryStore
from tools.vibe_orchestrator import VibeOrchestrator

SHA = "c" * 64


def test_end_to_end_observation_is_persisted(tmp_path):
    provider = StaticProvider("vibe", {("EVIDENCE_READ", "M81"): [("fact", "known")]})
    ctx = InvestigationContext(artifact_id=SHA, selected_target="M81")
    result = VibeOrchestrator([provider], tmp_path).run("/ask status", SHA, ctx)
    assert not result.blocked
    assert len(result.evidence_ids) == 1
    iid = MemoryStore.investigation_id(SHA)
    memory = MemoryStore(tmp_path).load(SHA, iid)
    assert memory is not None
    assert memory.targets[0].provenance.evidence_ids == tuple(result.evidence_ids)


def test_claim_without_explicit_support_stays_unknown(tmp_path):
    provider = StaticProvider("vibe", {("EVIDENCE_READ", "M81"): [("xref_in", ["M72"])]})
    ctx = InvestigationContext(artifact_id=SHA, selected_target="M81", selected_claim="C17")
    claim = Claim("C17", "M81", "handles", "request")
    result = VibeOrchestrator([provider], tmp_path).run("prove it", SHA, ctx, claim)
    assert result.answer["status"] == "unknown"


def test_fresh_explicit_support_can_validate_claim(tmp_path):
    provider = StaticProvider("vibe", {("EVIDENCE_READ", "M81"): [("claim_support", "C17")]})
    ctx = InvestigationContext(artifact_id=SHA, selected_target="M81", selected_claim="C17")
    claim = Claim("C17", "M81", "handles", "request")
    result = VibeOrchestrator([provider], tmp_path).run("prove it", SHA, ctx, claim)
    assert result.answer["status"] == "supported"
    memory = MemoryStore(tmp_path).load(SHA, MemoryStore.investigation_id(SHA))
    assert memory.claims[0].status == "supported"


def test_provider_failure_is_visible_and_persisted_as_unknown(tmp_path):
    class Broken:
        name = "vibe"
        def supports(self, capability): return capability == "EVIDENCE_READ"
        def observe(self, capability, target): raise RuntimeError("offline")
    ctx = InvestigationContext(artifact_id=SHA, selected_target="M81")
    result = VibeOrchestrator([Broken()], tmp_path).run("/ask status", SHA, ctx)
    assert result.failures
    memory = MemoryStore(tmp_path).load(SHA, MemoryStore.investigation_id(SHA))
    assert memory.unknowns[0].status == "unknown"


def test_blocked_request_does_not_create_memory(tmp_path):
    ctx = InvestigationContext(artifact_id=SHA)
    result = VibeOrchestrator([], tmp_path).run("/deepdive", SHA, ctx)
    assert result.blocked
    iid = MemoryStore.investigation_id(SHA)
    assert MemoryStore(tmp_path).load(SHA, iid) is None
