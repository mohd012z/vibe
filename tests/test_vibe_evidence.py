from tools.vibe_capabilities import InvestigationPlan, PlanStep
from tools.vibe_conversation import Intent
from tools.vibe_evidence import InvestigationExecutor, Observation, StaticProvider


class BrokenProvider:
    name = "radare2"
    def supports(self, capability):
        return capability == "REFERENCE_IN"
    def observe(self, capability, target):
        raise RuntimeError("provider unavailable")


class FallbackProvider:
    name = "ghidra"
    def supports(self, capability):
        return capability == "REFERENCE_IN"
    def observe(self, capability, target):
        return [Observation(capability, self.name, target, "xref_in", ["M72"])]


def test_executor_prefers_registry_provider_order_and_falls_back():
    plan = InvestigationPlan(Intent.DEEP_DIVE, "M81", [PlanStep("REFERENCE_IN", "M81", "test")])
    result = InvestigationExecutor([BrokenProvider(), FallbackProvider()]).execute(plan)
    assert not result.blocked
    assert len(result.evidence) == 1
    assert result.evidence[0].provider == "ghidra"
    assert result.evidence[0].value == ["M72"]
    assert result.failures[0].provider == "radare2"


def test_evidence_id_is_stable_for_same_observation():
    provider = StaticProvider("vibe", {("EVIDENCE_READ", "M81"): [("claim", "supported")]})
    plan = InvestigationPlan(Intent.ASK, "M81", [PlanStep("EVIDENCE_READ", "M81", "test")])
    a = InvestigationExecutor([provider]).execute(plan)
    b = InvestigationExecutor([provider]).execute(plan)
    assert a.evidence[0].evidence_id == b.evidence[0].evidence_id


def test_duplicate_observations_are_deduplicated():
    provider = StaticProvider("vibe", {("EVIDENCE_READ", None): [("fact", "x"), ("fact", "x")]})
    plan = InvestigationPlan(Intent.ASK, None, [PlanStep("EVIDENCE_READ", None, "test")])
    result = InvestigationExecutor([provider]).execute(plan)
    assert len(result.evidence) == 1


def test_blocked_plan_is_not_executed():
    plan = InvestigationPlan(Intent.UNKNOWN, None, blocked=True, reason="clarification required")
    result = InvestigationExecutor([]).execute(plan)
    assert result.blocked
    assert result.reason == "clarification required"


def test_write_capability_is_refused_even_if_injected_into_plan():
    plan = InvestigationPlan(Intent.PROCEED, "M81", [PlanStep("PATCH_COMMIT", "M81", "injected")])
    result = InvestigationExecutor([]).execute(plan)
    assert result.blocked
    assert "refuses write capability" in result.reason
