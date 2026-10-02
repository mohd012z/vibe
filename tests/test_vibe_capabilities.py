from tools.vibe_capabilities import Access, CapabilityRegistry, InvestigationPlanner
from tools.vibe_conversation import ConversationRouter, InvestigationContext, PendingAction


def test_deep_dive_compiles_to_read_only_capability_plan():
    ctx = InvestigationContext(artifact_id="A17", selected_target="M81")
    req = ConversationRouter().route("deep dive this", ctx)
    plan = InvestigationPlanner().plan(req)
    assert not plan.blocked
    assert [step.capability for step in plan.steps] == [
        "TARGET_RESOLVE",
        "REFERENCE_IN",
        "REFERENCE_OUT",
        "DEPENDENCY_MAP",
        "EVIDENCE_VALIDATE",
    ]


def test_deep_dive_without_target_is_blocked():
    req = ConversationRouter().route("/deepdive", InvestigationContext(artifact_id="A17"))
    plan = InvestigationPlanner().plan(req)
    assert plan.blocked
    assert "requires a selected target" in plan.reason


def test_proceed_can_plan_single_pending_read_action():
    ctx = InvestigationContext(artifact_id="A17", selected_target="M81")
    ctx.offer(PendingAction("A1", "ANALYZE_IMPACT", target="M81", mutating=False))
    req = ConversationRouter().route("proceed", ctx)
    plan = InvestigationPlanner().plan(req)
    assert not plan.blocked
    assert [s.capability for s in plan.steps] == ["ANALYZE_IMPACT"]


def test_write_capability_is_never_implicitly_planned():
    ctx = InvestigationContext(artifact_id="A17", selected_target="M81")
    ctx.offer(PendingAction("A2", "PATCH_COMMIT", target="M81", mutating=True, description="Commit C18"))
    req = ConversationRouter().route("do it", ctx)
    plan = InvestigationPlanner().plan(req)
    assert plan.blocked
    assert "explicit write action" in plan.reason


def test_registry_marks_patch_commit_as_write():
    cap = CapabilityRegistry().get("PATCH_COMMIT")
    assert cap is not None
    assert cap.access is Access.WRITE


def test_unknown_intent_does_not_invent_a_capability():
    req = ConversationRouter().route("", InvestigationContext())
    plan = InvestigationPlanner().plan(req)
    assert plan.blocked
    assert "No validated capability recipe" in plan.reason
