from tools.vibe_conversation import (
    ConversationRouter,
    InvestigationContext,
    Intent,
    PendingAction,
    ReferenceResolver,
    follow_up_suggestions,
)


def test_current_reference_uses_selected_target():
    ctx = InvestigationContext(selected_target="M81")
    target, problem = ReferenceResolver().resolve("it", ctx)
    assert problem is None
    assert target == "M81"


def test_ordinal_reference_uses_last_result_set():
    ctx = InvestigationContext(last_result_set=["M72", "M81", "N17"])
    target, problem = ReferenceResolver().resolve("second one", ctx)
    assert problem is None
    assert target == "M81"


def test_why_binds_to_current_claim_and_target():
    ctx = InvestigationContext(artifact_id="A17", selected_target="M81", selected_claim="C17")
    req = ConversationRouter().route("why?", ctx)
    assert req.intent is Intent.EXPLAIN
    assert req.artifact_id == "A17"
    assert req.target == "M81"
    assert req.claim == "C17"


def test_proceed_executes_only_single_non_mutating_pending_action():
    ctx = InvestigationContext(selected_target="M81")
    action = PendingAction("A1", "ANALYZE_IMPACT", target="M81", mutating=False)
    ctx.offer(action)
    req = ConversationRouter().route("proceed", ctx)
    assert req.intent is Intent.PROCEED
    assert req.pending_action == action
    assert req.needs_clarification is False


def test_proceed_never_implicitly_authorizes_write():
    ctx = InvestigationContext(selected_target="M81")
    action = PendingAction("A2", "PATCH_COMMIT", target="M81", mutating=True, description="Commit ChangeSet C18")
    ctx.offer(action)
    req = ConversationRouter().route("do it", ctx)
    assert req.pending_action == action
    assert req.needs_clarification is True
    assert "explicit write action" in req.clarification


def test_proceed_without_unique_pending_action_requires_clarification():
    ctx = InvestigationContext(selected_target="M81")
    req = ConversationRouter().route("yes", ctx)
    assert req.needs_clarification is True


def test_followups_prioritize_conflict_then_unknown_then_validation():
    ctx = InvestigationContext(
        selected_target="M81",
        selected_claim="C17",
        conflicts=["X9"],
        unknowns=["U7"],
    )
    suggestions = follow_up_suggestions(ctx)
    assert suggestions == [
        {"kind": "resolve_conflict", "id": "X9"},
        {"kind": "resolve_unknown", "id": "U7"},
        {"kind": "validate_claim", "id": "C17"},
    ]
