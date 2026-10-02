"""Evidence-aware conversation primitives for Vibe.

This module keeps conversational references separate from execution policy.
Natural language and slash commands resolve into typed requests; mutating
operations remain explicit and require their normal authorization gates.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Intent(str, Enum):
    ASK = "ask"
    FIND = "find"
    EXPLAIN = "explain"
    VALIDATE = "validate"
    FALSIFY = "falsify"
    DEEP_DIVE = "deep_dive"
    FOLLOW_UP = "follow_up"
    PROCEED = "proceed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PendingAction:
    action_id: str
    capability: str
    target: str | None = None
    mutating: bool = False
    description: str = ""


@dataclass
class InvestigationContext:
    artifact_id: str | None = None
    selected_target: str | None = None
    previous_target: str | None = None
    selected_claim: str | None = None
    selected_evidence: list[str] = field(default_factory=list)
    last_result_set: list[str] = field(default_factory=list)
    known: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    pending_actions: list[PendingAction] = field(default_factory=list)

    def select_target(self, target: str) -> None:
        if target != self.selected_target:
            self.previous_target = self.selected_target
            self.selected_target = target

    def set_results(self, results: list[str]) -> None:
        self.last_result_set = list(results)

    def offer(self, action: PendingAction) -> None:
        self.pending_actions = [action]

    def clear_pending(self) -> None:
        self.pending_actions.clear()


@dataclass(frozen=True)
class VibeRequest:
    intent: Intent
    text: str
    artifact_id: str | None
    target: str | None
    claim: str | None = None
    pending_action: PendingAction | None = None
    needs_clarification: bool = False
    clarification: str | None = None


class ReferenceResolver:
    """Resolve only high-confidence conversational references.

    Ambiguity is surfaced instead of guessed. Ordinals refer to the most recent
    result set. Pronouns resolve to the explicitly selected target.
    """

    _CURRENT = {"it", "this", "that", "this method", "that method", "this function", "that function"}
    _PREVIOUS = {"previous", "previous one", "the previous one"}
    _ORDINALS = {"first": 0, "second": 1, "third": 2}

    def resolve(self, phrase: str, ctx: InvestigationContext) -> tuple[str | None, str | None]:
        p = phrase.strip().lower().rstrip("?.!")
        if p in self._CURRENT:
            return ctx.selected_target, None if ctx.selected_target else "No target is selected."
        if p in self._PREVIOUS:
            return ctx.previous_target, None if ctx.previous_target else "No previous target is available."
        for word, index in self._ORDINALS.items():
            if word in p and ("one" in p or "result" in p or p == word):
                if index < len(ctx.last_result_set):
                    return ctx.last_result_set[index], None
                return None, f"The last result set has no {word} item."
        return None, None


class IntentResolver:
    """Small deterministic front door; an LLM may enrich UNKNOWN later."""

    def resolve(self, text: str) -> Intent:
        t = text.strip().lower()
        if t.startswith("/find ") or t.startswith("find "):
            return Intent.FIND
        if t.startswith("/deepdive") or "deep dive" in t:
            return Intent.DEEP_DIVE
        if t in {"why", "why?", "/why"} or t.startswith("why "):
            return Intent.EXPLAIN
        if t in {"prove it", "validate", "validate it", "/validate", "are you sure?", "are you sure"}:
            return Intent.VALIDATE
        if t.startswith("/falsify") or "contradict" in t:
            return Intent.FALSIFY
        if t in {"proceed", "yes", "do it", "continue", "go ahead"}:
            return Intent.PROCEED
        if t.startswith("/ask "):
            return Intent.ASK
        return Intent.FOLLOW_UP if t else Intent.UNKNOWN


class ConversationRouter:
    """Convert chat input into a typed VibeRequest without executing tools."""

    def __init__(self) -> None:
        self.intent = IntentResolver()
        self.references = ReferenceResolver()

    def route(self, text: str, ctx: InvestigationContext) -> VibeRequest:
        intent = self.intent.resolve(text)

        if intent is Intent.PROCEED:
            if len(ctx.pending_actions) != 1:
                return VibeRequest(
                    intent=intent,
                    text=text,
                    artifact_id=ctx.artifact_id,
                    target=ctx.selected_target,
                    needs_clarification=True,
                    clarification="Proceed requires exactly one pending action.",
                )
            action = ctx.pending_actions[0]
            # Mutating actions are identified but never treated as implicitly
            # authorized by conversational shorthand.
            if action.mutating:
                return VibeRequest(
                    intent=intent,
                    text=text,
                    artifact_id=ctx.artifact_id,
                    target=action.target or ctx.selected_target,
                    pending_action=action,
                    needs_clarification=True,
                    clarification=f"Confirm the explicit write action: {action.description or action.capability}.",
                )
            return VibeRequest(
                intent=intent,
                text=text,
                artifact_id=ctx.artifact_id,
                target=action.target or ctx.selected_target,
                pending_action=action,
            )

        # Exact short references may update the target of a follow-up.
        target, problem = self.references.resolve(text, ctx)
        if problem:
            return VibeRequest(
                intent=intent,
                text=text,
                artifact_id=ctx.artifact_id,
                target=None,
                needs_clarification=True,
                clarification=problem,
            )

        # Questions such as "why?" bind to the selected claim, while other
        # follow-ups inherit the selected target without fabricating a new one.
        return VibeRequest(
            intent=intent,
            text=text,
            artifact_id=ctx.artifact_id,
            target=target or ctx.selected_target,
            claim=ctx.selected_claim if intent in {Intent.EXPLAIN, Intent.VALIDATE, Intent.FALSIFY} else None,
        )


def follow_up_suggestions(ctx: InvestigationContext) -> list[dict[str, Any]]:
    """Evidence-state suggestions, ordered by information value."""
    out: list[dict[str, Any]] = []
    if ctx.conflicts:
        out.append({"kind": "resolve_conflict", "id": ctx.conflicts[0]})
    if ctx.unknowns:
        out.append({"kind": "resolve_unknown", "id": ctx.unknowns[0]})
    if ctx.selected_claim:
        out.append({"kind": "validate_claim", "id": ctx.selected_claim})
    if ctx.selected_target:
        out.append({"kind": "show_evidence", "id": ctx.selected_target})
    return out[:3]
