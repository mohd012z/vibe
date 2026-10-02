"""Provider-neutral contract for dispatching Vibe analysis jobs.

The contract intentionally accepts only named Vibe operations. Telegram/webhook
input must never become an arbitrary shell command or GitHub instruction.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import secrets
from typing import Any, Mapping


ALLOWED_OPERATIONS = frozenset({
    "analyze", "deepdive", "map", "find", "xref", "dex", "smali",
    "native", "strings", "urls", "resources", "report", "apk",
})


class JobValidationError(ValueError):
    pass


@dataclass(frozen=True)
class JobContract:
    job_id: str
    operation: str
    artifact_id: str
    chat_id: str
    parameters: dict[str, Any] = field(default_factory=dict)
    schema_version: int = 1

    @classmethod
    def create(
        cls,
        *,
        operation: str,
        artifact_id: str,
        chat_id: str,
        parameters: Mapping[str, Any] | None = None,
    ) -> "JobContract":
        op = operation.strip().lower()
        if op not in ALLOWED_OPERATIONS:
            raise JobValidationError(f"unsupported Vibe operation: {operation!r}")
        if not artifact_id.strip():
            raise JobValidationError("artifact_id is required")
        if not str(chat_id).strip():
            raise JobValidationError("chat_id is required")
        return cls(
            job_id=f"VIBE-{secrets.token_hex(4).upper()}",
            operation=op,
            artifact_id=artifact_id.strip(),
            chat_id=str(chat_id).strip(),
            parameters=dict(parameters or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, payload: str) -> "JobContract":
        data = json.loads(payload)
        if data.get("schema_version") != 1:
            raise JobValidationError("unsupported job schema version")
        operation = str(data.get("operation", "")).strip().lower()
        if operation not in ALLOWED_OPERATIONS:
            raise JobValidationError("unsupported Vibe operation")
        artifact_id = str(data.get("artifact_id", "")).strip()
        chat_id = str(data.get("chat_id", "")).strip()
        job_id = str(data.get("job_id", "")).strip()
        if not artifact_id or not chat_id or not job_id.startswith("VIBE-"):
            raise JobValidationError("invalid job contract")
        parameters = data.get("parameters", {})
        if not isinstance(parameters, dict):
            raise JobValidationError("parameters must be an object")
        return cls(
            job_id=job_id,
            operation=operation,
            artifact_id=artifact_id,
            chat_id=chat_id,
            parameters=parameters,
            schema_version=1,
        )
