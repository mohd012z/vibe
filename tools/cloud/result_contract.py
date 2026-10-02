from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
from typing import Any


SCHEMA_VERSION = 1


class ResultStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"


@dataclass(frozen=True)
class ResultContract:
    job_id: str
    status: ResultStatus
    operation: str
    summary: str = ""
    outputs: list[str] = field(default_factory=list)
    error: str = ""
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.job_id.strip():
            raise ValueError("job_id is required")
        if not self.operation.strip():
            raise ValueError("operation is required")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported result schema version: {self.schema_version}")
        if self.status in {ResultStatus.FAILED, ResultStatus.REJECTED} and not self.error.strip():
            raise ValueError("failed/rejected results require an error")

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ResultContract":
        return cls(
            job_id=str(payload.get("job_id", "")),
            status=ResultStatus(str(payload.get("status", ""))),
            operation=str(payload.get("operation", "")),
            summary=str(payload.get("summary", "")),
            outputs=[str(item) for item in payload.get("outputs", [])],
            error=str(payload.get("error", "")),
            schema_version=int(payload.get("schema_version", 0)),
        )

    @classmethod
    def from_json(cls, raw: str) -> "ResultContract":
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("result payload must be an object")
        return cls.from_dict(payload)
