from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

_ALLOWED_CLIENTS = frozenset({"telegram", "android"})
_ALLOWED_STATUSES = frozenset({
    "queued", "running", "held", "completed", "partial", "failed",
    "rejected", "cancelled", "expired",
})


@dataclass(frozen=True)
class DeliveryOutput:
    name: str
    artifact_ref: str

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("output name is required")
        if not self.artifact_ref.startswith("artifact://"):
            raise ValueError("delivery outputs must use controlled artifact:// references")


@dataclass(frozen=True)
class DeliveryContract:
    job_id: str
    destination_client: str
    destination_id: str
    status: str
    summary: str = ""
    outputs: list[DeliveryOutput] = field(default_factory=list)
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported delivery schema_version")
        if not self.job_id.strip():
            raise ValueError("job_id is required")
        if self.destination_client not in _ALLOWED_CLIENTS:
            raise ValueError("unsupported destination_client")
        if not self.destination_id.strip():
            raise ValueError("destination_id is required")
        if self.status not in _ALLOWED_STATUSES:
            raise ValueError("unsupported delivery status")
        if self.status == "completed" and not (self.summary.strip() or self.outputs):
            raise ValueError("completed delivery requires summary or output")
        if self.status in {"failed", "rejected", "cancelled", "expired"} and not self.summary.strip():
            raise ValueError("terminal unsuccessful delivery requires summary")

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "DeliveryContract":
        data: dict[str, Any] = json.loads(raw)
        data["outputs"] = [DeliveryOutput(**item) for item in data.get("outputs", [])]
        return cls(**data)
