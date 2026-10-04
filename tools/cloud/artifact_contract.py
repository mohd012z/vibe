from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
from datetime import datetime
from typing import Any

SCHEMA_VERSION = 1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ArtifactVerificationError(ValueError):
    """Artifact bytes or availability do not match the validated contract."""


@dataclass(frozen=True)
class ArtifactContract:
    artifact_id: str
    filename: str
    size_bytes: int
    sha256: str
    artifact_type: str
    retrieval_ref: str
    source_client: str
    expires_at: str
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported artifact schema version")
        for name in ("artifact_id", "filename", "artifact_type", "source_client", "expires_at"):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"{name} is required")
        if self.size_bytes < 0:
            raise ValueError("size_bytes must be non-negative")
        if not _SHA256.fullmatch(self.sha256):
            raise ValueError("sha256 must be 64 lowercase hex characters")
        if not self.retrieval_ref.startswith("artifact://") or len(self.retrieval_ref) <= len("artifact://"):
            raise ValueError("retrieval_ref must use controlled artifact:// scheme")
        parsed = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ArtifactContract":
        return cls(
            artifact_id=str(payload.get("artifact_id", "")),
            filename=str(payload.get("filename", "")),
            size_bytes=int(payload.get("size_bytes", -1)),
            sha256=str(payload.get("sha256", "")),
            artifact_type=str(payload.get("artifact_type", "")),
            retrieval_ref=str(payload.get("retrieval_ref", "")),
            source_client=str(payload.get("source_client", "")),
            expires_at=str(payload.get("expires_at", "")),
            schema_version=int(payload.get("schema_version", 0)),
        )

    @classmethod
    def from_json(cls, raw: str) -> "ArtifactContract":
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("artifact payload must be an object")
        return cls.from_dict(payload)
