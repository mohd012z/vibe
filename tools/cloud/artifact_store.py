from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Protocol

from tools.cloud.artifact_contract import ArtifactContract, ArtifactVerificationError


class ArtifactStore(Protocol):
    def put(self, retrieval_ref: str, data: bytes) -> None: ...
    def get(self, retrieval_ref: str) -> bytes: ...


class MemoryArtifactStore:
    """Test/reference adapter. Production storage implements the same boundary."""

    def __init__(self) -> None:
        self._items: dict[str, bytes] = {}

    @staticmethod
    def _validate_ref(retrieval_ref: str) -> None:
        if not retrieval_ref.startswith("artifact://") or len(retrieval_ref) <= len("artifact://"):
            raise ValueError("uncontrolled artifact reference")

    def put(self, retrieval_ref: str, data: bytes) -> None:
        self._validate_ref(retrieval_ref)
        self._items[retrieval_ref] = bytes(data)

    def get(self, retrieval_ref: str) -> bytes:
        self._validate_ref(retrieval_ref)
        try:
            return self._items[retrieval_ref]
        except KeyError as exc:
            raise ArtifactVerificationError("artifact is missing") from exc


def verify_artifact(contract: ArtifactContract, store: ArtifactStore) -> bytes:
    expires = datetime.fromisoformat(contract.expires_at.replace("Z", "+00:00"))
    if expires <= datetime.now(timezone.utc):
        raise ArtifactVerificationError("artifact is expired")

    try:
        data = store.get(contract.retrieval_ref)
    except ArtifactVerificationError:
        raise
    except (KeyError, FileNotFoundError) as exc:
        raise ArtifactVerificationError("artifact is missing") from exc

    if len(data) != contract.size_bytes:
        raise ArtifactVerificationError("artifact size mismatch")
    digest = hashlib.sha256(data).hexdigest()
    if digest != contract.sha256:
        raise ArtifactVerificationError("artifact sha256 mismatch")
    return data
