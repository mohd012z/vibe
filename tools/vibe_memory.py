"""Persistent, provenance-aware investigation memory for Vibe.

Memory is scoped to an artifact digest. Recalled conclusions are never promoted
back to current truth automatically: callers must revalidate them against the
current artifact/evidence before use.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Provenance:
    source: str
    evidence_ids: tuple[str, ...] = ()
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class MemoryItem:
    item_id: str
    kind: str
    value: Any
    status: str
    provenance: Provenance


@dataclass
class InvestigationMemory:
    investigation_id: str
    artifact_sha256: str
    targets: list[MemoryItem] = field(default_factory=list)
    claims: list[MemoryItem] = field(default_factory=list)
    unknowns: list[MemoryItem] = field(default_factory=list)
    conflicts: list[MemoryItem] = field(default_factory=list)
    decisions: list[MemoryItem] = field(default_factory=list)
    changesets: list[MemoryItem] = field(default_factory=list)

    def add(self, collection: str, item: MemoryItem) -> None:
        bucket = getattr(self, collection)
        if not isinstance(bucket, list):
            raise ValueError(f"invalid memory collection: {collection}")
        for index, existing in enumerate(bucket):
            if existing.item_id == item.item_id:
                bucket[index] = item
                return
        bucket.append(item)


class MemoryStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    @staticmethod
    def investigation_id(artifact_sha256: str, label: str = "default") -> str:
        raw = f"{artifact_sha256}:{label}".encode("utf-8")
        return "I-" + sha256(raw).hexdigest()[:16]

    def _path(self, artifact_sha256: str, investigation_id: str) -> Path:
        return self.root / artifact_sha256 / f"{investigation_id}.json"

    def save(self, memory: InvestigationMemory) -> Path:
        if len(memory.artifact_sha256) != 64:
            raise ValueError("artifact_sha256 must be a full SHA-256 digest")
        path = self._path(memory.artifact_sha256, memory.investigation_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = asdict(memory)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(path)
        return path

    def load(self, artifact_sha256: str, investigation_id: str) -> InvestigationMemory | None:
        path = self._path(artifact_sha256, investigation_id)
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("artifact_sha256") != artifact_sha256:
            raise ValueError("memory artifact digest mismatch")
        return self._decode(data)

    def recall(self, artifact_sha256: str, investigation_id: str) -> InvestigationMemory | None:
        """Recall as stale-by-default so evidence must be revalidated."""
        memory = self.load(artifact_sha256, investigation_id)
        if memory is None:
            return None
        for collection in ("targets", "claims", "decisions", "changesets"):
            for item in getattr(memory, collection):
                if item.status in {"supported", "validated", "applied"}:
                    item.status = "revalidation_required"
        return memory

    @staticmethod
    def _decode(data: dict[str, Any]) -> InvestigationMemory:
        def items(name: str) -> list[MemoryItem]:
            out = []
            for raw in data.get(name, []):
                p = raw["provenance"]
                out.append(MemoryItem(raw["item_id"], raw["kind"], raw["value"], raw["status"], Provenance(p["source"], tuple(p.get("evidence_ids", [])), p["created_at"])))
            return out
        return InvestigationMemory(
            investigation_id=data["investigation_id"],
            artifact_sha256=data["artifact_sha256"],
            targets=items("targets"), claims=items("claims"), unknowns=items("unknowns"),
            conflicts=items("conflicts"), decisions=items("decisions"), changesets=items("changesets"),
        )
