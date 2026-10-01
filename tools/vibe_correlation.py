"""Cross-domain correlation for Vibe read-only APK investigations.

Builds explicit Java/Smali/JNI/native relationships from observations. It does
not infer a link merely because names look similar: inferred candidates remain
unverified until supported by evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from tools.vibe_evidence import EvidenceRecord


class LinkStatus(str, Enum):
    VERIFIED = "verified"
    CANDIDATE = "candidate"
    CONFLICTED = "conflicted"


@dataclass(frozen=True)
class CorrelationNode:
    node_id: str
    domain: str
    value: str


@dataclass
class CorrelationLink:
    source: str
    target: str
    relation: str
    status: LinkStatus
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class CorrelatedEvidenceGraph:
    nodes: dict[str, CorrelationNode] = field(default_factory=dict)
    links: list[CorrelationLink] = field(default_factory=list)

    def add_node(self, node: CorrelationNode) -> None:
        self.nodes[node.node_id] = node

    def add_link(self, link: CorrelationLink) -> None:
        for current in self.links:
            if (current.source, current.target, current.relation) == (link.source, link.target, link.relation):
                current.evidence_ids = sorted(set(current.evidence_ids + link.evidence_ids))
                if current.status != link.status:
                    current.status = LinkStatus.CONFLICTED
                return
        self.links.append(link)


class JniCorrelationBuilder:
    """Normalize explicit JNI bridge observations into one graph.

    Recognized evidence kinds:
      java_native_method: {java, jni?}
      jni_export: {jni, library?, address?}
      register_natives: {java, native, library?, address?}
      native_symbol: {symbol, library?, address?}
    """

    def build(self, records: Iterable[EvidenceRecord]) -> CorrelatedEvidenceGraph:
        graph = CorrelatedEvidenceGraph()
        by_jni: dict[str, list[tuple[CorrelationNode, EvidenceRecord]]] = {}
        by_native: dict[str, list[tuple[CorrelationNode, EvidenceRecord]]] = {}

        for record in records:
            value = record.value if isinstance(record.value, dict) else {}
            if record.kind == "java_native_method" and value.get("java"):
                java = self._node("dex", value["java"])
                graph.add_node(java)
                jni = value.get("jni")
                if jni:
                    by_jni.setdefault(jni, []).append((java, record))
            elif record.kind == "jni_export" and value.get("jni"):
                native = self._node("native", self._native_value(value))
                graph.add_node(native)
                by_jni.setdefault(value["jni"], []).append((native, record))
            elif record.kind == "register_natives" and value.get("java") and value.get("native"):
                java = self._node("dex", value["java"])
                native = self._node("native", self._native_value(value, value["native"]))
                graph.add_node(java); graph.add_node(native)
                graph.add_link(CorrelationLink(java.node_id, native.node_id, "JNI_REGISTERED_TO", LinkStatus.VERIFIED, [record.evidence_id]))
            elif record.kind == "native_symbol" and value.get("symbol"):
                native = self._node("native", self._native_value(value, value["symbol"]))
                graph.add_node(native)
                by_native.setdefault(value["symbol"], []).append((native, record))

        for jni, matches in by_jni.items():
            java_matches = [(n, r) for n, r in matches if n.domain == "dex"]
            native_matches = [(n, r) for n, r in matches if n.domain == "native"]
            for java, jr in java_matches:
                for native, nr in native_matches:
                    graph.add_link(CorrelationLink(java.node_id, native.node_id, "JNI_EXPORT_TO", LinkStatus.VERIFIED, [jr.evidence_id, nr.evidence_id]))

        return graph

    @staticmethod
    def _node(domain: str, value: str) -> CorrelationNode:
        return CorrelationNode(f"{domain}:{value}", domain, value)

    @staticmethod
    def _native_value(value: dict, symbol: str | None = None) -> str:
        lib = value.get("library") or "<unknown-lib>"
        name = symbol or value.get("jni") or "<unknown-symbol>"
        address = value.get("address")
        return f"{lib}!{name}" + (f"@{address}" if address is not None else "")
