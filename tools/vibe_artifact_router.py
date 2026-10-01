"""Artifact-aware routing for Vibe read-only analysis.

Maps APK container members and resolved targets to analysis domains/providers.
This layer performs no mutation and does not grant write authorization.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import re
import zipfile


class Domain(str, Enum):
    MANIFEST = "manifest"
    RESOURCE = "resource"
    DEX = "dex"
    SMALI = "smali"
    NATIVE = "native"
    CONTAINER = "container"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ArtifactPart:
    path: str
    domain: Domain
    abi: str | None = None


@dataclass
class ArtifactMap:
    artifact: str
    parts: list[ArtifactPart] = field(default_factory=list)

    def domains(self) -> set[Domain]:
        return {p.domain for p in self.parts}

    def native_parts(self) -> list[ArtifactPart]:
        return [p for p in self.parts if p.domain is Domain.NATIVE]


@dataclass(frozen=True)
class TargetHint:
    raw: str
    domain: Domain
    canonical: str
    confidence: float
    reason: str


class ApkArtifactRouter:
    """Inventory an APK and infer analysis domains without executing its code."""

    _SO = re.compile(r"^lib/([^/]+)/(.+\.so)$")

    def inspect(self, apk: str | Path) -> ArtifactMap:
        apk = Path(apk)
        if not apk.is_file() or not zipfile.is_zipfile(apk):
            raise ValueError(f"not an APK/ZIP: {apk}")
        result = ArtifactMap(str(apk))
        with zipfile.ZipFile(apk) as z:
            for name in sorted(z.namelist()):
                if name == "AndroidManifest.xml":
                    result.parts.append(ArtifactPart(name, Domain.MANIFEST))
                elif name == "resources.arsc" or name.startswith("res/") or name.startswith("assets/"):
                    result.parts.append(ArtifactPart(name, Domain.RESOURCE))
                elif re.fullmatch(r"classes(?:\d+)?\.dex", name):
                    result.parts.append(ArtifactPart(name, Domain.DEX))
                else:
                    native = self._SO.match(name)
                    if native:
                        result.parts.append(ArtifactPart(name, Domain.NATIVE, native.group(1)))
        result.parts.append(ArtifactPart("<apk-container>", Domain.CONTAINER))
        return result

    def provider_order(self, capability: str, domain: Domain) -> tuple[str, ...]:
        table = {
            Domain.MANIFEST: ("apktool", "androguard"),
            Domain.RESOURCE: ("apktool", "androguard"),
            Domain.DEX: ("jadx", "androguard", "apktool"),
            Domain.SMALI: ("apktool",),
            Domain.NATIVE: ("radare2", "ghidra"),
            Domain.CONTAINER: ("androguard", "apktool", "jadx"),
        }
        order = table.get(domain, ())
        if capability in {"REFERENCE_IN", "REFERENCE_OUT"} and domain is Domain.NATIVE:
            return ("radare2", "ghidra")
        return order


class TargetResolver:
    """Classify user targets before choosing an analysis engine.

    Classification is intentionally conservative: ambiguous names stay UNKNOWN
    rather than being silently forced into Java or native analysis.
    """

    _ADDRESS = re.compile(r"^0x[0-9a-fA-F]+$")
    _JAVA = re.compile(r"^(?:[A-Za-z_$][\w$]*\.)+[A-Za-z_$][\w$]*(?:[#.]?[A-Za-z_$][\w$]*)?$", re.ASCII)
    _SMALI = re.compile(r"^L[^;]+;->[A-Za-z_$<>][\w$<>]*", re.ASCII)
    _JNI = re.compile(r"^Java_[A-Za-z0-9_]+$")

    def resolve(self, raw: str) -> TargetHint:
        target = raw.strip()
        if self._ADDRESS.fullmatch(target):
            return TargetHint(raw, Domain.NATIVE, target.lower(), 1.0, "native address")
        if self._JNI.fullmatch(target):
            return TargetHint(raw, Domain.NATIVE, target, 0.98, "JNI export-style symbol")
        if self._SMALI.match(target):
            return TargetHint(raw, Domain.SMALI, target, 1.0, "smali method descriptor")
        if target.endswith(".so") or target.startswith("lib/"):
            return TargetHint(raw, Domain.NATIVE, target, 0.95, "native library path/name")
        if self._JAVA.fullmatch(target):
            return TargetHint(raw, Domain.DEX, target, 0.85, "Java/Kotlin-style qualified name")
        return TargetHint(raw, Domain.UNKNOWN, target, 0.0, "ambiguous target; evidence required")


def validate_radare_target(target: str) -> str:
    """Accept only address or conservative symbol syntax for r2 seek commands."""
    value = target.strip()
    if re.fullmatch(r"0x[0-9a-fA-F]+", value):
        return value.lower()
    if re.fullmatch(r"[A-Za-z_.$][A-Za-z0-9_.$:@-]{0,255}", value):
        return value
    raise ValueError("unsafe or ambiguous radare target")
