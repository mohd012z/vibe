from tools.vibe_capabilities import CapabilityRegistry
from tools.vibe_runtime import RuntimeEvent, RuntimeEvidenceProvider, StaticRuntimeBackend


def test_runtime_event_normalizes_to_vibe_observation():
    backend = StaticRuntimeBackend({
        ("RUNTIME_MODULES", None): [RuntimeEvent("module_loaded", {"name": "libdemo.so", "base": "0x1000"}, "session:S1")]
    })
    provider = RuntimeEvidenceProvider(backend)
    rows = provider.observe("RUNTIME_MODULES", None)
    assert len(rows) == 1
    assert rows[0].provider == "runtime-replay"
    assert rows[0].kind == "module_loaded"
    assert rows[0].value["name"] == "libdemo.so"


def test_runtime_provider_refuses_unknown_capability():
    backend = StaticRuntimeBackend({("PATCH_COMMIT", "M81"): [RuntimeEvent("x", "y")]})
    provider = RuntimeEvidenceProvider(backend)
    assert not provider.supports("PATCH_COMMIT")
    assert provider.observe("PATCH_COMMIT", "M81") == []


def test_runtime_trace_preserves_target_and_source():
    backend = StaticRuntimeBackend({
        ("RUNTIME_TRACE", "libdemo.so!verify"): [RuntimeEvent("function_observed", {"address": "0x2200"}, "session:S2")]
    })
    row = RuntimeEvidenceProvider(backend).observe("RUNTIME_TRACE", "libdemo.so!verify")[0]
    assert row.target == "libdemo.so!verify"
    assert row.source == "session:S2"


def test_runtime_capabilities_are_read_only_and_registered():
    registry = CapabilityRegistry()
    for cid in (
        "RUNTIME_MODULES", "RUNTIME_SYMBOL_LOOKUP", "RUNTIME_TRACE",
        "RUNTIME_BACKTRACE", "RUNTIME_MEMORY_MAP", "RUNTIME_THREAD_MAP",
    ):
        cap = registry.get(cid)
        assert cap is not None
        assert cap.access.value == "read"


def test_runtime_trace_requires_target():
    registry = CapabilityRegistry()
    assert registry.get("RUNTIME_TRACE").requires_target
    assert registry.get("RUNTIME_BACKTRACE").requires_target
