from tools.vibe_correlation import JniCorrelationBuilder, LinkStatus
from tools.vibe_evidence import EvidenceRecord


def ev(eid, kind, value, provider="test"):
    return EvidenceRecord(eid, "ARTIFACT_INDEX", provider, None, kind, value, None)


def test_explicit_java_and_jni_export_are_correlated():
    rows = [
        ev("E1", "java_native_method", {"java": "com.demo.Main.verify", "jni": "Java_com_demo_Main_verify"}, "jadx"),
        ev("E2", "jni_export", {"jni": "Java_com_demo_Main_verify", "library": "libdemo.so", "address": "0x1000"}, "radare2"),
    ]
    graph = JniCorrelationBuilder().build(rows)
    assert len(graph.links) == 1
    link = graph.links[0]
    assert link.relation == "JNI_EXPORT_TO"
    assert link.status is LinkStatus.VERIFIED
    assert set(link.evidence_ids) == {"E1", "E2"}


def test_register_natives_is_direct_verified_link():
    graph = JniCorrelationBuilder().build([
        ev("E3", "register_natives", {"java": "com.demo.Main.verify", "native": "verifyNative", "library": "libdemo.so", "address": "0x2200"}, "radare2")
    ])
    assert graph.links[0].relation == "JNI_REGISTERED_TO"
    assert graph.links[0].status is LinkStatus.VERIFIED
    assert graph.links[0].evidence_ids == ["E3"]


def test_name_similarity_alone_does_not_create_link():
    graph = JniCorrelationBuilder().build([
        ev("E1", "text_match", {"file": "Main.java", "snippet": "verify"}, "jadx"),
        ev("E2", "native_symbol", {"symbol": "verify", "library": "libdemo.so"}, "radare2"),
    ])
    assert graph.links == []


def test_unmatched_java_native_method_stays_unlinked():
    graph = JniCorrelationBuilder().build([
        ev("E1", "java_native_method", {"java": "com.demo.Main.verify", "jni": "Java_com_demo_Main_verify"}, "jadx")
    ])
    assert "dex:com.demo.Main.verify" in graph.nodes
    assert graph.links == []


def test_duplicate_link_merges_provenance():
    rows = [
        ev("E1", "register_natives", {"java": "com.demo.Main.verify", "native": "verifyNative", "library": "libdemo.so"}),
        ev("E2", "register_natives", {"java": "com.demo.Main.verify", "native": "verifyNative", "library": "libdemo.so"}),
    ]
    graph = JniCorrelationBuilder().build(rows)
    assert len(graph.links) == 1
    assert graph.links[0].evidence_ids == ["E1", "E2"]
