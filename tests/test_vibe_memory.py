from tools.vibe_memory import InvestigationMemory, MemoryItem, MemoryStore, Provenance


SHA = "a" * 64


def test_roundtrip_preserves_provenance(tmp_path):
    store = MemoryStore(tmp_path)
    iid = store.investigation_id(SHA)
    memory = InvestigationMemory(iid, SHA)
    memory.add("claims", MemoryItem("C17", "claim", {"subject": "M81"}, "supported", Provenance("claim_evaluator", ("E1",))))
    store.save(memory)
    loaded = store.load(SHA, iid)
    assert loaded is not None
    assert loaded.claims[0].provenance.evidence_ids == ("E1",)


def test_recall_marks_prior_conclusions_for_revalidation(tmp_path):
    store = MemoryStore(tmp_path)
    iid = store.investigation_id(SHA)
    memory = InvestigationMemory(iid, SHA)
    memory.add("claims", MemoryItem("C17", "claim", "M81 handles request", "supported", Provenance("claim_evaluator", ("E1",))))
    store.save(memory)
    recalled = store.recall(SHA, iid)
    assert recalled is not None
    assert recalled.claims[0].status == "revalidation_required"


def test_unknowns_remain_unknown_on_recall(tmp_path):
    store = MemoryStore(tmp_path)
    iid = store.investigation_id(SHA)
    memory = InvestigationMemory(iid, SHA)
    memory.add("unknowns", MemoryItem("U1", "unknown", "runtime_not_observed", "unknown", Provenance("executor")))
    store.save(memory)
    recalled = store.recall(SHA, iid)
    assert recalled.unknowns[0].status == "unknown"


def test_artifacts_are_isolated_by_sha(tmp_path):
    store = MemoryStore(tmp_path)
    iid = store.investigation_id(SHA)
    store.save(InvestigationMemory(iid, SHA))
    other = "b" * 64
    assert store.load(other, iid) is None


def test_invalid_digest_is_rejected(tmp_path):
    store = MemoryStore(tmp_path)
    memory = InvestigationMemory("I-bad", "short")
    try:
        store.save(memory)
    except ValueError as exc:
        assert "full SHA-256" in str(exc)
    else:
        raise AssertionError("invalid digest accepted")


def test_add_replaces_same_item_id_instead_of_duplicating():
    memory = InvestigationMemory("I1", SHA)
    memory.add("claims", MemoryItem("C1", "claim", "old", "unknown", Provenance("a")))
    memory.add("claims", MemoryItem("C1", "claim", "new", "supported", Provenance("b", ("E2",))))
    assert len(memory.claims) == 1
    assert memory.claims[0].value == "new"
