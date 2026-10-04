import hashlib
import unittest
from datetime import datetime, timedelta, timezone

from tools.cloud.artifact_contract import ArtifactContract, ArtifactVerificationError
from tools.cloud.artifact_store import MemoryArtifactStore, verify_artifact


class ArtifactContractTests(unittest.TestCase):
    def make_contract(self, data=b"hello", **overrides):
        values = dict(
            artifact_id="art-001",
            filename="sample.apk",
            size_bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            artifact_type="apk",
            retrieval_ref="artifact://art-001",
            source_client="telegram",
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
        )
        values.update(overrides)
        return ArtifactContract(**values)

    def test_round_trip(self):
        contract = self.make_contract()
        self.assertEqual(ArtifactContract.from_json(contract.to_json()), contract)

    def test_rejects_bad_sha256_shape(self):
        with self.assertRaises(ValueError):
            self.make_contract(sha256="bad")

    def test_verified_bytes_are_returned(self):
        data = b"hello"
        contract = self.make_contract(data)
        store = MemoryArtifactStore()
        store.put(contract.retrieval_ref, data)
        self.assertEqual(verify_artifact(contract, store), data)

    def test_tampered_bytes_are_rejected(self):
        contract = self.make_contract(b"hello")
        store = MemoryArtifactStore()
        store.put(contract.retrieval_ref, b"tampered")
        with self.assertRaises(ArtifactVerificationError):
            verify_artifact(contract, store)

    def test_wrong_size_is_rejected(self):
        data = b"hello"
        contract = self.make_contract(data, size_bytes=len(data) + 1)
        store = MemoryArtifactStore()
        store.put(contract.retrieval_ref, data)
        with self.assertRaises(ArtifactVerificationError):
            verify_artifact(contract, store)

    def test_expired_artifact_is_rejected(self):
        data = b"hello"
        contract = self.make_contract(
            data,
            expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
        )
        store = MemoryArtifactStore()
        store.put(contract.retrieval_ref, data)
        with self.assertRaises(ArtifactVerificationError):
            verify_artifact(contract, store)

    def test_uncontrolled_reference_is_rejected(self):
        with self.assertRaises(ValueError):
            self.make_contract(retrieval_ref="/tmp/user.apk")

    def test_missing_artifact_is_rejected(self):
        contract = self.make_contract()
        with self.assertRaises(ArtifactVerificationError):
            verify_artifact(contract, MemoryArtifactStore())


if __name__ == "__main__":
    unittest.main()
