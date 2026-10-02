import json
import unittest

from tools.vibebot.cloud_job import JobContract, JobValidationError


class CloudJobContractTests(unittest.TestCase):
    def test_accepts_allowlisted_operation_and_artifact(self):
        job = JobContract.create(
            operation="deepdive",
            artifact_id="sha256:abc123",
            chat_id="12345",
            parameters={"target": "urls"},
        )
        self.assertEqual(job.operation, "deepdive")
        self.assertEqual(job.artifact_id, "sha256:abc123")
        self.assertTrue(job.job_id.startswith("VIBE-"))
        self.assertEqual(job.schema_version, 1)

    def test_rejects_arbitrary_shell_operation(self):
        with self.assertRaises(JobValidationError):
            JobContract.create(
                operation="rm -rf /",
                artifact_id="sha256:abc123",
                chat_id="12345",
            )

    def test_rejects_missing_artifact_for_analysis(self):
        with self.assertRaises(JobValidationError):
            JobContract.create(operation="dex", artifact_id="", chat_id="12345")

    def test_json_round_trip_preserves_contract(self):
        original = JobContract.create(
            operation="xref",
            artifact_id="sha256:def456",
            chat_id="777",
            parameters={"symbol": "Example.method"},
        )
        restored = JobContract.from_json(original.to_json())
        self.assertEqual(restored.to_dict(), original.to_dict())
        json.loads(original.to_json())


if __name__ == "__main__":
    unittest.main()
