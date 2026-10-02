import unittest

from tools.cloud import job_runner
from tools.vibebot.cloud_job import JobContract


class CloudJobRunnerTests(unittest.TestCase):
    def test_runner_accepts_canonical_string_operation(self):
        job = JobContract.create(
            operation="map",
            artifact_id="sha256:abc123",
            chat_id="12345",
        )

        result = job_runner.run(job)

        self.assertEqual(result.operation, "map")
        self.assertEqual(result.job_id, job.job_id)


if __name__ == "__main__":
    unittest.main()
