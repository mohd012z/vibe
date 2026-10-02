import json
import unittest

from tools.cloud.result_contract import ResultContract, ResultStatus


class ResultContractTests(unittest.TestCase):
    def test_completed_result_round_trips(self):
        result = ResultContract(
            job_id="VIBE-A8F21",
            status=ResultStatus.COMPLETED,
            operation="deepdive",
            summary="analysis complete",
            outputs=["summary.md", "evidence.json"],
        )
        restored = ResultContract.from_json(result.to_json())
        self.assertEqual(restored, result)

    def test_failed_result_requires_error(self):
        with self.assertRaises(ValueError):
            ResultContract(
                job_id="VIBE-A8F21",
                status=ResultStatus.FAILED,
                operation="deepdive",
            )

    def test_result_json_has_stable_schema_version(self):
        result = ResultContract(
            job_id="VIBE-A8F21",
            status=ResultStatus.COMPLETED,
            operation="map",
            summary="done",
        )
        payload = json.loads(result.to_json())
        self.assertEqual(payload["schema_version"], 1)


if __name__ == "__main__":
    unittest.main()
