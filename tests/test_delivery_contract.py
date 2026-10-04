import unittest

from tools.cloud.delivery_contract import DeliveryContract, DeliveryOutput


class DeliveryContractTests(unittest.TestCase):
    def test_round_trip(self):
        contract = DeliveryContract(
            job_id="VIBE-001",
            destination_client="telegram",
            destination_id="chat-123",
            status="completed",
            summary="analysis complete",
            outputs=[DeliveryOutput(name="report.json", artifact_ref="artifact://out-001")],
        )
        self.assertEqual(DeliveryContract.from_json(contract.to_json()), contract)

    def test_rejects_uncontrolled_output_path(self):
        with self.assertRaises(ValueError):
            DeliveryOutput(name="report.json", artifact_ref="/tmp/report.json")

    def test_rejects_unknown_destination_client(self):
        with self.assertRaises(ValueError):
            DeliveryContract(
                job_id="VIBE-001",
                destination_client="shell",
                destination_id="x",
                status="completed",
                summary="done",
            )

    def test_rejects_empty_destination(self):
        with self.assertRaises(ValueError):
            DeliveryContract(
                job_id="VIBE-001",
                destination_client="android",
                destination_id="",
                status="completed",
                summary="done",
            )

    def test_rejects_success_without_summary_or_output(self):
        with self.assertRaises(ValueError):
            DeliveryContract(
                job_id="VIBE-001",
                destination_client="telegram",
                destination_id="chat-123",
                status="completed",
            )

    def test_failed_delivery_requires_summary(self):
        with self.assertRaises(ValueError):
            DeliveryContract(
                job_id="VIBE-001",
                destination_client="telegram",
                destination_id="chat-123",
                status="failed",
            )


if __name__ == "__main__":
    unittest.main()
