import unittest

from tools.cloud.capability_router import CapabilityRouter, RouteDecision


class CapabilityRouterTests(unittest.TestCase):
    def setUp(self):
        self.router = CapabilityRouter(
            local_operations={"sha256", "file_info", "strings"},
            cloud_operations={"analyze", "deepdive", "xref", "dex", "native"},
        )

    def test_auto_prefers_equivalent_local_capability(self):
        decision = self.router.route(
            operation="sha256", requested_mode="auto", network_available=True,
            cloud_budget_available=True,
        )
        self.assertEqual(decision, RouteDecision("local", "local_capability_available"))

    def test_auto_routes_heavy_operation_to_cloud(self):
        decision = self.router.route(
            operation="deepdive", requested_mode="auto", network_available=True,
            cloud_budget_available=True,
        )
        self.assertEqual(decision, RouteDecision("cloud", "cloud_capability_required"))

    def test_offline_cloud_operation_is_held_not_downgraded(self):
        decision = self.router.route(
            operation="deepdive", requested_mode="auto", network_available=False,
            cloud_budget_available=True,
        )
        self.assertEqual(decision.route, "held")
        self.assertEqual(decision.reason, "network_unavailable")

    def test_exhausted_free_budget_holds_cloud_job(self):
        decision = self.router.route(
            operation="xref", requested_mode="auto", network_available=True,
            cloud_budget_available=False,
        )
        self.assertEqual(decision, RouteDecision("held", "cloud_budget_exhausted"))

    def test_explicit_local_rejects_unsupported_heavy_operation(self):
        decision = self.router.route(
            operation="native", requested_mode="local", network_available=True,
            cloud_budget_available=True,
        )
        self.assertEqual(decision, RouteDecision("held", "local_capability_unavailable"))

    def test_explicit_cloud_respects_budget_guard(self):
        decision = self.router.route(
            operation="analyze", requested_mode="cloud", network_available=True,
            cloud_budget_available=False,
        )
        self.assertEqual(decision, RouteDecision("held", "cloud_budget_exhausted"))

    def test_unknown_operation_is_rejected(self):
        decision = self.router.route(
            operation="shell", requested_mode="auto", network_available=True,
            cloud_budget_available=True,
        )
        self.assertEqual(decision, RouteDecision("rejected", "unknown_operation"))

    def test_unknown_mode_is_rejected(self):
        decision = self.router.route(
            operation="sha256", requested_mode="magic", network_available=True,
            cloud_budget_available=True,
        )
        self.assertEqual(decision, RouteDecision("rejected", "unknown_mode"))


if __name__ == "__main__":
    unittest.main()
