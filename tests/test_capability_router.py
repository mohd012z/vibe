import unittest

from tools.cloud.capability_router import CapabilityRouter, RouteDecision


class CapabilityRouterTests(unittest.TestCase):
    def setUp(self):
        self.router = CapabilityRouter(
            local_operations={"sha256", "file_info", "strings"},
            heavy_operations={"analyze", "deepdive", "xref", "dex", "native"},
        )

    def test_auto_prefers_equivalent_local_capability(self):
        decision = self.router.route(
            operation="sha256", requested_mode="auto", network_available=True,
            cloud_budget_available=True,
        )
        self.assertEqual(decision, RouteDecision("local", "local_capability_available"))

    def test_heavy_operation_runs_local_when_local_heavy_capability_available(self):
        decision = self.router.route(
            operation="deepdive", requested_mode="auto", network_available=True,
            cloud_budget_available=True, local_heavy_available=True,
        )
        self.assertEqual(decision, RouteDecision("local", "local_heavy_capability_available"))

    def test_heavy_operation_falls_back_to_cloud_when_local_heavy_unavailable(self):
        decision = self.router.route(
            operation="deepdive", requested_mode="auto", network_available=True,
            cloud_budget_available=True, local_heavy_available=False,
        )
        self.assertEqual(decision, RouteDecision("cloud", "cloud_fallback_required"))

    def test_offline_heavy_operation_runs_local_when_capable(self):
        decision = self.router.route(
            operation="deepdive", requested_mode="auto", network_available=False,
            cloud_budget_available=False, local_heavy_available=True,
        )
        self.assertEqual(decision, RouteDecision("local", "local_heavy_capability_available"))

    def test_offline_heavy_operation_is_held_when_local_unavailable(self):
        decision = self.router.route(
            operation="deepdive", requested_mode="auto", network_available=False,
            cloud_budget_available=True, local_heavy_available=False,
        )
        self.assertEqual(decision, RouteDecision("held", "network_unavailable"))

    def test_exhausted_free_budget_holds_only_when_local_heavy_unavailable(self):
        decision = self.router.route(
            operation="xref", requested_mode="auto", network_available=True,
            cloud_budget_available=False, local_heavy_available=False,
        )
        self.assertEqual(decision, RouteDecision("held", "cloud_budget_exhausted"))

    def test_explicit_local_allows_heavy_when_capable(self):
        decision = self.router.route(
            operation="native", requested_mode="local", network_available=True,
            cloud_budget_available=True, local_heavy_available=True,
        )
        self.assertEqual(decision, RouteDecision("local", "local_heavy_capability_available"))

    def test_explicit_local_holds_heavy_when_capability_unavailable(self):
        decision = self.router.route(
            operation="native", requested_mode="local", network_available=True,
            cloud_budget_available=True, local_heavy_available=False,
        )
        self.assertEqual(decision, RouteDecision("held", "local_capability_unavailable"))

    def test_explicit_cloud_respects_budget_guard(self):
        decision = self.router.route(
            operation="analyze", requested_mode="cloud", network_available=True,
            cloud_budget_available=False, local_heavy_available=True,
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
