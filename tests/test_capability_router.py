import unittest

from tools.cloud.capability_router import CapabilityRouter, RouteDecision


class CapabilityRouterTests(unittest.TestCase):
    def setUp(self):
        self.router = CapabilityRouter(
            local_operations={"sha256", "file_info", "strings"},
            heavy_operations={"analyze", "deepdive", "xref", "dex", "native"},
        )

    def test_auto_prefers_equivalent_local_capability(self):
        decision = self.router.route("sha256", "auto", True, True)
        self.assertEqual(decision, RouteDecision("local", "local_capability_available"))

    def test_heavy_operation_runs_local_when_capable(self):
        decision = self.router.route("deepdive", "auto", True, True, local_heavy_available=True)
        self.assertEqual(decision, RouteDecision("local", "local_heavy_capability_available"))

    def test_heavy_operation_can_run_local_with_github_assist(self):
        decision = self.router.route(
            "deepdive", "auto", True, True,
            local_heavy_available=True, github_assist_beneficial=True,
        )
        self.assertEqual(decision, RouteDecision("local+github", "github_assist_beneficial"))

    def test_offline_heavy_continues_locally_when_capable(self):
        decision = self.router.route(
            "deepdive", "auto", False, True,
            local_heavy_available=True, github_assist_beneficial=True,
        )
        self.assertEqual(decision, RouteDecision("local", "github_assist_network_unavailable"))

    def test_budget_exhaustion_does_not_block_capable_local_heavy(self):
        decision = self.router.route(
            "xref", "auto", True, False,
            local_heavy_available=True, github_assist_beneficial=True,
        )
        self.assertEqual(decision, RouteDecision("local", "github_assist_budget_exhausted"))

    def test_heavy_falls_back_to_github_when_local_unavailable(self):
        decision = self.router.route("native", "auto", True, True, local_heavy_available=False)
        self.assertEqual(decision, RouteDecision("github", "local_capability_unavailable"))

    def test_no_local_and_no_network_is_held(self):
        decision = self.router.route("native", "auto", False, True, local_heavy_available=False)
        self.assertEqual(decision, RouteDecision("held", "network_unavailable"))

    def test_no_local_and_no_free_budget_is_held(self):
        decision = self.router.route("native", "auto", True, False, local_heavy_available=False)
        self.assertEqual(decision, RouteDecision("held", "cloud_budget_exhausted"))

    def test_explicit_local_allows_heavy_when_capable(self):
        decision = self.router.route("native", "local", True, True, local_heavy_available=True)
        self.assertEqual(decision, RouteDecision("local", "local_heavy_capability_available"))

    def test_explicit_local_holds_when_capability_unavailable(self):
        decision = self.router.route("native", "local", True, True, local_heavy_available=False)
        self.assertEqual(decision, RouteDecision("held", "local_capability_unavailable"))

    def test_explicit_github_respects_budget_guard(self):
        decision = self.router.route("analyze", "github", True, False, local_heavy_available=True)
        self.assertEqual(decision, RouteDecision("held", "cloud_budget_exhausted"))

    def test_unknown_operation_is_rejected(self):
        decision = self.router.route("shell", "auto", True, True)
        self.assertEqual(decision, RouteDecision("rejected", "unknown_operation"))

    def test_unknown_mode_is_rejected(self):
        decision = self.router.route("sha256", "magic", True, True)
        self.assertEqual(decision, RouteDecision("rejected", "unknown_mode"))


if __name__ == "__main__":
    unittest.main()
