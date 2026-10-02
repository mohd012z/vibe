import unittest

from tools.cloud.analyzer_registry import AnalyzerRegistry, AnalyzerSpec
from tools.cloud.capability_router import CapabilityRouter
from tools.cloud.analysis_execution_planner import AnalysisExecutionPlanner


class AnalysisExecutionPlannerTests(unittest.TestCase):
    def setUp(self):
        registry = AnalyzerRegistry([
            AnalyzerSpec("strings", workload="light", local=True),
            AnalyzerSpec("xref", workload="compute", local=True, github_assist=True, checkpoint=True),
            AnalyzerSpec("dex", workload="compute", local=True, github_assist=True, checkpoint=True),
            AnalyzerSpec("deepdive", workload="heavy", local=True, github_assist=True, checkpoint=True),
            AnalyzerSpec("native", workload="heavy", local=True, github_assist=True, checkpoint=True, tools=("native-analyzer",)),
            AnalyzerSpec("investigate", workload="heavy", local=True, github_assist=True, checkpoint=True),
        ])
        router = CapabilityRouter(
            local_operations={"strings"},
            heavy_operations={"xref", "dex", "deepdive", "native", "investigate"},
        )
        self.planner = AnalysisExecutionPlanner(registry, router)

    def test_light_analysis_plans_local(self):
        plan = self.planner.plan("strings", artifact_size_bytes=1_000, available_tools=set())
        self.assertEqual(plan.route, "local")
        self.assertEqual(plan.workload, "light")
        self.assertFalse(plan.checkpoint)

    def test_heavy_analysis_plans_local_plus_github_when_assist_beneficial(self):
        plan = self.planner.plan("deepdive", artifact_size_bytes=80_000_000, available_tools=set())
        self.assertEqual(plan.route, "local+github")
        self.assertEqual(plan.workload, "heavy")
        self.assertTrue(plan.checkpoint)

    def test_heavy_analysis_continues_local_when_offline(self):
        plan = self.planner.plan(
            "deepdive", artifact_size_bytes=80_000_000, available_tools=set(), network_available=False
        )
        self.assertEqual(plan.route, "local")
        self.assertEqual(plan.reason, "github_assist_network_unavailable")

    def test_heavy_analysis_continues_local_when_free_budget_exhausted(self):
        plan = self.planner.plan(
            "deepdive", artifact_size_bytes=80_000_000, available_tools=set(), cloud_budget_available=False
        )
        self.assertEqual(plan.route, "local")
        self.assertEqual(plan.reason, "github_assist_budget_exhausted")

    def test_missing_native_tool_falls_back_to_github(self):
        plan = self.planner.plan("native", artifact_size_bytes=5_000_000, available_tools=set())
        self.assertEqual(plan.route, "github")
        self.assertFalse(plan.local_viable)

    def test_missing_native_tool_and_offline_holds(self):
        plan = self.planner.plan(
            "native", artifact_size_bytes=5_000_000, available_tools=set(), network_available=False
        )
        self.assertEqual(plan.route, "held")

    def test_cached_small_xref_stays_local(self):
        plan = self.planner.plan("xref", artifact_size_bytes=2_000_000, cached=True, available_tools=set())
        self.assertEqual(plan.route, "local")
        self.assertFalse(plan.github_assist_beneficial)

    def test_large_uncached_xref_can_use_github_assist(self):
        plan = self.planner.plan("xref", artifact_size_bytes=250_000_000, cached=False, available_tools=set())
        self.assertEqual(plan.route, "local+github")
        self.assertTrue(plan.github_assist_beneficial)

    def test_unknown_analyzer_is_rejected_by_registry(self):
        with self.assertRaises(KeyError):
            self.planner.plan("magic", artifact_size_bytes=1)


if __name__ == "__main__":
    unittest.main()
