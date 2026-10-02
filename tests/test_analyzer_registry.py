import unittest

from tools.cloud.analyzer_registry import AnalyzerRegistry, AnalyzerSpec, WorkloadProfile


class AnalyzerRegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = AnalyzerRegistry([
            AnalyzerSpec("strings", workload="light", local=True, github_assist=False, checkpoint=False),
            AnalyzerSpec("xref", workload="compute", local=True, github_assist=True, checkpoint=True),
            AnalyzerSpec("dex", workload="compute", local=True, github_assist=True, checkpoint=True),
            AnalyzerSpec("deepdive", workload="heavy", local=True, github_assist=True, checkpoint=True),
            AnalyzerSpec("native", workload="heavy", local=True, github_assist=True, checkpoint=True, tools=("native-analyzer",)),
            AnalyzerSpec("investigate", workload="heavy", local=True, github_assist=True, checkpoint=True),
        ])

    def test_lookup_returns_registered_capability(self):
        self.assertEqual(self.registry.get("deepdive").workload, "heavy")

    def test_unknown_capability_is_not_silently_invented(self):
        with self.assertRaises(KeyError):
            self.registry.get("magic")

    def test_duplicate_capability_is_rejected(self):
        with self.assertRaises(ValueError):
            AnalyzerRegistry([AnalyzerSpec("dex"), AnalyzerSpec("dex")])

    def test_heavy_local_capability_remains_local_capable(self):
        spec = self.registry.get("native")
        self.assertTrue(spec.local)
        self.assertTrue(spec.github_assist)

    def test_profile_small_cached_xref_can_be_local_compute(self):
        profile = self.registry.profile("xref", artifact_size_bytes=2_000_000, cached=True)
        self.assertEqual(profile, WorkloadProfile("compute", local_viable=True, github_assist_beneficial=False))

    def test_profile_large_xref_marks_github_assist_beneficial(self):
        profile = self.registry.profile("xref", artifact_size_bytes=250_000_000, cached=False)
        self.assertTrue(profile.local_viable)
        self.assertTrue(profile.github_assist_beneficial)

    def test_heavy_deepdive_is_local_viable_and_assistable(self):
        profile = self.registry.profile("deepdive", artifact_size_bytes=80_000_000, cached=False)
        self.assertEqual(profile.workload, "heavy")
        self.assertTrue(profile.local_viable)
        self.assertTrue(profile.github_assist_beneficial)

    def test_missing_required_local_tool_makes_local_not_viable(self):
        profile = self.registry.profile("native", artifact_size_bytes=5_000_000, available_tools=set())
        self.assertFalse(profile.local_viable)
        self.assertTrue(profile.github_assist_beneficial)

    def test_checkpoint_capability_exposed_for_resumable_heavy_work(self):
        self.assertTrue(self.registry.get("deepdive").checkpoint)
        self.assertTrue(self.registry.get("dex").checkpoint)

    def test_invalid_workload_class_is_rejected(self):
        with self.assertRaises(ValueError):
            AnalyzerSpec("bad", workload="gigantic")


if __name__ == "__main__":
    unittest.main()
