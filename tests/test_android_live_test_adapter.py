import unittest

from tools.runtime.android_live_adapter import (
    AndroidLiveCapabilities,
    AndroidLiveTestAdapter,
    InstalledApp,
)


class AndroidLiveTestAdapterTests(unittest.TestCase):
    def setUp(self):
        self.apps = [
            InstalledApp("com.example.alpha", "Alpha", launchable=True),
            InstalledApp("com.example.beta", "Beta", launchable=False),
        ]

    def test_lists_only_adapter_visible_installed_apps(self):
        adapter = AndroidLiveTestAdapter(installed_apps=self.apps)
        self.assertEqual([a.package_name for a in adapter.list_installed_apps()], [
            "com.example.alpha", "com.example.beta"
        ])

    def test_select_requires_known_installed_app(self):
        adapter = AndroidLiveTestAdapter(installed_apps=self.apps)
        with self.assertRaises(KeyError):
            adapter.select_target("com.unknown.app", authorized=True)

    def test_select_requires_explicit_authorization(self):
        adapter = AndroidLiveTestAdapter(installed_apps=self.apps)
        with self.assertRaises(PermissionError):
            adapter.select_target("com.example.alpha", authorized=False)

    def test_start_creates_live_session_for_authorized_target(self):
        adapter = AndroidLiveTestAdapter(installed_apps=self.apps)
        adapter.select_target("com.example.alpha", authorized=True)
        session = adapter.start_live_test(timestamp_ms=100)
        self.assertEqual(session.package_name, "com.example.alpha")
        self.assertEqual(session.state, "running")

    def test_non_launchable_target_can_attach_if_already_running(self):
        adapter = AndroidLiveTestAdapter(installed_apps=self.apps, running_packages={"com.example.beta"})
        adapter.select_target("com.example.beta", authorized=True)
        session = adapter.start_live_test(timestamp_ms=100)
        self.assertEqual(session.state, "running")

    def test_non_launchable_non_running_target_is_rejected(self):
        adapter = AndroidLiveTestAdapter(installed_apps=self.apps)
        adapter.select_target("com.example.beta", authorized=True)
        with self.assertRaises(RuntimeError):
            adapter.start_live_test(timestamp_ms=100)

    def test_capability_detection_never_claims_private_process_access(self):
        caps = AndroidLiveCapabilities(
            process_status=True,
            observable_metrics=True,
            debug_logs=True,
            private_process_memory=False,
        )
        adapter = AndroidLiveTestAdapter(installed_apps=self.apps, capabilities=caps)
        detected = adapter.detect_capabilities()
        self.assertFalse(detected.private_process_memory)

    def test_floating_controls_are_small_explicit_actions(self):
        adapter = AndroidLiveTestAdapter(installed_apps=self.apps)
        self.assertEqual(adapter.floating_controls(), ("mark_issue", "snapshot", "pause_resume", "stop"))

    def test_mark_issue_flows_into_live_timeline(self):
        adapter = AndroidLiveTestAdapter(installed_apps=self.apps)
        adapter.select_target("com.example.alpha", authorized=True)
        adapter.start_live_test(timestamp_ms=100)
        event = adapter.mark_issue("screen froze", timestamp_ms=110)
        self.assertEqual(event.kind, "issue")
        self.assertEqual(adapter.session.timeline[-1].summary, "screen froze")

    def test_snapshot_filters_to_supported_observable_metrics(self):
        caps = AndroidLiveCapabilities(process_status=True, observable_metrics=True)
        adapter = AndroidLiveTestAdapter(installed_apps=self.apps, capabilities=caps)
        adapter.select_target("com.example.alpha", authorized=True)
        adapter.start_live_test(timestamp_ms=100)
        event = adapter.snapshot({"cpu_pct": 8, "rss_mb": 96, "private_memory": "no"}, timestamp_ms=110)
        self.assertEqual(event.data, {"cpu_pct": 8, "rss_mb": 96})


if __name__ == "__main__":
    unittest.main()
