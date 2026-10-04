import unittest

from tools.runtime.android_live_ui_provider import (
    AndroidLiveProvider,
    LiveTestScreenModel,
    ProviderApp,
    RuntimeSample,
)


class AndroidLiveUIProviderTests(unittest.TestCase):
    def setUp(self):
        self.apps = [
            ProviderApp("com.example.alpha", "Alpha", launchable=True, running=False),
            ProviderApp("com.example.beta", "Beta", launchable=False, running=True),
        ]

    def test_home_exposes_installed_app_and_apk_file_test_modes(self):
        provider = AndroidLiveProvider(apps=self.apps)
        self.assertEqual(provider.home_actions(), ("test_installed_app", "test_apk_file", "live_test"))

    def test_app_picker_returns_only_visible_apps(self):
        provider = AndroidLiveProvider(apps=self.apps)
        self.assertEqual([a.package_name for a in provider.app_picker()], ["com.example.alpha", "com.example.beta"])

    def test_start_requires_explicit_authorization(self):
        provider = AndroidLiveProvider(apps=self.apps)
        with self.assertRaises(PermissionError):
            provider.start("com.example.alpha", authorized=False, timestamp_ms=100)

    def test_launchable_app_opens_and_starts_foreground_session(self):
        provider = AndroidLiveProvider(apps=self.apps)
        screen = provider.start("com.example.alpha", authorized=True, timestamp_ms=100)
        self.assertTrue(screen.foreground_session)
        self.assertEqual(screen.target_package, "com.example.alpha")
        self.assertEqual(screen.state, "running")

    def test_running_non_launchable_app_can_attach(self):
        provider = AndroidLiveProvider(apps=self.apps)
        screen = provider.start("com.example.beta", authorized=True, timestamp_ms=100)
        self.assertEqual(screen.state, "running")

    def test_compact_floating_controller_contract(self):
        provider = AndroidLiveProvider(apps=self.apps)
        self.assertEqual(provider.floating_controls(), ("mark_issue", "snapshot", "pause_resume", "stop"))

    def test_runtime_sample_contains_only_observable_metrics(self):
        provider = AndroidLiveProvider(apps=self.apps)
        provider.start("com.example.alpha", authorized=True, timestamp_ms=100)
        event = provider.record_sample(RuntimeSample(cpu_pct=9, rss_mb=120, frame_ms=16.7), timestamp_ms=110)
        self.assertEqual(event.data, {"cpu_pct": 9, "rss_mb": 120, "frame_ms": 16.7})
        self.assertNotIn("private_memory", event.data)

    def test_mark_issue_updates_timeline_screen(self):
        provider = AndroidLiveProvider(apps=self.apps)
        provider.start("com.example.alpha", authorized=True, timestamp_ms=100)
        provider.mark_issue("freeze", timestamp_ms=110)
        screen = provider.screen_model()
        self.assertEqual(screen.timeline[-1].summary, "freeze")

    def test_screen_model_is_read_only_projection(self):
        provider = AndroidLiveProvider(apps=self.apps)
        provider.start("com.example.alpha", authorized=True, timestamp_ms=100)
        screen = provider.screen_model()
        self.assertIsInstance(screen, LiveTestScreenModel)
        with self.assertRaises(Exception):
            screen.state = "fake"

    def test_stop_ends_foreground_session(self):
        provider = AndroidLiveProvider(apps=self.apps)
        provider.start("com.example.alpha", authorized=True, timestamp_ms=100)
        provider.stop(timestamp_ms=110)
        screen = provider.screen_model()
        self.assertEqual(screen.state, "stopped")
        self.assertFalse(screen.foreground_session)


if __name__ == "__main__":
    unittest.main()
