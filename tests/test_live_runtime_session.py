import unittest

from tools.runtime.live_session import LiveRuntimeSession, RuntimeEvent


class LiveRuntimeSessionTests(unittest.TestCase):
    def test_requires_explicit_authorized_target(self):
        with self.assertRaises(ValueError):
            LiveRuntimeSession(package_name="", authorized=True)
        with self.assertRaises(PermissionError):
            LiveRuntimeSession(package_name="com.example.app", authorized=False)

    def test_session_state_machine(self):
        session = LiveRuntimeSession("com.example.app", authorized=True)
        self.assertEqual(session.state, "ready")
        session.start()
        self.assertEqual(session.state, "running")
        session.pause()
        self.assertEqual(session.state, "paused")
        session.resume()
        self.assertEqual(session.state, "running")
        session.stop()
        self.assertEqual(session.state, "stopped")

    def test_mark_issue_creates_timestamped_evidence_event(self):
        session = LiveRuntimeSession("com.example.app", authorized=True)
        session.start(timestamp_ms=12000)
        event = session.mark_issue("freeze after login", timestamp_ms=12345)
        self.assertEqual(event.kind, "issue")
        self.assertEqual(event.timestamp_ms, 12345)
        self.assertEqual(event.summary, "freeze after login")
        self.assertEqual(session.timeline[-1], event)

    def test_snapshot_records_observation_without_private_memory_access(self):
        session = LiveRuntimeSession("com.example.app", authorized=True)
        session.start(timestamp_ms=19000)
        event = session.snapshot({"cpu_pct": 12, "rss_mb": 184}, timestamp_ms=20000)
        self.assertEqual(event.kind, "snapshot")
        self.assertEqual(event.data["rss_mb"], 184)
        self.assertNotIn("private_memory", event.data)

    def test_private_memory_payload_is_rejected(self):
        session = LiveRuntimeSession("com.example.app", authorized=True)
        session.start()
        with self.assertRaises(ValueError):
            session.snapshot({"private_memory": "secret"})

    def test_runtime_events_are_ordered(self):
        session = LiveRuntimeSession("com.example.app", authorized=True)
        session.start(timestamp_ms=100)
        session.observe("activity", "MainActivity resumed", timestamp_ms=120)
        session.mark_issue("UI stalled", timestamp_ms=130)
        self.assertEqual([e.timestamp_ms for e in session.timeline], [100, 120, 130])

    def test_out_of_order_timestamp_is_rejected(self):
        session = LiveRuntimeSession("com.example.app", authorized=True)
        session.start(timestamp_ms=100)
        session.observe("activity", "MainActivity resumed", timestamp_ms=120)
        with self.assertRaises(ValueError):
            session.mark_issue("late evidence", timestamp_ms=110)
        self.assertEqual([e.timestamp_ms for e in session.timeline], [100, 120])

    def test_cannot_capture_after_stop(self):
        session = LiveRuntimeSession("com.example.app", authorized=True)
        session.start()
        session.stop()
        with self.assertRaises(RuntimeError):
            session.mark_issue("too late")

    def test_runtime_event_is_immutable(self):
        event = RuntimeEvent(1, "activity", "opened", {})
        with self.assertRaises(Exception):
            event.summary = "changed"


if __name__ == "__main__":
    unittest.main()
