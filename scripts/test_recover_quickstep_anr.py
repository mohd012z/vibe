import unittest
from recover_quickstep_anr import recovery_coordinates


def node(text, resource_id, cls="android.widget.Button", bounds="[70,1269][1010,1395]", package="android"):
    return f'<node text="{text}" resource-id="{resource_id}" class="{cls}" package="{package}" enabled="true" clickable="true" bounds="{bounds}" />'


class RecoveryTests(unittest.TestCase):
    def test_exact_dialog(self):
        xml = "<hierarchy>" + node("Quickstep isn&#39;t responding", "android:id/alertTitle", "android.widget.TextView") + node("Wait", "android:id/aerr_wait") + "</hierarchy>"
        self.assertEqual(recovery_coordinates(xml), (540, 1332))

    def test_other_app_is_not_dismissed(self):
        xml = "<hierarchy>" + node("Vibe isn't responding", "android:id/alertTitle") + node("Wait", "android:id/aerr_wait") + "</hierarchy>"
        self.assertIsNone(recovery_coordinates(xml))

    def test_duplicate_wait_rejected(self):
        xml = "<hierarchy>" + node("Quickstep isn&#39;t responding", "android:id/alertTitle") + node("Wait", "android:id/aerr_wait") * 2 + "</hierarchy>"
        with self.assertRaises(ValueError):
            recovery_coordinates(xml)


if __name__ == "__main__":
    unittest.main()
