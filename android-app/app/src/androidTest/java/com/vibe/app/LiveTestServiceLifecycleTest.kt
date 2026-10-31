package com.vibe.app

import android.app.Notification
import android.app.NotificationManager
import android.widget.Button
import android.view.View
import android.view.ViewGroup
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class LiveTestServiceLifecycleTest {
    private fun waitFor(message: String, timeoutMs: Long = 10000, condition: () -> Boolean) {
        val deadline = System.nanoTime() + timeoutMs * 1_000_000
        while (System.nanoTime() < deadline) {
            if (condition()) return
            Thread.sleep(150)
        }
        assertTrue(message, condition())
    }

    private fun findLiveTestButton(root: View): Button? {
        if (root is Button && root.text.toString().trim().equals("Live Test", ignoreCase = true)) {
            return root
        }
        if (root is ViewGroup) {
            for (index in 0 until root.childCount) {
                val match = findLiveTestButton(root.getChildAt(index))
                if (match != null) return match
            }
        }
        return null
    }

    @Test
    fun appOwnedStartCreatesForegroundNotificationAndStopActionRemovesIt() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val notifications = context.getSystemService(NotificationManager::class.java)
        val notificationId = 7001
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        try {
            scenario.onActivity { activity ->
                val button = findLiveTestButton(activity.window.decorView)
                assertNotNull("Live Test must be an app-owned visible button", button)
                assertTrue("Live Test button must be enabled", button!!.isEnabled)
                assertTrue("Live Test button must be clickable", button.isClickable)
                button.performClick()
            }
            waitFor("Foreground notification did not appear") {
                notifications.activeNotifications.any { it.id == notificationId }
            }
            val active = notifications.activeNotifications.single { it.id == notificationId }
            val notification = active.notification
            assertEquals("vibe_live_test", notification.channelId)
            assertTrue(
                "Notification must be attached to a foreground service",
                notification.flags and Notification.FLAG_FOREGROUND_SERVICE != 0
            )
            val stopActions = notification.actions.orEmpty().filter {
                it.title.toString().trim().equals("Stop", ignoreCase = true)
            }
            assertEquals("Exactly one Stop notification action required", 1, stopActions.size)
            assertNotNull("Stop PendingIntent missing", stopActions.single().actionIntent)
            stopActions.single().actionIntent.send()
            waitFor("Stop did not remove the foreground notification") {
                notifications.activeNotifications.none { it.id == notificationId }
            }
        } finally {
            scenario.close()
        }
    }
    @Test
    fun repeatedStartStopAndActivityRecreationLeaveNoNotification() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val notifications = context.getSystemService(NotificationManager::class.java)
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        try {
            repeat(3) { cycle ->
                scenario.onActivity { activity ->
                    val button = findLiveTestButton(activity.window.decorView)
                    assertNotNull("Cycle $cycle: Live Test button missing", button)
                    assertTrue("Cycle $cycle: button disabled", button!!.isEnabled)
                    assertTrue("Cycle $cycle: button not clickable", button.isClickable)
                    button.performClick()
                }
                waitFor("Cycle $cycle: foreground notification missing") {
                    notifications.activeNotifications.any { it.id == 7001 }
                }
                val active = notifications.activeNotifications.single { it.id == 7001 }
                assertEquals("vibe_live_test", active.notification.channelId)
                assertTrue(
                    "Cycle $cycle: foreground flag missing",
                    active.notification.flags and Notification.FLAG_FOREGROUND_SERVICE != 0
                )
                val stopActions = active.notification.actions.orEmpty().filter {
                    it.title.toString().trim().equals("Stop", ignoreCase = true)
                }
                assertEquals("Cycle $cycle: exactly one Stop required", 1, stopActions.size)
                assertNotNull("Cycle $cycle: Stop intent missing", stopActions.single().actionIntent)
                stopActions.single().actionIntent.send()
                waitFor("Cycle $cycle: notification leaked after Stop") {
                    notifications.activeNotifications.none { it.id == 7001 }
                }
                if (cycle == 0) scenario.recreate()
            }
        } finally {
            scenario.close()
        }
    }

    @Test
    fun notificationPermissionDeniedDoesNotBreakAppOwnedStartStop() {
        if (android.os.Build.VERSION.SDK_INT < 33) return
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val permission = android.Manifest.permission.POST_NOTIFICATIONS
        val wasGranted = context.checkSelfPermission(permission) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED

        fun changePermission(command: String) {
            instrumentation.uiAutomation.executeShellCommand(
                "pm $command ${context.packageName} $permission"
            ).use { descriptor ->
                android.os.ParcelFileDescriptor.AutoCloseInputStream(descriptor).use {
                    it.readBytes()
                }
            }
        }

        var scenario: ActivityScenario<MainActivity>? = null
        try {
            changePermission("revoke")
            waitFor("Notification permission was not revoked") {
                context.checkSelfPermission(permission) ==
                    android.content.pm.PackageManager.PERMISSION_DENIED
            }
            scenario = ActivityScenario.launch(MainActivity::class.java)
            scenario.onActivity { activity ->
                val button = findLiveTestButton(activity.window.decorView)
                assertNotNull("Live Test button missing when notifications denied", button)
                assertTrue("Live Test button disabled when notifications denied", button!!.isEnabled)
                button.performClick()
            }
            // Android may suppress drawer notifications while still running the
            // foreground service; do not assert activeNotifications visibility.
            context.startService(
                android.content.Intent(context, LiveTestService::class.java)
                    .setAction(LiveTestService.ACTION_STOP)
            )
            scenario.onActivity { activity ->
                assertTrue("Activity was destroyed by denied permission", !activity.isFinishing)
            }
        } finally {
            context.stopService(android.content.Intent(context, LiveTestService::class.java))
            scenario?.close()
            if (wasGranted) changePermission("grant") else changePermission("revoke")
            waitFor("Notification permission state was not restored") {
                (context.checkSelfPermission(permission) ==
                    android.content.pm.PackageManager.PERMISSION_GRANTED) == wasGranted
            }
        }
    }

}
