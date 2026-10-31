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
}
