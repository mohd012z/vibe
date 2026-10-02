package com.vibe.app

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat

class LiveTestService : Service() {
    companion object {
        const val ACTION_START = "com.vibe.app.START"
        const val ACTION_MARK_ISSUE = "com.vibe.app.MARK_ISSUE"
        const val ACTION_SNAPSHOT = "com.vibe.app.SNAPSHOT"
        const val ACTION_PAUSE_RESUME = "com.vibe.app.PAUSE_RESUME"
        const val ACTION_STOP = "com.vibe.app.STOP"
        private const val CHANNEL = "vibe_live_test"
        private const val NOTIFICATION_ID = 7001
    }

    override fun onCreate() {
        super.onCreate()
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, "Vibe live test", NotificationManager.IMPORTANCE_LOW)
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> { stopForeground(STOP_FOREGROUND_REMOVE); stopSelf(); return START_NOT_STICKY }
            ACTION_MARK_ISSUE -> Unit
            ACTION_SNAPSHOT -> Unit
            ACTION_PAUSE_RESUME -> Unit
        }
        startForeground(NOTIFICATION_ID, notification())
        return START_NOT_STICKY
    }

    private fun notification() = NotificationCompat.Builder(this, CHANNEL)
        .setSmallIcon(android.R.drawable.ic_menu_info_details)
        .setContentTitle("Vibe Live Test")
        .setContentText("Authorized runtime observation active")
        .setOngoing(true)
        .addAction(0, "Mark Issue", pending(ACTION_MARK_ISSUE, 1))
        .addAction(0, "Snapshot", pending(ACTION_SNAPSHOT, 2))
        .addAction(0, "Pause/Resume", pending(ACTION_PAUSE_RESUME, 3))
        .addAction(0, "Stop", pending(ACTION_STOP, 4))
        .build()

    private fun pending(action: String, code: Int): PendingIntent = PendingIntent.getService(
        this, code, Intent(this, LiveTestService::class.java).setAction(action),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
    )

    override fun onBind(intent: Intent?): IBinder? = null
}
