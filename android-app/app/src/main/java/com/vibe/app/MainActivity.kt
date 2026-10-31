package com.vibe.app

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts.OpenDocument
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

class MainActivity : AppCompatActivity() {
    private val apkPicker = registerForActivityResult(OpenDocument()) { uri ->
        if (uri != null) status.text = "APK selected: ${uri.lastPathSegment ?: "document"}"
    }
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        status = TextView(this).apply { text = "Ready" }
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 48, 32, 32) }
        root.addView(TextView(this).apply { text = "Vibe"; textSize = 28f })
        root.addView(actionButton("Test Installed App") { status.text = "Installed-app picker binding is next" })
        root.addView(actionButton("Test APK File") { apkPicker.launch(arrayOf("application/vnd.android.package-archive")) })
        root.addView(actionButton("Live Test") { startLiveService() })
        root.addView(status)
        setContentView(root)
    }

    private fun actionButton(label: String, action: () -> Unit) = Button(this).apply { text = label; setOnClickListener { action() } }

    private fun startLiveService() {
        val intent = Intent(this, LiveTestService::class.java).setAction(LiveTestService.ACTION_START)
        ContextCompat.startForegroundService(this, intent)
        status.text = "Live test running"
    }
}
