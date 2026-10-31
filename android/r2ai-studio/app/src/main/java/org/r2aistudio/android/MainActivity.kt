package org.r2aistudio.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.ViewGroup
import android.widget.*
import kotlinx.coroutines.*
import org.r2aistudio.ai.LiteRtLmProvider
import java.io.File

class MainActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val ai = LiteRtLmProvider()
    private lateinit var status: TextView
    private lateinit var prompt: EditText
    private lateinit var output: TextView
    private var model: File? = null
    private val importCode = 12

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
        }
        status = TextView(this).apply { text = "Offline mode • No model loaded" }
        val import = Button(this).apply { text = "Settings · Import LiteRT model"; setOnClickListener { showSetup() } }
        prompt = EditText(this).apply { hint = "Ask about an APK inspection report"; minLines = 2 }
        val send = Button(this).apply { text = "Ask local AI"; setOnClickListener { ask() } }
        output = TextView(this).apply { text = "The editor and offline inspector do not require AI." }
        root.addView(status)
        root.addView(import)
        root.addView(prompt)
        root.addView(send)
        val scroll = ScrollView(this)
        scroll.addView(output)
        root.addView(scroll, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)
        showSetup()
    }

    private fun showSetup() {
        AlertDialog.Builder(this)
            .setTitle("Offline AI model")
            .setMessage("Import a compatible .litertlm model to enable on-device AI. No GGUF or cloud API required. Files stay on this phone.")
            .setPositiveButton("Import model") { _, _ ->
                startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    type = "*/*"
                    addCategory(Intent.CATEGORY_OPENABLE)
                }, importCode)
            }
            .setNeutralButton("Continue without AI") { _, _ -> }
            .setNegativeButton("Model help") { _, _ ->
                startActivity(Intent(Intent.ACTION_VIEW, android.net.Uri.parse("https://huggingface.co/litert-community")))
            }.show()
    }

    @Deprecated("Uses Activity result API for a minimal compatibility shell")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != importCode || resultCode != RESULT_OK) return
        val uri = data?.data ?: return
        scope.launch {
            status.text = "Importing model…"
            try {
                val file = withContext(Dispatchers.IO) {
                    val destination = File(filesDir, "local-model.litertlm")
                    val temp = File(filesDir, "local-model.partial")
                    try {
                        contentResolver.openInputStream(uri).use { input ->
                            requireNotNull(input) { "Unable to open selected file" }
                            temp.outputStream().use { output ->
                                val buffer = ByteArray(65536)
                                var total = 0L
                                while (true) {
                                    val n = input.read(buffer)
                                    if (n < 0) break
                                    total += n
                                    require(total <= 4L * 1024 * 1024 * 1024) { "Model exceeds 4 GiB limit" }
                                    output.write(buffer, 0, n)
                                }
                            }
                        }
                        require(temp.length() > 0) { "Model is empty" }
                        if (destination.exists()) require(destination.delete()) { "Cannot replace old model" }
                        require(temp.renameTo(destination)) { "Unable to save model" }
                        destination
                    } finally { temp.delete() }
                }
                model = file
                status.text = "Model imported • Loading…"
                withContext(Dispatchers.IO) { ai.close(); ai.load(file.absolutePath) }
                status.text = "Local AI ready"
            } catch (e: Exception) {
                status.text = "Model unavailable: ${e.message}"
                AlertDialog.Builder(this@MainActivity).setTitle("Model setup failed")
                    .setMessage("${e.message}\n\nCheck model compatibility and free storage. Offline tools remain available.")
                    .setPositiveButton("Retry") { _, _ -> showSetup() }.setNegativeButton("Close", null).show()
            }
        }
    }

    private fun ask() {
        if (!ai.isLoaded) { showSetup(); return }
        val question = prompt.text.toString()
        scope.launch {
            status.text = "Generating locally…"
            try {
                output.text = ai.generate(question)
                status.text = "Local AI ready"
            } catch (e: Exception) {
                status.text = "Generation failed"
                output.text = e.message ?: "Unknown error"
            }
        }
    }

    override fun onDestroy() {
        scope.cancel()
        ai.close()
        super.onDestroy()
    }
}
