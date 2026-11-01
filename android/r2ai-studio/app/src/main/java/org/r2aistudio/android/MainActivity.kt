package org.r2aistudio.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.view.ViewGroup
import android.widget.*
import kotlinx.coroutines.*
import org.r2aistudio.ai.LiteRtLmProvider
import org.r2aistudio.ai.ModelIntegrity
import java.io.File
import java.security.MessageDigest
import java.net.URL
import java.net.HttpURLConnection

class MainActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val ai = LiteRtLmProvider()
    private lateinit var status: TextView
    private lateinit var prompt: EditText
    private lateinit var output: TextView
    private lateinit var expectedHash: EditText
    private var model: File? = null
    private val importCode = 12
    private var importing = false
    private var generating = false
    private var generationEpoch = 0L
    private val preferences by lazy { getSharedPreferences("offline_llm", MODE_PRIVATE) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
        }
        status = TextView(this).apply { text = "Offline mode • No model loaded" }
        val import = Button(this).apply { text = "Settings · Import LiteRT model"; setOnClickListener { showSetup() } }
        expectedHash = EditText(this).apply { hint = "Trusted SHA-256 (optional, 64 hex characters)"; setSingleLine(true) }
        prompt = EditText(this).apply { hint = "Ask about an APK inspection report"; minLines = 2 }
        val send = Button(this).apply { text = "Ask local AI"; setOnClickListener { ask() } }
        output = TextView(this).apply { text = "The editor and offline inspector do not require AI." }
        root.addView(status)
        root.addView(import)
        root.addView(Button(this).apply { text = "LLM · Download model"; setOnClickListener { showDownloadModel() } })
        root.addView(Button(this).apply { text = "LLM · Load saved model"; setOnClickListener { showSavedModels() } })
        root.addView(expectedHash)
        root.addView(prompt)
        root.addView(send)
        val scroll = ScrollView(this)
        scroll.addView(output)
        root.addView(scroll, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)
        if (savedInstanceState != null) {
            prompt.setText(savedInstanceState.getString("draftPrompt", ""))
            expectedHash.setText(savedInstanceState.getString("expectedHash", ""))
            output.text = savedInstanceState.getString("lastOutput", "The editor and offline inspector do not require AI.")
            status.text = "Offline mode • Restoring model…"
            autoSetup()
        } else {
            autoSetup()
        }
    }

    private fun autoSetup() {
        val saved = preferences.getString("activeModel", null)
        val selected = saved?.let { File(filesDir, it) }
        if (selected?.isFile == true && selected.name.matches(Regex("model-[0-9a-fA-F-]{36}\\.litertlm"))) {
            importing = true
            scope.launch {
                status.text = "Starting saved offline LLM…"
                try {
                    ai.load(selected.absolutePath)
                    model = selected
                    status.text = "Local LLM ready"
                } catch (failure: Exception) {
                    preferences.edit().remove("activeModel").apply()
                    status.text = "Saved LLM unavailable: " + (failure.message ?: "Unknown error")
                    showSetup()
                } finally { importing = false }
            }
        } else {
            if (saved != null) preferences.edit().remove("activeModel").apply()
            showSetup()
        }
    }

    private fun showDownloadModel() {
        if (importing || generating) {
            status.text = "Wait for the current model operation to finish"
            return
        }
        val address = EditText(this).apply {
            hint = "https://.../model.litertlm"
            setSingleLine(true)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_URI
        }
        AlertDialog.Builder(this).setTitle("Download LiteRT-LM model")
            .setMessage("Use a direct HTTPS model file URL from a trusted publisher. Supply its SHA-256 in the main screen for verification. Downloads require internet; inference remains offline.")
            .setView(address)
            .setPositiveButton("Download") { _, _ ->
                val urlText = address.text.toString().trim()
                val checksum = expectedHash.text.toString().trim()
                if (!urlText.startsWith("https://", ignoreCase = true) || !urlText.substringBefore('?').endsWith(".litertlm", ignoreCase = true)) {
                    status.text = "Provide a direct HTTPS .litertlm URL"
                } else if (checksum.isNotEmpty() && runCatching { ModelIntegrity.normalizeExpectedSha256(checksum) }.isFailure) {
                    status.text = "Invalid expected SHA-256"
                } else {
                    importing = true
                    generationEpoch++
                    scope.launch {
                        status.text = "Downloading LLM…"
                        try {
                            val file = withContext(Dispatchers.IO) {
                                val destination = File(filesDir, "model-" + java.util.UUID.randomUUID() + ".litertlm")
                                val temp = File(filesDir, destination.name + ".partial")
                                val digest = MessageDigest.getInstance("SHA-256")
                                val limit = 4L * 1024 * 1024 * 1024
                                try {
                                    val connection = URL(urlText).openConnection() as HttpURLConnection
                                    connection.connectTimeout = 15000
                                    connection.readTimeout = 30000
                                    connection.instanceFollowRedirects = false
                                    try {
                                        require(connection.responseCode == 200) { "Download failed: HTTP " + connection.responseCode }
                                        require(connection.contentLengthLong <= limit) { "Model exceeds 4 GiB" }
                                        connection.inputStream.use { input ->
                                            temp.outputStream().use { output ->
                                                val buffer = ByteArray(65536)
                                                var count = 0L
                                                while (true) {
                                                    val n = input.read(buffer)
                                                    if (n == -1) break
                                                    count += n
                                                    require(count <= limit && n.toLong() <= filesDir.usableSpace) { "Model exceeds size or available storage" }
                                                    output.write(buffer, 0, n)
                                                    digest.update(buffer, 0, n)
                                                }
                                            }
                                        }
                                        require(temp.length() > 0) { "Downloaded model is empty" }
                                        val hash = digest.digest().joinToString("") { "%02x".format(it) }
                                        if (checksum.isNotEmpty()) {
                                            require(hash == ModelIntegrity.normalizeExpectedSha256(checksum)) { "Model checksum mismatch" }
                                        }
                                        require(temp.renameTo(destination)) { "Unable to save downloaded model" }
                                        destination
                                    } finally { connection.disconnect() }
                                } finally { temp.delete() }
                            }
                            try {
                                ai.load(file.absolutePath)
                                val previous = model
                                model = file
                                preferences.edit().putString("activeModel", file.name).apply()
                                if (previous != null && previous != file) previous.delete()
                                status.text = "Downloaded offline LLM ready"
                            } catch (failure: Exception) {
                                file.delete()
                                val previous = model
                                if (previous?.isFile == true && !ai.isLoaded) {
                                    runCatching { ai.load(previous.absolutePath) }
                                }
                                throw failure
                            }
                        } catch (failure: Exception) {
                            status.text = "LLM download failed: " + (failure.message ?: "Unknown error")
                        } finally {
                            importing = false
                        }
                    }
                }
            }.setNegativeButton("Cancel", null).show()
    }

    private fun showSavedModels() {
        if (importing || generating) {
            status.text = "Wait for the current model operation to finish"
            return
        }
        val files = filesDir.listFiles()
            ?.filter { it.isFile && it.name.endsWith(".litertlm", ignoreCase = true) }
            ?.sortedByDescending { it.lastModified() }
            .orEmpty()
        if (files.isEmpty()) {
            showSetup()
            return
        }
        val labels = files.map { file ->
            file.name + " (" + (file.length() / (1024 * 1024)) + " MiB)"
        }.toTypedArray()
        AlertDialog.Builder(this)
            .setTitle("Offline LLM models")
            .setItems(labels) { _, index ->
                val selected = files[index]
                importing = true
                generationEpoch++
                scope.launch {
                    status.text = "Loading saved LLM…"
                    try {
                        ai.load(selected.absolutePath)
                        model = selected
                        preferences.edit().putString("activeModel", selected.name).apply()
                        status.text = "Local LLM ready"
                    } catch (failure: Exception) {
                        status.text = "LLM load failed: " + (failure.message ?: "Unknown error")
                    } finally {
                        importing = false
                    }
                }
            }
            .setNegativeButton("Close", null)
            .show()
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
        if (importing) return
        val checksum = expectedHash.text.toString().trim()
        if (checksum.isNotEmpty()) {
            try { ModelIntegrity.normalizeExpectedSha256(checksum) }
            catch (e: IllegalArgumentException) { expectedHash.error = e.message; return }
        }
        importing = true
        generationEpoch++ // Invalidate any response started for the previous model.
        scope.launch {
            status.text = "Importing model…"
            try {
                val file = withContext(Dispatchers.IO) {
                    // Unique destination preserves the last working model until validation succeeds.
                    val destination = File(filesDir, "model-" + java.util.UUID.randomUUID() + ".litertlm")
                    val temp = File(filesDir, destination.name + ".partial")
                    val maxBytes = 4L * 1024 * 1024 * 1024
                    val digest = MessageDigest.getInstance("SHA-256")
                    require(filesDir.usableSpace > 0L) { "Cannot determine free model storage" }
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
                                    require(total <= maxBytes) { "Model exceeds 4 GiB limit" }
                                    require(n.toLong() <= filesDir.usableSpace) { "Not enough free storage for model" }
                                    output.write(buffer, 0, n)
                                    digest.update(buffer, 0, n)
                                }
                            }
                        }
                        require(temp.length() > 0) { "Model is empty" }
                        val hash = digest.digest().joinToString("") { "%02x".format(it) }
                        require(hash.length == 64) { "SHA-256 calculation failed" }
                        if (checksum.isNotEmpty()) {
                            require(hash == ModelIntegrity.normalizeExpectedSha256(checksum)) { "Model SHA-256 does not match trusted checksum" }
                        }
                        require(temp.renameTo(destination)) { "Unable to save model" }
                        destination
                    } finally { temp.delete() }
                }
                status.text = "Model imported • Loading…"
                try {
                    ai.load(file.absolutePath)
                    val previous = model
                    model = file
                    preferences.edit().putString("activeModel", file.name).apply()
                    if (previous != null && previous != file) previous.delete()
                    status.text = "Local AI ready"
                } catch (failure: Exception) {
                    file.delete()
                    val previous = model
                    if (previous?.isFile == true && !ai.isLoaded) {
                        try { ai.load(previous.absolutePath) } catch (_: Exception) { /* Keep original error. */ }
                    }
                    throw failure
                }
            } catch (e: Exception) {
                status.text = "Model unavailable: ${e.message}"
                AlertDialog.Builder(this@MainActivity).setTitle("Model setup failed")
                    .setMessage("${e.message}\n\nCheck model compatibility and free storage. Offline tools remain available.")
                    .setPositiveButton("Retry") { _, _ -> showSetup() }.setNegativeButton("Close", null).show()
            } finally {
                importing = false
            }
        }
    }

    private fun ask() {
        if (!ai.isLoaded) { showSetup(); return }
        if (generating || importing) return
        val question = prompt.text.toString()
        if (question.isBlank()) { prompt.error = "Enter a question"; return }
        generating = true
        val epoch = ++generationEpoch
        scope.launch {
            status.text = "Generating locally…"
            try {
                val answer = ai.generate(question)
                if (epoch == generationEpoch && !isFinishing && !isDestroyed) {
                    output.text = answer
                    status.text = "Local AI ready"
                }
            } catch (e: Exception) {
                if (epoch == generationEpoch && !isFinishing && !isDestroyed) {
                    status.text = "Generation failed"
                    output.text = e.message ?: "Unknown error"
                }
            } finally {
                generating = false
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString("draftPrompt", prompt.text.toString())
        outState.putString("expectedHash", expectedHash.text.toString())
        outState.putString("lastOutput", output.text.toString())
        super.onSaveInstanceState(outState)
    }

    override fun onDestroy() {
        generationEpoch++
        scope.cancel()
        Thread({ ai.close() }, "r2ai-engine-shutdown").start()
        super.onDestroy()
    }
}
