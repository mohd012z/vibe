package org.r2aistudio.ai

import com.google.ai.edge.litertlm.Backend
import com.google.ai.edge.litertlm.Engine
import com.google.ai.edge.litertlm.EngineConfig
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.Executors

/**
 * One executor owns the engine and all conversations.
 * close() must be called after pending generate/load calls have completed.
 */
class LiteRtLmProvider : LocalAiProvider {
    private val executor = Executors.newSingleThreadExecutor()
    private val dispatcher = executor.asCoroutineDispatcher()
    @Volatile private var loaded = false
    private var engine: Engine? = null
    override val isLoaded: Boolean get() = loaded

    override suspend fun load(modelPath: String) = withContext(dispatcher) {
        require(File(modelPath).isFile) { "Select a readable model file" }
        require(modelPath.endsWith(".litertlm", ignoreCase = true)) {
            "Select a LiteRT-LM .litertlm model, not a GGUF file"
        }
        check(engine == null) { "Unload the existing model before loading another" }
        val candidate = Engine(EngineConfig(modelPath = modelPath, backend = Backend.CPU()))
        // LiteRT-LM documents that closing an engine after failed initialization may throw.
        candidate.initialize()
        engine = candidate
        loaded = true
    }

    override suspend fun generate(prompt: String): String = withContext(dispatcher) {
        require(prompt.isNotBlank()) { "Enter a question" }
        val current = checkNotNull(engine) { "Import a model under AI Models" }
        current.createConversation().use { conversation ->
            conversation.sendMessage(prompt).toString()
        }
    }

    override fun close() {
        // Serializes teardown behind any in-flight load/generate task.
        if (executor.isShutdown) return
        val teardown = executor.submit {
            val current = engine
            engine = null
            loaded = false
            current?.close()
        }
        try { teardown.get() } finally {
            dispatcher.close()
            executor.shutdown()
        }
    }
}
