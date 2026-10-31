package org.r2aistudio.ai

import com.google.ai.edge.litertlm.Backend
import com.google.ai.edge.litertlm.Engine
import com.google.ai.edge.litertlm.EngineConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/** LiteRT-LM CPU implementation. Model import and UI orchestration live elsewhere. */
class LiteRtLmProvider : LocalAiProvider {
    private var engine: Engine? = null
    override val isLoaded: Boolean get() = engine != null

    override suspend fun load(modelPath: String) = withContext(Dispatchers.IO) {
        require(File(modelPath).isFile) { "Model must be a readable local file" }
        check(engine == null) { "Unload the current model before loading another" }
        val candidate = Engine(EngineConfig(modelPath = modelPath, backend = Backend.CPU()))
        try {
            candidate.initialize()
            engine = candidate
        } catch (failure: Exception) {
            runCatching { candidate.close() }
            throw failure
        }
    }

    override suspend fun generate(prompt: String): String = withContext(Dispatchers.IO) {
        require(prompt.isNotBlank()) { "Prompt must not be blank" }
        val current = checkNotNull(engine) { "Import and load a model in Settings → AI Models" }
        current.createConversation().use { conversation ->
            conversation.sendMessage(prompt).toString()
        }
    }

    override fun close() {
        val current = engine
        engine = null
        if (current != null) current.close()
    }
}
