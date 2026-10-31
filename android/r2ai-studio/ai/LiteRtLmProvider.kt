package org.r2aistudio.ai

import com.google.ai.edge.litertlm.Backend
import com.google.ai.edge.litertlm.Engine
import com.google.ai.edge.litertlm.EngineConfig
import com.google.ai.edge.litertlm.Conversation
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * One executor owns the engine and all conversations.
 * close() must be called after pending generate/load calls have completed.
 */
class LiteRtLmProvider : LocalAiProvider {
    private val executor = Executors.newSingleThreadExecutor()
    private val dispatcher = executor.asCoroutineDispatcher()
    private val closing = AtomicBoolean(false)
    @Volatile private var loaded = false
    private var engine: Engine? = null
    private var conversation: Conversation? = null
    override val isLoaded: Boolean get() = loaded && !closing.get()

    override suspend fun load(modelPath: String) = withContext(dispatcher) {
        require(File(modelPath).isFile) { "Select a readable model file" }
        require(modelPath.endsWith(".litertlm", ignoreCase = true)) {
            "Select a LiteRT-LM .litertlm model, not a GGUF file"
        }
        check(!closing.get()) { "Provider is closed" }
        // Initialize the replacement before releasing the working model.
        // This preserves the previous session if initialization fails, at the
        // cost of temporarily needing memory for both models.
        val candidate = Engine(EngineConfig(modelPath = modelPath, backend = Backend.CPU()))
        candidate.initialize()
        val newChat = try {
            candidate.createConversation()
        } catch (failure: Throwable) {
            candidate.close()
            throw failure
        }
        val oldChat = conversation
        val oldEngine = engine
        conversation = newChat
        engine = candidate
        loaded = true
        try { oldChat?.close() } finally { oldEngine?.close() }
    }

    override suspend fun generate(prompt: String): String = withContext(dispatcher) {
        require(prompt.isNotBlank()) { "Enter a question" }
        check(!closing.get()) { "Provider is closing" }
        val chat = checkNotNull(conversation) { "Import a model under AI Models" }
        chat.sendMessage(prompt).toString()
    }

    override fun close() {
        // Serializes teardown behind any in-flight load/generate task.
        if (!closing.compareAndSet(false, true)) return
        val teardown = executor.submit {
            val chat = conversation
            conversation = null
            val current = engine
            engine = null
            loaded = false
            try { chat?.close() } finally { current?.close() }
        }
        try { teardown.get() } finally {
            dispatcher.close()
            executor.shutdown()
        }
    }
}
