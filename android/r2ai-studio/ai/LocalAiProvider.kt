package org.r2aistudio.ai

/** Explicit lifecycle contract; no cloud or GGUF requirement. */
interface LocalAiProvider : AutoCloseable {
    val isLoaded: Boolean
    suspend fun load(modelPath: String)
    suspend fun generate(prompt: String): String
    override fun close()
}
