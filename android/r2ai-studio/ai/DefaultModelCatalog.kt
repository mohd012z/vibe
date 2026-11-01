package org.r2aistudio.ai

/** Publisher references, not a verified cryptographic trust store. */
object DefaultModelCatalog {
    const val modelId = "litert-community/Qwen3-0.6B"
    const val fileName = "Qwen3-0.6B.litertlm"
    const val estimatedBytes = 586_000_000L
    const val minimumRuntime = "0.18.0"
    const val contextTokens = 4096
    const val artifactQuantization = "dynamic INT8"
    const val url = "https://huggingface.co/litert-community/Qwen3-0.6B/resolve/main/Qwen3-0.6B.litertlm"
    const val licenseStatus = "Review publisher model card before use; license not verified in this app"
    fun isTrustedTransport(candidate: String): Boolean =
        candidate == url
}
