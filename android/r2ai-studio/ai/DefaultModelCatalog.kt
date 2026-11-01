package org.r2aistudio.ai

/** Publisher references, not a verified cryptographic trust store. */
object DefaultModelCatalog {
    const val modelId = "litert-community/Qwen3-0.6B"
    const val fileName = "Qwen3-0.6B.litertlm"
    const val estimatedBytes = 613_722_264L
    const val sha256 = "c5f39b4191926786c3e6668b62af4d6eb15248dfc7a5348252a9b406f33f2108"
    const val minimumRuntime = "0.18.0"
    const val contextTokens = 4096
    const val artifactQuantization = "dynamic INT8"
    const val url = "https://huggingface.co/litert-community/Qwen3-0.6B/resolve/main/Qwen3-0.6B.litertlm"
    const val licenseStatus = "Apache-2.0 (publisher model card)"
    fun isTrustedTransport(candidate: String): Boolean =
        candidate == url
}
