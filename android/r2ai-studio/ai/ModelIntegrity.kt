package org.r2aistudio.ai

import java.io.File
import java.security.MessageDigest

/** Pure-JVM integrity checks. A computed digest alone is not authentication. */
object ModelIntegrity {
    fun normalizeExpectedSha256(value: String): String {
        val normalized = value.trim().lowercase()
        require(normalized.length == 64 && normalized.all { it in '0'..'9' || it in 'a'..'f' }) {
            "Expected SHA-256 must be exactly 64 hexadecimal characters"
        }
        return normalized
    }

    fun sha256(file: File): String {
        require(file.isFile) { "Model file does not exist" }
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count == -1) break
                if (count > 0) digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    fun verify(file: File, expectedSha256: String): Boolean {
        val expected = normalizeExpectedSha256(expectedSha256)
        val actual = sha256(file)
        return MessageDigest.isEqual(actual.toByteArray(Charsets.US_ASCII), expected.toByteArray(Charsets.US_ASCII))
    }
}
