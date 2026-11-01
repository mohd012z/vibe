package org.r2aistudio.ai

import org.junit.Assert.*
import org.junit.Test
import java.io.File

class ModelIntegrityTest {
    @Test fun checksum() {
        val file = File.createTempFile("r2ai", ".litertlm")
        try {
            file.writeText("abc")
            val hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            assertTrue(ModelIntegrity.verify(file, hash))
            file.writeText("abd")
            assertFalse(ModelIntegrity.verify(file, hash))
        } finally { file.delete() }
    }

    @Test fun uppercaseAndWhitespace() {
        val file = File.createTempFile("r2ai", ".litertlm")
        try {
            file.writeText("abc")
            val hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            assertTrue(ModelIntegrity.verify(file, "  " + hash.uppercase() + "  "))
        } finally { file.delete() }
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectMalformedExpectedDigest() {
        ModelIntegrity.normalizeExpectedSha256("not a sha256")
    }

    @Test fun rejectEmptyAndTruncatedModel() {
        val file = File.createTempFile("r2ai", ".litertlm")
        try {
            val original = "abc".toByteArray()
            file.writeBytes(original)
            val expected = ModelIntegrity.sha256(file)
            file.writeBytes(original.copyOf(2))
            assertFalse(ModelIntegrity.verify(file, expected))
            file.writeBytes(byteArrayOf())
            assertFalse(ModelIntegrity.verify(file, expected))
        } finally { file.delete() }
    }
}
