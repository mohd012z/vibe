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
}
