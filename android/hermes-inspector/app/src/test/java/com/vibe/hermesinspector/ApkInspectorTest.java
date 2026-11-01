package com.vibe.hermesinspector;

import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class ApkInspectorTest {
    @Rule public final TemporaryFolder temp = new TemporaryFolder();

    private byte[] hermes(int version, int functionCount) {
        byte[] data = new byte[256];
        ByteBuffer b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        b.putLong(0, ApkInspector.HERMES_MAGIC);
        b.putInt(8, version);
        b.putInt(32, data.length);
        b.putInt(40, functionCount);
        byte[] text = "genuine-looking phrase for search".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(text, 0, data, 125, text.length);
        return data;
    }

    private File zipped(String name, Map<String, byte[]> entries) throws IOException {
        File file = temp.newFile(name);
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(file))) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue());
                zip.closeEntry();
            }
        }
        return file;
    }

    @Test public void validHeaderAndFunctions() throws Exception {
        ApkInspector.Header h = ApkInspector.parseHermesHeader(hermes(99, 123));
        assertNotNull(h);
        assertEquals(99, h.version);
        assertTrue(h.registered);
        assertEquals(123L, h.functionCount);
        assertEquals("empty", h.bigIntStatus);
    }

    @Test public void rejectedUnknownVersionNotPretendedSupported() throws Exception {
        ApkInspector.Header h = ApkInspector.parseHermesHeader(hermes(101, 3));
        assertNotNull(h);
        assertFalse(h.registered);
    }

    @Test public void plainJavaScriptIsNotHermes() throws Exception {
        assertNull(ApkInspector.parseHermesHeader("console.log('hello')".getBytes(StandardCharsets.UTF_8)));
    }

    @Test public void truncatedMagicHeaderRejected() throws Exception {
        byte[] bytes = new byte[16];
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
                .putLong(0, ApkInspector.HERMES_MAGIC);
        try {
            ApkInspector.parseHermesHeader(bytes);
            fail("Expected IOException");
        } catch (IOException expected) {
            assertTrue(expected.getMessage().contains("Truncated"));
        }
    }

    @Test public void mixedFlutterDexReactNativeHermes() throws Exception {
        Map<String, byte[]> data = new LinkedHashMap<>();
        data.put("classes.dex", new byte[]{'d', 'e', 'x'});
        data.put("lib/arm64-v8a/libflutter.so", new byte[]{1,2});
        data.put("assets/index.android.bundle", hermes(100, 7));
        ApkInspector.Report report = ApkInspector.inspect(zipped("mixed.apk", data));
        assertTrue(report.technologies.contains("DEX"));
        assertTrue(report.technologies.contains("Flutter"));
        assertTrue(report.technologies.contains("React Native"));
        assertTrue(report.technologies.contains("Hermes"));
        assertEquals(7L, report.functionCount);
        assertEquals(1, report.hermesBundles);
        assertEquals(3, report.entries);
        assertEquals(64, report.sha256.length());
        assertTrue(report.candidates.stream().anyMatch(s -> s.contains("genuine-looking")));
    }

    @Test public void javascriptBundleIsNotMisclassifiedAsHermes() throws Exception {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("assets/index.android.bundle", "console.log('hello')".getBytes(StandardCharsets.US_ASCII));
        ApkInspector.Report report = ApkInspector.inspect(zipped("plain.apk", entries));
        assertEquals(0, report.hermesBundles);
        assertTrue(report.technologies.contains("React Native"));
        assertFalse(report.technologies.contains("Hermes"));
    }

    @Test public void traversalPathsAreRejected() throws Exception {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("../assets/index.android.bundle", hermes(99, 1));
        try {
            ApkInspector.inspect(zipped("traversal.apk", entries));
            fail("Expected path refusal");
        } catch (IOException expected) {
            assertTrue(expected.getMessage().contains("Unsafe"));
        }
    }

    @Test public void compressedBombIsRejected() throws Exception {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("assets/index.android.bundle", new byte[3_000_000]);
        try {
            ApkInspector.inspect(zipped("bomb.apk", entries));
            fail("Expected excessive compression ratio");
        } catch (IOException expected) {
            assertTrue(expected.getMessage().contains("compression"));
        }
    }

    @Test public void sourceAPKIsNeverModified() throws Exception {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("assets/index.android.bundle", hermes(84, 11));
        File apk = zipped("original.apk", entries);
        String shaBefore = ApkInspector.sha256(apk);
        ApkInspector.inspect(apk);
        assertEquals(shaBefore, ApkInspector.sha256(apk));
    }

    @Test public void unknownFileRefused() throws Exception {
        File file = temp.newFile("not-apk.apk");
        try {
            ApkInspector.inspect(file);
            fail("Expected invalid archive");
        } catch (IOException expected) {
            assertNotNull(expected.getMessage());
        }
    }

    @Test public void bigintNonemptyOnlyWarnedNotDecompiled() throws Exception {
        byte[] data = hermes(100, 1);
        ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).putInt(64, 3);
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("assets/index.android.bundle", data);
        ApkInspector.Report report = ApkInspector.inspect(zipped("bigint.apk", entries));
        assertTrue(report.warnings.stream().anyMatch(s -> s.contains("BigInt")));
        assertTrue(report.bundleDetails.get(0).contains("nonempty-unverified"));
    }
}
