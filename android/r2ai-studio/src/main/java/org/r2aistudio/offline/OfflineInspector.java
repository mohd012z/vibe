package org.r2aistudio.offline;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/** Deterministic, offline, read-only binary inspection; no API/network/native runtime. */
public final class OfflineInspector {
    public static final int MAX_INPUT_BYTES = 8 * 1024 * 1024;
    public static final int MAX_STRINGS = 1000;
    public static final int MAX_STRING_CHARS = 256;
    private OfflineInspector() {}

    public static final class Report {
        public final String format;
        public final int bytes;
        public final List<String> strings;
        public final List<String> warnings;
        Report(String format, int bytes, List<String> strings, List<String> warnings) {
            this.format = format;
            this.bytes = bytes;
            this.strings = Collections.unmodifiableList(new ArrayList<>(strings));
            this.warnings = Collections.unmodifiableList(new ArrayList<>(warnings));
        }
        public String asText() {
            StringBuilder b = new StringBuilder("Offline inspection\nFormat: ")
                .append(format).append("\nBytes: ").append(bytes)
                .append("\nStrings: ").append(strings.size()).append('\n');
            for (String s : strings) b.append(s).append('\n');
            for (String w : warnings) b.append("Warning: ").append(w).append('\n');
            return b.toString();
        }
    }

    public static Report inspect(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        if (bytes.length > MAX_INPUT_BYTES)
            throw new IllegalArgumentException("input exceeds 8 MiB inspection limit");
        List<String> warnings = new ArrayList<>();
        String format = detect(bytes);
        if ("Unknown".equals(format)) warnings.add("Unrecognized file signature; no executable parsing attempted");
        List<String> strings = new ArrayList<>();
        StringBuilder run = new StringBuilder();
        boolean truncated = false;
        for (int i = 0; i < bytes.length; i++) {
            int c = bytes[i] & 255;
            if (c >= 32 && c <= 126) {
                if (run.length() < MAX_STRING_CHARS) run.append((char)c);
                else truncated = true;
            } else {
                if (run.length() >= 4) {
                    if (strings.size() >= MAX_STRINGS) {
                        warnings.add("String result cap reached");
                        return new Report(format, bytes.length, strings, warnings);
                    }
                    strings.add(run.toString() + (truncated ? "…" : ""));
                }
                run.setLength(0);
                truncated = false;
            }
        }
        if (run.length() >= 4) {
            if (strings.size() < MAX_STRINGS) strings.add(run.toString() + (truncated ? "…" : ""));
            else warnings.add("String result cap reached");
        }
        return new Report(format, bytes.length, strings, warnings);
    }

    private static boolean prefix(byte[] b, int... magic) {
        if (b.length < magic.length) return false;
        for (int i=0;i<magic.length;i++) if ((b[i]&255)!=magic[i]) return false;
        return true;
    }
    private static String detect(byte[] b) {
        if (prefix(b,0x7f,0x45,0x4c,0x46)) return "ELF";
        if (prefix(b,0x64,0x65,0x78,0x0a)) return "DEX";
        if (prefix(b,0x50,0x4b,0x03,0x04)) return "ZIP/APK candidate";
        if (prefix(b,0x4d,0x5a)) return "PE/MZ candidate";
        if (prefix(b,0xca,0xfe,0xba,0xbe)) return "Java class / Mach-O fat candidate";
        if (prefix(b,0xcf,0xfa,0xed,0xfe) || prefix(b,0xfe,0xed,0xfa,0xcf)
            || prefix(b,0xce,0xfa,0xed,0xfe) || prefix(b,0xfe,0xed,0xfa,0xce)) return "Mach-O candidate";
        return "Unknown";
    }
}
