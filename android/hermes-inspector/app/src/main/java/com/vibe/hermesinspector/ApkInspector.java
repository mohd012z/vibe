package com.vibe.hermesinspector;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Read-only APK and Hermes metadata inventory. No user-provided bytecode is
 * executed, decompiled or altered. Candidate strings are heuristic only.
 */
public final class ApkInspector {
    public static final long MAX_APK_BYTES = 96L * 1024L * 1024L;
    public static final long MAX_ENTRY_BYTES = 48L * 1024L * 1024L;
    public static final long MAX_TOTAL_UNCOMPRESSED = 1024L * 1024L * 1024L;
    public static final int MAX_ENTRIES = 20000;
    public static final int MAX_SCAN_BYTES = 8 * 1024 * 1024;
    public static final int MAX_CANDIDATES = 2000;
    public static final long HERMES_MAGIC = 2240826417119764422L;

    private static final Set<Integer> REGISTERED = Collections.unmodifiableSet(
        new HashSet<>(Arrays.asList(59, 62, 74, 76, 83, 84, 85, 86,
              87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100)));
    private ApkInspector() {}

    public interface OpcodeProvider {
        InputStream open(int version) throws IOException;
    }
    public static boolean supportedHbc(int version) {
        return REGISTERED.contains(version);
    }

    public static final class Report {
        public final List<String> technologies = new ArrayList<>();
        public final List<String> bundleDetails = new ArrayList<>();
        public final List<String> candidates = new ArrayList<>();
        public final List<String> warnings = new ArrayList<>();
        public final List<String> dexStrings = new ArrayList<>();
        public final List<String> dexClasses = new ArrayList<>();
        public final List<String> dexMethods = new ArrayList<>();
        public final List<String> hermesStrings = new ArrayList<>();
        public final List<String> hermesFunctions = new ArrayList<>();
        public final List<String> hermesInstructions = new ArrayList<>();
        public final List<String> hermesReferences = new ArrayList<>();
        public int dexParsed, dexDeclaredClasses, dexDeclaredMethods, dexDeclaredStrings;
        public int hermesDecodedInstructions;
        public String sha256;
        public long byteSize;
        public int entries;
        public int hermesBundles;
        public long functionCount;
        public boolean sampleLimited;
    }

    public static final class Header {
        public final int version;
        public final long functionCount;
        public final long declaredSize;
        public final boolean registered;
        public final String bigIntStatus;
        Header(int version, long functionCount, long declaredSize, boolean registered, String bigIntStatus) {
            this.version = version;
            this.functionCount = functionCount;
            this.declaredSize = declaredSize;
            this.registered = registered;
            this.bigIntStatus = bigIntStatus;
        }
    }

    /**
     * May be called on the first >=44 bytes of a ZIP entry.
     * Returns null if magic is not Hermes. Invalid Hermes headers throw IOException.
     */
    public static Header parseHermesHeader(byte[] prefix) throws IOException {
        if (prefix == null || prefix.length < 12) return null;
        ByteBuffer b = ByteBuffer.wrap(prefix).order(ByteOrder.LITTLE_ENDIAN);
        if (b.getLong(0) != HERMES_MAGIC) return null;
        if (prefix.length < 44) throw new IOException("Truncated Hermes header");
        long versionLong = Integer.toUnsignedLong(b.getInt(8));
        if (versionLong == 0 || versionLong > 65535) throw new IOException("Implausible HBC version");
        int version = (int) versionLong;
        long declaredSize = Integer.toUnsignedLong(b.getInt(32));
        long functionCount = Integer.toUnsignedLong(b.getInt(40));
        if (functionCount > 1_000_000L) throw new IOException("Implausible HBC function count");
        String bigInt = "not-applicable";
        if (version >= 87 && version <= 100) {
            if (prefix.length < 72) bigInt = "incomplete-header";
            else {
                long count = Integer.toUnsignedLong(b.getInt(64));
                long storage = Integer.toUnsignedLong(b.getInt(68));
                bigInt = count > 0 || storage > 0 ? "nonempty-unverified" : "empty";
            }
        }
        return new Header(version, functionCount, declaredSize,
                REGISTERED.contains(version), bigInt);
    }

    public static Report inspect(File file) throws IOException {
        return inspect(file, null);
    }

    public static Report inspect(File file, OpcodeProvider opcodeProvider) throws IOException {
        if (file == null || !file.isFile()) throw new IOException("APK file not found");
        if (file.length() < 22 || file.length() > MAX_APK_BYTES)
            throw new IOException("APK is empty or exceeds 96 MiB");
        Report report = new Report();
        report.sha256 = sha256(file);
        report.byteSize = file.length();

        Set<String> names = new HashSet<>();
        LinkedHashSet<String> candidateStrings = new LinkedHashSet<>();
        boolean hasDex = false, hasFlutter = false, hasReactNative = false;
        long totalDexBytes = 0;
        long declaredTotal = 0L;

        try (ZipFile zip = new ZipFile(file)) {
            Enumeration<? extends ZipEntry> members = zip.entries();
            while (members.hasMoreElements()) {
                if (Thread.currentThread().isInterrupted()) throw new IOException("Analysis cancelled");
                ZipEntry entry = members.nextElement();
                report.entries++;
                if (report.entries > MAX_ENTRIES) throw new IOException("ZIP has too many members");
                String name = entry.getName();
                if (!isSafeZipName(name)) throw new IOException("Unsafe ZIP member path");
                if (!names.add(name)) throw new IOException("Duplicate ZIP member name");
                if (entry.isDirectory()) continue;
                long size = entry.getSize();
                long compressed = entry.getCompressedSize();
                if (size < 0 || compressed < 0) throw new IOException("Unknown ZIP member size");
                if (size > MAX_TOTAL_UNCOMPRESSED ||
                    declaredTotal > MAX_TOTAL_UNCOMPRESSED - size)
                    throw new IOException("ZIP uncompressed size exceeds limit");
                declaredTotal += size;
                if (size > 1024L * 1024L &&
                        (compressed == 0 || (compressed > 0 && size / compressed > 200)))
                    throw new IOException("Excessive ZIP compression ratio");

                String lower = name.toLowerCase(Locale.ROOT);
                if (lower.matches("classes[0-9]*\\.dex")) {
                    hasDex = true;
                    if(size > 0 && size <= DexAnalyzer.MAX_DEX_BYTES &&
                       totalDexBytes + size <= 64L * 1024L * 1024L) {
                        totalDexBytes += size;
                        try (InputStream stream = zip.getInputStream(entry)) {
                            byte[] data = readDexBytes(stream, (int)size);
                            DexAnalyzer.Result dex = DexAnalyzer.inspect(data);
                            report.dexParsed++;
                            report.dexDeclaredClasses += dex.declaredClasses;
                            report.dexDeclaredMethods += dex.declaredMethods;
                            report.dexDeclaredStrings += dex.declaredStrings;
                            appendCapped(report.dexStrings,dex.strings,6000);
                            appendCapped(report.dexClasses,dex.classNames,3000);
                            appendCapped(report.dexMethods,dex.methodReferences,4000);
                            report.warnings.addAll(dex.issues);
                        } catch(IOException | RuntimeException invalid) {
                            report.warnings.add(name+": DEX index rejected: "+safeReason(invalid));
                        }
                    } else {
                        report.warnings.add(name+": DEX indexing skipped because it exceeds memory limits");
                    }
                }
                if (lower.endsWith("/libflutter.so") || lower.endsWith("/libapp.so")
                        || lower.startsWith("assets/flutter_assets/")) hasFlutter = true;
                if (lower.startsWith("assets/") &&
                        (lower.endsWith(".bundle") || lower.equals("assets/index.android.bundle")))
                    hasReactNative = true;
                if (!(lower.endsWith(".bundle") || lower.endsWith(".hbc"))) continue;

                if (size > MAX_ENTRY_BYTES) {
                    report.warnings.add(name + " exceeds 48 MiB analysis limit");
                    continue;
                }
                byte[] sample;
                try (InputStream stream = zip.getInputStream(entry)) {
                    sample = readPrefix(stream, (int) Math.min(size, MAX_SCAN_BYTES));
                } catch (RuntimeException error) {
                    throw new IOException("Malformed compressed Hermes candidate", error);
                }
                if (sample.length < 12) continue;
                Header header;
                try {
                    header = parseHermesHeader(sample);
                } catch (IOException invalid) {
                    report.warnings.add(name + ": " + invalid.getMessage());
                    continue;
                }
                if (header == null) continue;

                report.hermesBundles++;
                report.functionCount += header.functionCount;
                report.bundleDetails.add(name + " • HBC " + header.version +
                    " • functions " + header.functionCount +
                    " • version registered " + (header.registered ? "yes" : "no") +
                    " • BigInt " + header.bigIntStatus);
                if (header.declaredSize != 0 && header.declaredSize != size)
                    report.warnings.add(name + ": header file length differs from ZIP size");
                if ("nonempty-unverified".equals(header.bigIntStatus))
                    report.warnings.add(name + ": nonempty BigInt table; no full parser validation");
                if (size > MAX_SCAN_BYTES) report.sampleLimited = true;
                addAsciiCandidates(sample, candidateStrings);
                addUtf16Candidates(sample, candidateStrings);
                if(opcodeProvider!=null && sample.length >= 128 && supportedHbc(header.version)
                        && sample.length == size) {
                    try (InputStream schema = opcodeProvider.open(header.version)) {
                        HbcAnalyzer.Result hbc = HbcAnalyzer.parse(sample,schema);
                        appendCapped(report.hermesStrings,hbc.strings,6000);
                        appendCapped(report.hermesFunctions,hbc.functions,3000);
                        appendCapped(report.hermesInstructions,hbc.instructions,6000);
                        appendCapped(report.hermesReferences,hbc.references,3000);
                        report.hermesDecodedInstructions += hbc.instructionsDecoded;
                        report.warnings.addAll(hbc.warnings);
                    } catch(IOException | RuntimeException invalid) {
                        report.warnings.add(name+": full HBC index unavailable: "+safeReason(invalid));
                    }
                } else if(opcodeProvider!=null && sample.length<size && header.registered) {
                    report.warnings.add(name+": HBC bytecode exceeds 8 MiB sample window; full disassembly skipped");
                }
            }
        } catch (IOException invalid) {
            throw new IOException("APK inspection refused: " + invalid.getMessage(), invalid);
        }
        if (hasDex) report.technologies.add("DEX");
        if (hasFlutter) report.technologies.add("Flutter");
        if (hasReactNative || report.hermesBundles > 0) report.technologies.add("React Native");
        if (report.hermesBundles > 0) report.technologies.add("Hermes");
        report.candidates.addAll(candidateStrings);
        if (report.technologies.isEmpty()) report.technologies.add("Unknown APK technology");
        if (report.hermesBundles == 0)
            report.warnings.add("No confirmed Hermes magic found in candidate bundle entries");
        if(report.dexParsed==0 && hasDex)
            report.warnings.add("DEX detected, but no complete class/string index was available under scan limits.");
        if(report.hermesBundles==0)
            report.warnings.add("This APK has DEX bytecode, not Hermes. Select DEX strings/classes/methods to search.");
        report.warnings.add("Printable byte sequences are heuristics, separate from verified HBC/DEX string tables.");
        report.warnings.add("Decoded Hermes instructions show bytecode opcodes, not reconstructed JavaScript.");
        report.warnings.add("DEX method references do not prove executable method bodies or call relationships.");
        if (report.sampleLimited)
            report.warnings.add("Large bundle: inspected first 8 MiB only for string candidates.");
        return report;
    }

    private static String safeReason(Throwable error) {
        String message=error.getMessage();
        if(message==null)return "malformed or unsupported data";
        return message.length()>160?message.substring(0,160):message;
    }
    private static void appendCapped(List<String> to,List<String> from,int limit) {
        for(String item:from){
            if(to.size()>=limit)break;
            to.add(item);
        }
    }
    private static byte[] readDexBytes(InputStream input,int size)throws IOException {
        if(size<=0||size>DexAnalyzer.MAX_DEX_BYTES)throw new IOException("DEX input too large");
        byte[] data=new byte[size];
        int p=0;
        while(p<data.length){
            if(Thread.currentThread().isInterrupted())throw new IOException("DEX decoding cancelled");
            int n=input.read(data,p,Math.min(65536,data.length-p));
            if(n<0)throw new IOException("Truncated DEX stream");
            if(n==0)continue;
            p+=n;
        }
        return data;
    }

    private static boolean isSafeZipName(String name) {
        if (name == null || name.isEmpty() || name.startsWith("/") || name.indexOf('\\') >= 0 ||
                name.indexOf('\0') >= 0) return false;
        String[] parts = name.split("/", -1);
        for (String part : parts) if (part.equals("..") || part.equals(".")) return false;
        return true;
    }

    private static byte[] readPrefix(InputStream input, int limit) throws IOException {
        if (limit < 0 || limit > MAX_SCAN_BYTES) throw new IOException("Invalid scan length");
        byte[] data = new byte[limit];
        int pos = 0;
        while (pos < limit) {
            if (Thread.currentThread().isInterrupted()) throw new IOException("Analysis cancelled");
            int n = input.read(data, pos, Math.min(65536, limit - pos));
            if (n < 0) break;
            if (n == 0) continue;
            pos += n;
        }
        return pos == limit ? data : Arrays.copyOf(data, pos);
    }

    private static void addAsciiCandidates(byte[] raw, Set<String> out) {
        StringBuilder run = new StringBuilder(140);
        for (byte value : raw) {
            if (out.size() >= MAX_CANDIDATES) return;
            int ch = value & 0xff;
            if (ch >= 32 && ch <= 126) {
                if (run.length() < 140) run.append((char)ch);
            } else {
                store(run, out);
                run.setLength(0);
            }
        }
        store(run, out);
    }

    private static void addUtf16Candidates(byte[] raw, Set<String> out) {
        for (int parity = 0; parity <= 1; parity++) {
            StringBuilder run = new StringBuilder(140);
            for (int pos = parity; pos + 1 < raw.length; pos += 2) {
                if (out.size() >= MAX_CANDIDATES) return;
                int ch = raw[pos] & 0xff;
                int upper = raw[pos + 1] & 0xff;
                if (upper == 0 && ch >= 32 && ch <= 126) {
                    if (run.length() < 140) run.append((char)ch);
                } else {
                    store(run, out);
                    run.setLength(0);
                }
            }
            store(run, out);
        }
    }

    private static void store(StringBuilder run, Set<String> out) {
        if (run.length() < 5 || out.size() >= MAX_CANDIDATES) return;
        String text = run.toString().trim();
        if (text.length() < 5) return;
        boolean hasLetter = false;
        for (int i = 0; i < text.length(); i++)
            if (Character.isLetterOrDigit(text.charAt(i))) {
                hasLetter = true;
                break;
            }
        if (hasLetter) out.add(text);
    }

    public static String sha256(File file) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = new java.io.FileInputStream(file)) {
                byte[] buffer = new byte[65536];
                int read;
                while ((read = input.read(buffer)) != -1) digest.update(buffer, 0, read);
            }
            StringBuilder result = new StringBuilder();
            for (byte b : digest.digest()) result.append(String.format(Locale.ROOT,"%02x", b & 0xff));
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IOException("SHA-256 unavailable", impossible);
        }
    }
}
