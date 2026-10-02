import java.nio.file.*;
import java.util.*;
import org.jetbrains.kotlin.metadata.jvm.deserialization.BitEncoding;

// Differential oracle for the 8-to-7 / UTF-8 BitEncoding modes.
//
// The 8-to-7 mode is selected the AUTHORITATIVE way: the test launches
// this helper with -Dkotlin.jvm.serialization.use8to7=true, which the
// compiler's BitEncoding static initializer reads into
// FORCE_8TO7_ENCODING at class-load. We do NOT flip the field by hand.
//
// For each hex byte case it runs the Kotlin compiler's OWN
// BitEncoding.encodeBytes (in the requested mode) and BitEncoding.decodeBytes,
// printing one line:
//     CASE <idx> RT<1|0> D1=<encoded, parts concatenated,
//                          control/non-ASCII/space as backslash-u hex> DECH=<decode hex>
// D1 is exactly the string @Metadata.d1 would carry (single part, or
// multi-part concatenated with the mode marker on the first part).
// DECH is the compiler's own decode of the same D1 — the oracle.
//
// The Python differential (tools/vibebot_test.py) feeds the SAME D1 to
// kotlinmeta.bitencoding_decode and asserts byte-for-byte equality with
// DECH. That is a real-compiler check of the decode path, including the
// no-marker 8-to-7 case (the common small payload) and the \uFFFF
// multi-part marker, which a hand-rolled port is easy to get wrong.
// RT0 cases are the compiler's own known lossy 8-to-7 (a lone high byte);
// we still require my decode == the compiler's decode, not the original.
public class BE8to7 {
    public static void main(String[] args) throws Exception {
        for (int idx = 0; idx < args.length; idx++) {
            byte[] data;
            if (args[idx].startsWith("BIG:")) {
                // Synthesize a large case in-process (argv can't carry
                // 140KB+). Deterministic PRNG; length chosen so the
                // encoded output splits into 2 strings (>= ~65533
                // effective bytes), which makes splitBytesToStringArray
                // prefix the \uFFFF mode marker on the first part.
                int n = Integer.parseInt(args[idx].substring(4));
                java.util.Random r = new java.util.Random(0x5EED8207L);
                data = new byte[n];
                for (int i = 0; i < n; i++) data[i] = (byte) r.nextInt(256);
            } else {
                data = hexToBytes(args[idx]);
            }
            String[] enc = BitEncoding.encodeBytes(data);
            byte[] dec = BitEncoding.decodeBytes(enc.clone());
            String d1 = String.join("", enc);
            StringBuilder line = new StringBuilder("CASE " + idx);
            line.append(" RT").append(Arrays.equals(data, dec) ? "1" : "0");
            // d1 is emitted as a 2-byte-per-char hex string: fully
            // unambiguous (a raw char-escape breaks when the data itself
            // contains 0x5C '\'). d1 chars are 0..65535 (a Java char), so
            // hex(char) is lossless.
            StringBuilder dh = new StringBuilder();
            for (int i = 0; i < d1.length(); i++)
                dh.append(String.format("%04x", (int) d1.charAt(i)));
            line.append(" D1H=").append(dh);
            line.append(" DECH=").append(bytesToHex(dec));
            System.out.println(line);
        }
    }

    static byte[] hexToBytes(String h) {
        int n = h.length();
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2)
            out[i / 2] = (byte) Integer.parseInt(h.substring(i, i + 2), 16);
        return out;
    }

    static String bytesToHex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }
}
