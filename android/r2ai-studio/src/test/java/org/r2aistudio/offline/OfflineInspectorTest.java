package org.r2aistudio.offline;
import java.nio.charset.StandardCharsets;
public final class OfflineInspectorTest {
    static void check(boolean x) { if(!x) throw new AssertionError(); }
    public static void main(String[] args) {
        check(OfflineInspector.inspect(new byte[]{0x7f,'E','L','F'}).format.equals("ELF"));
        check(OfflineInspector.inspect(new byte[]{'d','e','x',10}).format.equals("DEX"));
        check(OfflineInspector.inspect(new byte[]{'P','K',3,4}).format.equals("ZIP/APK candidate"));
        check(OfflineInspector.inspect(new byte[]{'M','Z'}).format.equals("PE/MZ candidate"));
        OfflineInspector.Report report=OfflineInspector.inspect("hello world\u0000other".getBytes(StandardCharsets.UTF_8));
        check(report.strings.size()==2);
        check(report.strings.get(0).equals("hello world"));
        try {OfflineInspector.inspect(new byte[OfflineInspector.MAX_INPUT_BYTES+1]);throw new AssertionError();}
        catch(IllegalArgumentException expected){}
        System.out.println("PASS: signatures, strings, 8 MiB bound");
    }
}
