package org.r2aistudio.offline;
import java.io.*;
import java.util.Arrays;
import java.util.concurrent.CancellationException;
public final class BoundedReaderTest {
    private static void check(boolean value) { if(!value) throw new AssertionError(); }
    public static void main(String[] args) throws Exception {
        byte[] payload = new byte[100]; Arrays.fill(payload,(byte)65);
        check(Arrays.equals(payload,BoundedReader.read(new ByteArrayInputStream(payload),100,()->false)));
        try { BoundedReader.read(new ByteArrayInputStream(payload),99,()->false); throw new AssertionError(); }
        catch(IOException expected) { check(expected.getMessage().contains("limit")); }
        try { BoundedReader.read(new ByteArrayInputStream(payload),100,()->true); throw new AssertionError(); }
        catch(CancellationException expected) {}
        try { BoundedReader.read(new ByteArrayInputStream(payload),0,()->false); throw new AssertionError(); }
        catch(IllegalArgumentException expected) {}
        InputStream zeroOnce = new ByteArrayInputStream(payload) {
            boolean first=true;
            @Override public synchronized int read(byte[] b,int off,int len) {
                if(first){first=false;return 0;}
                return super.read(b,off,len);
            }
        };
        check(Arrays.equals(payload,BoundedReader.read(zeroOnce,100,()->false)));
        check(BoundedReader.read(new ByteArrayInputStream(new byte[0]),100,()->false).length==0);
        System.out.println("PASS: bounded reader exact limit, overflow, cancellation, zero-read, empty input");
    }
}
