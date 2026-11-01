package com.vibe.hermesinspector;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/** Negative and valid DEX structure fixtures; no target execution. */
public class DexAnalyzerTest {
    private byte[] fixture() {
        byte[] b=new byte[272];
        ByteBuffer out=ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
        b[0]='d';b[1]='e';b[2]='x';b[3]='\n';
        b[4]='0';b[5]='3';b[6]='9';b[7]=0;
        out.putInt(32,b.length);out.putInt(36,112);out.putInt(40,0x12345678);
        // Strings 0: Lcom/test/Demo; 1: myMethod 2: hello-world
        out.putInt(56,3);out.putInt(60,112);
        out.putInt(64,1);out.putInt(68,124);
        out.putInt(88,1);out.putInt(92,128);
        out.putInt(96,1);out.putInt(100,136);
        out.putInt(112,168);out.putInt(116,188);out.putInt(120,204);
        out.putInt(124,0);
        out.putShort(128,(short)0);out.putShort(130,(short)0);out.putInt(132,1);
        out.putInt(136,0);
        putString(b,168,"Lcom/test/Demo;");
        putString(b,188,"myMethod");
        putString(b,204,"hello-world");
        return b;
    }
    private void putString(byte[] data,int offset,String value){
        byte[] bytes=value.getBytes(StandardCharsets.UTF_8);
        data[offset]=(byte)bytes.length;
        System.arraycopy(bytes,0,data,offset+1,bytes.length);
        data[offset+1+bytes.length]=0;
    }
    @Test public void indexesRealDexTables(){
        DexAnalyzer.Result d;
        try{d=DexAnalyzer.inspect(fixture());}catch(IOException x){throw new AssertionError(x);}
        assertEquals(3,d.declaredStrings);
        assertEquals(1,d.declaredClasses);
        assertEquals(1,d.declaredMethods);
        assertTrue(d.classNames.get(0).contains("Demo"));
        assertTrue(d.methodReferences.get(0).contains("myMethod"));
        assertTrue(d.strings.stream().anyMatch(s->s.contains("hello-world")));
    }
    @Test public void modifiedUtf8Nul(){
        byte[] string={(byte)1,(byte)0xc0,(byte)0x80,0};
        try{
            assertEquals("\0",DexAnalyzer.stringAt(string,1));
            fail("Offset 1 points at encoded characters not ULEB header");
        }catch(IOException expected){
            assertNotNull(expected.getMessage());
        }
        byte[] padded={(byte)0,(byte)1,(byte)0xc0,(byte)0x80,0};
        try{assertEquals("\0",DexAnalyzer.stringAt(padded,1));}catch(IOException e){throw new AssertionError(e);}
    }
    @Test public void rejectsMismatchedSize(){
        byte[] bytes=fixture();bytes[32]=0;
        try{DexAnalyzer.inspect(bytes);fail("Invalid DEX length accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("length"));}
    }
    @Test public void rejectsMissingStringReference(){
        byte[] bytes=fixture();
        // String ID 2 is not referenced by a class or method, but must
        // still be validated before the DEX is accepted.
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(120,90000);
        try{DexAnalyzer.inspect(bytes);fail("Invalid string pointer accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("string-data offset"));}
    }
    @Test public void rejectsZeroStringPointer(){
        byte[] bytes=fixture();
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(120,0);
        try{DexAnalyzer.inspect(bytes);fail("Null string pointer accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("string-data offset"));}
    }
    @Test public void rejectsHugeTableCounts(){
        byte[] bytes=fixture();
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(56,0x7fffffff);
        try{DexAnalyzer.inspect(bytes);fail("Too many table rows");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("limit"));}
    }
    @Test public void rejectsInvalidEndian(){
        byte[] bytes=fixture();bytes[40]=(byte)0xff;
        try{DexAnalyzer.inspect(bytes);fail("Endian spoof");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("byte order"));}
    }
}
