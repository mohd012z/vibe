package com.vibe.hermesinspector;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.io.InputStream;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Random;

/** Native Java decoder must pass pinned genuine public Hermes fixtures. */
public class HbcAnalyzerTest {
    private byte[] fixture(int version)throws IOException {
        try(InputStream in=getClass().getResourceAsStream("/hbc"+version+".hbc")){
            if(in==null)throw new IOException("Missing real fixture HBC"+version);
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();
            byte[] chunk=new byte[65536];int n;
            while((n=in.read(chunk))!=-1)bytes.write(chunk,0,n);
            return bytes.toByteArray();
        }
    }
    private HbcAnalyzer.Result inspect(byte[] data,int version)throws IOException{
        try(InputStream defs=new FileInputStream(new File("src/main/assets/opcodes/hbc"+version+".json"))){
            return HbcAnalyzer.parse(data,defs);
        }
    }
    @Test public void genuineHbc94StringsFunctionsAndInstructions()throws Exception{
        HbcAnalyzer.Result h=inspect(fixture(94),94);
        assertEquals(94,h.version);
        assertEquals(8,h.declaredFunctions);
        assertEquals(8,h.functionsIndexed);
        assertTrue(h.declaredStrings>=30);
        assertTrue(h.strings.stream().anyMatch(s->s.contains("bonjour")));
        assertTrue(h.instructionsDecoded>=150);
        assertTrue(h.instructions.get(0).contains("DeclareGlobalVar"));
    }
    @Test public void genuineHbc99StringsFunctionsAndInstructions()throws Exception{
        HbcAnalyzer.Result h=inspect(fixture(99),99);
        assertEquals(99,h.version);
        assertEquals(8,h.declaredFunctions);
        assertTrue(h.instructionsDecoded>=300);
        assertTrue(h.instructions.get(0).contains("CreateFunctionEnvironment"));
    }
    private void assertAgainstPinnedHbcdump(int version) throws Exception {
        HbcAnalyzer.Result result=inspect(fixture(version),version);
        InputStream stream=getClass().getResourceAsStream("/hbc"+version+".official");
        if(stream==null)throw new IOException("Missing pinned official Hermes reference "+version);
        String text;
        try(InputStream input=stream) {
            text=new String(input.readAllBytes(),StandardCharsets.UTF_8);
        }
        Pattern function=Pattern.compile("^(?:NC)?Function<.*?>(\\d+)\\(");
        Pattern instruction=Pattern.compile("^\\[@\\s*(\\d+)\\]\\s+([A-Za-z][A-Za-z0-9_]*)");
        ArrayList<String> expected=new ArrayList<>();
        int fid=-1;
        for(String line:text.split("\\R")) {
            Matcher header=function.matcher(line);
            if(header.find())fid=Integer.parseInt(header.group(1));
            Matcher op=instruction.matcher(line);
            if(fid>=0 && op.find())expected.add("fn#"+fid+" +"+op.group(1)+" "+op.group(2));
        }
        ArrayList<String> actual=new ArrayList<>();
        for(String line:result.instructions) {
            String[] parts=line.split("\\s+",4);
            if(parts.length<3)throw new AssertionError("Malformed native opcode output: "+line);
            actual.add(parts[0]+" "+parts[1]+" "+parts[2]);
        }
        assertTrue("No official opcodes parsed",expected.size()>150);
        assertEquals("Native function opcode IDs and relative offsets must match official saved hbcdump",
                     expected,actual);
    }

    @Test public void nativeHbc94OpcodeOffsetsMatchOfficialHbcdump()throws Exception{
        assertAgainstPinnedHbcdump(94);
    }
    @Test public void nativeHbc99OpcodeOffsetsMatchOfficialHbcdump()throws Exception{
        assertAgainstPinnedHbcdump(99);
    }

    @Test public void genuineHbc84DecodesWithinBudget()throws Exception{
        HbcAnalyzer.Result h=inspect(fixture(84),84);
        assertEquals(84,h.version);
        assertEquals(17899,h.declaredFunctions);
        assertTrue(h.functionsIndexed>=1);
        assertTrue(h.instructionsDecoded>=1);
        assertTrue(h.instructionsDecoded<=HbcAnalyzer.MAX_OPCODES);
        assertTrue(h.truncated);
    }
    @Test public void declaredStringStorageBoundsAreEnforced()throws Exception{
        byte[] data=fixture(94);
        ByteBuffer header=ByteBuffer.wrap(data).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        int functions=header.getInt(40), kinds=header.getInt(44), identifiers=header.getInt(48);
        int stringTable=128+16*functions+4*kinds+4*identifiers;
        stringTable=(stringTable+3)&~3;
        // 8-byte UTF8 string positioned at the maximum 23-bit offset.
        header.putInt(stringTable,(8<<24)|(0x7fffff<<1));
        try{inspect(data,94);fail("Storage section escape must be rejected");}
        catch(IOException expected){
            assertTrue(expected.getMessage().contains("storage"));
        }
    }

    @Test public void modifiedHeaderVersionCannotBeReinterpreted()throws Exception{
        byte[] data=fixture(94);
        data[8]=(byte)101;
        try{inspect(data,94);fail("Unsupported HBC version accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("Unregistered"));}
    }
    @Test public void malformedStringTablePointerFailsClosed()throws Exception{
        byte[] data=fixture(94);
        data[52]=(byte)0xff;data[53]=(byte)0xff;
        try{inspect(data,94);fail("Corrupt table accepted");}
        catch(IOException expected){assertNotNull(expected.getMessage());}
    }
    @Test public void deterministicTruncationAndMutationNeverCrashes()throws Exception{
        byte[] original=fixture(94);
        for(int n=0;n<64;n++){
            byte[] copy=Arrays.copyOf(original,Math.max(12,original.length-n*27));
            try{inspect(copy,94);}
            catch(IOException rejected){ /* malformed fixtures must fail cleanly */ }
        }
        Random random=new Random(20261101);
        for(int i=0;i<128;i++){
            byte[] copy=original.clone();
            for(int j=0;j<1+random.nextInt(3);j++)
                copy[random.nextInt(copy.length)]^=1+random.nextInt(255);
            try{inspect(copy,94);}
            catch(IOException rejected){ /* rejected malformed bytecode */ }
        }
    }
}
