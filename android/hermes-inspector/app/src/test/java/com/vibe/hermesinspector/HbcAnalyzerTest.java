package com.vibe.hermesinspector;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
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
    @Test public void genuineHbc84DecodesWithinBudget()throws Exception{
        HbcAnalyzer.Result h=inspect(fixture(84),84);
        assertEquals(84,h.version);
        assertEquals(17899,h.declaredFunctions);
        assertTrue(h.functionsIndexed>=1);
        assertTrue(h.instructionsDecoded>=1);
        assertTrue(h.instructionsDecoded<=HbcAnalyzer.MAX_OPCODES);
        assertTrue(h.truncated);
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
