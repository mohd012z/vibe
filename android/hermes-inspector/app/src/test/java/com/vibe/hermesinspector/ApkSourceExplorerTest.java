package com.vibe.hermesinspector;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import static org.junit.Assert.*;

public class ApkSourceExplorerTest {
    @Rule public TemporaryFolder tmp=new TemporaryFolder();

    private File zip(Map<String,byte[]> contents)throws IOException {
        File path=tmp.newFile("fixture-"+System.nanoTime()+".apk");
        try(ZipOutputStream out=new ZipOutputStream(new FileOutputStream(path))){
            for(Map.Entry<String,byte[]> member:contents.entrySet()){
                out.putNextEntry(new ZipEntry(member.getKey()));
                out.write(member.getValue());
                out.closeEntry();
            }
        }
        return path;
    }
    private static Map<String,byte[]> entries(){
        Map<String,byte[]> map=new LinkedHashMap<>();
        map.put("assets/app.js","function hello() { return 42; }\n".getBytes(StandardCharsets.UTF_8));
        map.put("assets/data.json","{\"title\":\"café\"}".getBytes(StandardCharsets.UTF_8));
        map.put("res/raw/photo.png",new byte[]{(byte)0x89,'P','N','G'});
        return map;
    }

    @Test public void textAndBinaryIndexDisplay(){
        try{
            File apk=zip(entries());
            String hash=ApkInspector.sha256(apk);
            ApkSourceExplorer.Result listing=ApkSourceExplorer.index(apk);
            assertEquals(3,listing.entries.size());
            assertEquals(0,listing.dexFiles);
            assertEquals(0,listing.totalDexClasses);
            String first=ApkSourceExplorer.open(apk,listing.entries.get(0));
            assertTrue(first.contains("return 42"));
            String second=ApkSourceExplorer.open(apk,listing.entries.get(1));
            assertTrue(second.contains("café"));
            String third=ApkSourceExplorer.open(apk,listing.entries.get(2));
            assertTrue(third.contains("Binary"));
            assertEquals(hash,ApkInspector.sha256(apk));
        }catch(IOException e){throw new AssertionError(e);}
    }
    @Test public void traversalRejected(){
        try{
            Map<String,byte[]> data=new LinkedHashMap<>();
            data.put("../assets/app.js",new byte[]{1,2,3});
            ApkSourceExplorer.index(zip(data));
            fail("Traversal should be refused");
        }catch(IOException expected){assertTrue(expected.getMessage().contains("Unsafe"));}
    }
    @Test public void truncatedUtf8TextRefused(){
        try{
            Map<String,byte[]> data=new LinkedHashMap<>();
            data.put("assets/bad.js",new byte[]{(byte)0xc3,(byte)0x28});
            File apk=zip(data);
            ApkSourceExplorer.open(apk,ApkSourceExplorer.index(apk).entries.get(0));
            fail("Unpaired UTF8 accepted as text");
        }catch(IOException expected){assertTrue(expected.getMessage().contains("UTF-8"));}
    }
    @Test public void oversizedPackagedSourceRefused(){
        try{
            Map<String,byte[]> data=new LinkedHashMap<>();
            data.put("assets/larger.js",new byte[ApkSourceExplorer.MAX_TEXT+4096]);
            File apk=zip(data);
            ApkSourceExplorer.open(apk,ApkSourceExplorer.index(apk).entries.get(0));
            fail("Oversized source accepted");
        }catch(IOException expected){assertTrue(expected.getMessage().contains("limit"));}
    }
    @Test public void canBrowseRealD8DexMethodsAndRegisters()throws Exception{
        try(InputStream input=getClass().getResourceAsStream("/source-explorer-fixture.dex")){
            assertNotNull("CI must supply actual D8 DEX fixture",input);
            byte[] dex=input.readAllBytes();
            Map<String,byte[]> data=entries();
            data.put("classes.dex",dex);
            File apk=zip(data);
            ApkSourceExplorer.Result index=ApkSourceExplorer.index(apk);
            assertEquals(1,index.dexFiles);
            assertTrue(index.totalDexClasses>=1);
            ApkSourceExplorer.Entry selected=null;
            for(ApkSourceExplorer.Entry entry:index.entries){
                if("class".equals(entry.kind) &&
                   entry.classDescriptor.equals("Lcom/vibe/fixture/Greeter;")){
                    selected=entry;break;
                }
            }
            assertNotNull("Expected fixture class indexed",selected);
            String view=ApkSourceExplorer.open(apk,selected);
            assertTrue(view.contains(".class Lcom/vibe/fixture/Greeter;"));
            assertTrue(view.contains(".method greeting("));
            assertTrue(view.contains(".registers"));
            assertTrue(view.contains(".end method"));
            assertTrue(view.contains("return"));
            assertTrue(view.contains("const-string"));
            assertTrue(view.contains("not compilable original source"));
        }
    }
}
