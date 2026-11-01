package com.vibe.hermesinspector;

import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;
import static org.junit.Assert.*;

public class SourceAdvancedTest {
    @Rule public TemporaryFolder dir=new TemporaryFolder();

    private File apk(Map<String,byte[]> members)throws Exception{
        File path=dir.newFile("source-"+System.nanoTime()+".apk");
        try(ZipOutputStream z=new ZipOutputStream(new FileOutputStream(path))){
            for(Map.Entry<String,byte[]> x:members.entrySet()){
                z.putNextEntry(new ZipEntry(x.getKey()));
                z.write(x.getValue());
                z.closeEntry();
            }
        }
        return path;
    }

    @Test public void binaryManifestStringPoolAndTagsDecode()throws Exception{
        // Compiled XML with a genuine structural string pool and empty manifest tag.
        byte[] data=new byte[112];
        ByteBuffer b=ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        b.putShort(0,(short)3);b.putShort(2,(short)8);b.putInt(4,data.length);
        b.putShort(8,(short)1);b.putShort(10,(short)28);b.putInt(12,44);
        b.putInt(16,1);b.putInt(20,0);b.putInt(24,0x100);b.putInt(28,32);
        b.putInt(32,0);b.putInt(36,0);
        data[40]=8;data[41]=8;
        byte[] name="manifest".getBytes(StandardCharsets.UTF_8);
        System.arraycopy(name,0,data,42,name.length);
        int start=52;
        b.putShort(start,(short)0x102);b.putShort(start+2,(short)16);b.putInt(start+4,36);
        b.putInt(start+20,0);
        b.putShort(start+24,(short)20);b.putShort(start+26,(short)20);
        b.putShort(start+28,(short)0);
        int end=88;
        b.putShort(end,(short)0x103);b.putShort(end+2,(short)16);b.putInt(end+4,24);
        b.putInt(end+20,0);
        String decoded=BinaryResourceViewer.manifest(data);
        assertTrue(decoded,decoded.contains("<manifest>"));
        assertTrue(decoded,decoded.contains("</manifest>"));
    }

    @Test public void malformedAndroidXmlCannotAllocateHugePool()throws Exception{
        byte[] data=new byte[64];
        ByteBuffer b=ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        b.putShort(0,(short)3);b.putShort(2,(short)8);b.putInt(4,data.length);
        b.putShort(8,(short)1);b.putShort(10,(short)28);b.putInt(12,56);
        b.putInt(16,Integer.MAX_VALUE);
        try{BinaryResourceViewer.manifest(data);fail("String pool budget bypassed");}
        catch(IOException expected){assertNotNull(expected.getMessage());}
    }

    @Test public void elfReportsActualArchitecture()throws Exception{
        byte[] data=new byte[64];data[0]=0x7f;data[1]='E';data[2]='L';data[3]='F';
        data[4]=2;data[5]=1;data[18]=(byte)183;
        String text=BinaryResourceViewer.elf(data,"lib/arm64-v8a/libdemo.so",4096);
        assertTrue(text.contains("AArch64"));
        assertTrue(text.contains("64-bit"));
        assertTrue(text.contains("not contain original"));
        data[1]=0;
        try{BinaryResourceViewer.elf(data,"lib.so",4096);fail("Invalid ELF magic accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("ELF"));}
    }

    @Test public void binaryResourceHeaderAndSizeValidation()throws Exception{
        byte[] arsc=new byte[12];
        ByteBuffer b=ByteBuffer.wrap(arsc).order(ByteOrder.LITTLE_ENDIAN);
        b.putShort(0,(short)2);b.putShort(2,(short)12);b.putInt(4,12);
        b.putInt(8,1);
        assertTrue(BinaryResourceViewer.resourceTable(arsc,12).contains("resource packages: 1"));
        try{BinaryResourceViewer.resourceTable(arsc,16);fail("Wrong length accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("length"));}
    }

    @Test public void multiFileZipExportUsesReadOnlyActualSources()throws Exception{
        Map<String,byte[]> members=new LinkedHashMap<>();
        members.put("assets/hello.js","const answer=42;\n".getBytes(StandardCharsets.UTF_8));
        members.put("assets/labels.json","{\"label\":\"café\"}".getBytes(StandardCharsets.UTF_8));
        File path=apk(members);
        String originalHash=ApkInspector.sha256(path);
        ApkSourceExplorer.Result index=ApkSourceExplorer.index(path);
        byte[] data=SourceBundleExporter.create(path,index.entries,DexViewModes.MODE_BYTECODE);
        int found=0;
        try(ZipInputStream input=new ZipInputStream(new ByteArrayInputStream(data))){
            ZipEntry next;
            while((next=input.getNextEntry())!=null){
                assertFalse(next.getName().contains("../"));
                found++;
                if(next.getName().equals("README.txt")){
                    String manifest=new String(input.readAllBytes(),StandardCharsets.UTF_8);
                    assertTrue(manifest.contains(originalHash));
                    assertTrue(manifest.contains("not original"));
                }
            }
        }
        assertEquals(3,found);
        assertEquals(originalHash,ApkInspector.sha256(path));
    }
    @Test public void exportRefusesExcessItemsAndEmptyList()throws Exception{
        File path=apk(Collections.singletonMap("assets/a.txt",new byte[]{65}));
        ApkSourceExplorer.Entry e=new ApkSourceExplorer.Entry("file","assets/a.txt",null,"a");
        List<ApkSourceExplorer.Entry> huge=new ArrayList<>();
        for(int i=0;i<26;i++)huge.add(e);
        try{SourceBundleExporter.create(path,huge,0);fail("26 sources accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("1–25"));}
        try{SourceBundleExporter.create(path,Collections.emptyList(),0);fail("Empty accepted");}
        catch(IOException expected){assertNotNull(expected.getMessage());}
    }
    @Test public void compressedBombRejectedBySourceIndex()throws Exception{
        File path=apk(Collections.singletonMap("assets/bomb.txt",new byte[3_000_000]));
        try{ApkSourceExplorer.index(path);fail("Compressed bomb indexed");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("compression"));}
    }
}
