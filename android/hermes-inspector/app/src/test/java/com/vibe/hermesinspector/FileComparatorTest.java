package com.vibe.hermesinspector;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.*;

public class FileComparatorTest {
    @Rule public TemporaryFolder tmp=new TemporaryFolder();

    private File file(String name,byte[] bytes)throws IOException{
        File f=tmp.newFile(name);
        try(FileOutputStream out=new FileOutputStream(f)){out.write(bytes);}
        return f;
    }
    private File archive(String name,Map<String,byte[]> items)throws IOException{
        File f=tmp.newFile(name);
        try(ZipOutputStream out=new ZipOutputStream(new FileOutputStream(f))){
            for(Map.Entry<String,byte[]> entry:items.entrySet()){
                out.putNextEntry(new ZipEntry(entry.getKey()));
                out.write(entry.getValue());
                out.closeEntry();
            }
        }
        return f;
    }
    private static Map<String,byte[]> records(String a,String b){
        Map<String,byte[]> data=new LinkedHashMap<>();
        data.put("assets/example.js",a.getBytes(StandardCharsets.UTF_8));
        data.put("res/raw/name.txt",b.getBytes(StandardCharsets.UTF_8));
        return data;
    }

    @Test public void sameUtf8FilesHaveIdenticalShaAndNoDifferences()throws Exception{
        File a=file("left.txt","hello\ncafé ☕\n".getBytes(StandardCharsets.UTF_8));
        File b=file("right.txt","hello\ncafé ☕\n".getBytes(StandardCharsets.UTF_8));
        FileComparator.Result comparison=FileComparator.compare(a,b);
        assertTrue(comparison.identical);
        assertTrue(comparison.bothText);
        assertEquals(comparison.leftHash,comparison.rightHash);
        assertTrue(comparison.detail.contains("No line differences"));
        assertEquals(a.length(),comparison.leftBytes);
    }
    @Test public void textDifferencesShowOriginalAndChangedLines()throws Exception{
        File a=file("a.txt","alpha\npremium\nend\n".getBytes(StandardCharsets.UTF_8));
        File b=file("b.txt","alpha\nstandard\nend\n".getBytes(StandardCharsets.UTF_8));
        FileComparator.Result report=FileComparator.compare(a,b);
        assertFalse(report.identical);
        assertTrue(report.bothText);
        assertTrue(report.detail.contains("- premium"));
        assertTrue(report.detail.contains("+ standard"));
        assertTrue(report.detail.contains("@ line 2"));
    }
    @Test public void binaryFilesUseHashNotUntrustedText()throws Exception{
        File a=file("one.bin",new byte[]{1,0,3,4});
        File b=file("two.bin",new byte[]{1,0,3,5});
        FileComparator.Result result=FileComparator.compare(a,b);
        assertFalse(result.identical);
        assertFalse(result.bothText);
        assertTrue(result.detail.contains("Binary/large"));
    }
    @Test public void utf8PreviewRejectsMalformationWithoutCrashing()throws Exception{
        File f=file("broken.txt",new byte[]{(byte)0xc3,(byte)0x28});
        assertTrue(FileComparator.preview(f).contains("Binary or non-UTF-8"));
    }
    @Test public void shaWorksWithLargeInputWithoutLoadingAllToMemory()throws Exception{
        File f=file("large.bin",new byte[2*1024*1024]);
        assertEquals(64,FileComparator.sha256(f).length());
        assertTrue(FileComparator.preview(f).contains("larger than 256 KiB"));
    }
    @Test public void apkInventoriesIdentifyAddedRemovedAndChangedMembers()throws Exception{
        Map<String,byte[]> left=records("first","same");
        Map<String,byte[]> right=records("second","same");
        right.put("assets/new.txt","new".getBytes(StandardCharsets.UTF_8));
        File a=archive("one.apk",left);
        File b=archive("two.apk",right);
        String before=FileComparator.sha256(a);
        String diff=FileComparator.zipDifferences(a,b);
        assertTrue(diff.contains("~ changed: assets/example.js"));
        assertTrue(diff.contains("+ only right: assets/new.txt"));
        assertTrue(diff.contains("matching ZIP CRC is not cryptographic proof"));
        assertEquals(before,FileComparator.sha256(a));
    }
    @Test public void zipMagicWorksEvenForTemporaryDatCacheFiles()throws Exception{
        File a=archive("first.dat",records("first","same"));
        File b=archive("second.dat",records("second","same"));
        FileComparator.Result result=FileComparator.compare(a,b);
        assertFalse(result.identical);
        assertTrue(result.detail.contains("APK ZIP ENTRY COMPARISON"));
        assertTrue(result.detail.contains("assets/example.js"));
    }
    @Test public void compareSelectedArchiveTextEntriesIndependently()throws Exception{
        File a=archive("left.apk",records("hello\nitem one\n","same"));
        File b=archive("right.apk",records("hello\nitem two\n","same"));
        FileComparator.Result result=FileComparator.compareEntries(
            a,"assets/example.js",b,"assets/example.js");
        assertFalse(result.identical);
        assertTrue(result.bothText);
        assertTrue(result.detail.contains("- item one"));
        assertTrue(result.detail.contains("+ item two"));
        assertTrue(FileComparator.previewEntry(a,"assets/example.js").contains("item one"));
    }
    @Test public void refuseZipPathTraversal()throws Exception{
        File f=archive("unsafe.apk",java.util.Collections.singletonMap(
            "../outside.txt","test".getBytes(StandardCharsets.UTF_8)));
        try{FileComparator.inventory(f);fail("Unsafe name accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("Unsafe"));}
    }
    @Test public void refuseDangerousZipCompressionRatio()throws Exception{
        File f=archive("bomb.apk",java.util.Collections.singletonMap("assets/bomb.bin",new byte[3_000_000]));
        try{FileComparator.inventory(f);fail("Bomb accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("compression"));}
    }
    @Test public void refuseOversizedOrInvalidSelectedPaths()throws Exception{
        File f=archive("text.apk",records("alpha","beta"));
        try{FileComparator.previewEntry(f,"../secret");fail("Traversal accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("Unsafe"));}
        try{FileComparator.previewEntry(f,"missing.txt");fail("Missing accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("missing"));}
    }
    @Test public void boundedLineComparisonHandlesManyChanges(){
        StringBuilder a=new StringBuilder(),b=new StringBuilder();
        for(int i=0;i<1000;i++){a.append("old-").append(i).append("\n");b.append("new-").append(i).append("\n");}
        String result=FileComparator.lineDifferences(a.toString(),b.toString());
        assertTrue(result.contains("Showing first 100"));
        assertTrue(result.contains("Mismatching line positions: 1000"));
        assertTrue(result.length()<=FileComparator.MAX_DISPLAY);
    }
}
