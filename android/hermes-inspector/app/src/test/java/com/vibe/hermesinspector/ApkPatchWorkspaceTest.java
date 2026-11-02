package com.vibe.hermesinspector;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;
import static org.junit.Assert.*;

public class ApkPatchWorkspaceTest {
    @Rule public TemporaryFolder tmp=new TemporaryFolder();
    private File archive(String filename,Map<String,byte[]> members)throws Exception {
        File f=tmp.newFile(filename);
        try(ZipOutputStream out=new ZipOutputStream(new FileOutputStream(f))){
            for(Map.Entry<String,byte[]> item:members.entrySet()){
                out.putNextEntry(new ZipEntry(item.getKey()));
                out.write(item.getValue());out.closeEntry();
            }
        }
        return f;
    }
    private Map<String,byte[]> sample(){
        Map<String,byte[]> data=new LinkedHashMap<>();
        data.put("assets/theme.css","body { color: red; }".getBytes(StandardCharsets.UTF_8));
        data.put("assets/readme.txt","Hello café ☕".getBytes(StandardCharsets.UTF_8));
        data.put("classes.dex",new byte[]{'d','e','x','\n',1,2,3});
        data.put("META-INF/APP.SF",new byte[]{9});
        data.put("META-INF/APP.RSA",new byte[]{7});
        data.put("META-INF/MANIFEST.MF",new byte[]{6});
        return data;
    }
    @Test public void stagesAndBuildsSeparateUnsignedApkWithOriginalUntouched()throws Exception {
        File apk=archive("original.apk",sample());
        String original=FileComparator.sha256(apk);
        ApkPatchWorkspace plan=new ApkPatchWorkspace(apk);
        plan.stage(apk,"assets/readme.txt","Changed café ☕");
        File target=new File(tmp.getRoot(),"unsigned.apk");
        ApkPatchWorkspace.Result result=plan.buildUnsigned(apk,target);
        assertEquals(1,result.changedFiles);
        assertEquals(3,result.strippedV1SignatureEntries);
        assertEquals(original,FileComparator.sha256(apk));
        assertEquals(result.outputSha256,FileComparator.sha256(target));
        try(ZipFile output=new ZipFile(target)){
            assertNull(output.getEntry("META-INF/APP.RSA"));
            assertNull(output.getEntry("META-INF/APP.SF"));
            assertNotNull(output.getEntry("classes.dex"));
            assertEquals("Changed café ☕",new String(output.getInputStream(
                output.getEntry("assets/readme.txt")).readAllBytes(),StandardCharsets.UTF_8));
        }
    }
    @Test public void batchTextReplaceWithRemovalIsReversible()throws Exception {
        File source=archive("replace.apk",sample());
        ApkPatchWorkspace plan=new ApkPatchWorkspace(source);
        assertEquals(1,plan.replaceLiteral(source,"color: red","color: blue"));
        assertEquals(1,plan.size());
        assertTrue(plan.staged().get(0).describe().contains("theme.css"));
        plan.remove("assets/theme.css");
        assertEquals(0,plan.size());
        try{plan.buildUnsigned(source,new File(tmp.getRoot(),"out.apk"));fail("Empty plan accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("No changes"));}
    }
    @Test public void rejectsExecutableBillingAndSigningFileClasses()throws Exception {
        File apk=archive("blocked.apk",sample());
        ApkPatchWorkspace plan=new ApkPatchWorkspace(apk);
        for(String path:new String[]{"classes.dex","resources.arsc","AndroidManifest.xml",
            "assets/logic.js","lib/a.so","META-INF/APP.SF","../assets/theme.css"}){
            assertFalse(ApkPatchWorkspace.editable(path));
            try{plan.stage(apk,path,"patched");fail("Unsafe edit accepted");}
            catch(IOException expected){assertTrue(expected.getMessage().contains("editable"));}
        }
    }
    @Test public void failsIfTargetExistsOrPinnedSourceChanges()throws Exception {
        File apk=archive("pinned.apk",sample());
        ApkPatchWorkspace plan=new ApkPatchWorkspace(apk);
        plan.stage(apk,"assets/readme.txt","safe revision");
        try{plan.buildUnsigned(apk,apk);fail("Overwrote original");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("distinct"));}
        try(FileOutputStream f=new FileOutputStream(apk,true)){f.write(0);}
        File out=new File(tmp.getRoot(),"absent.apk");
        try{plan.buildUnsigned(apk,out);fail("Changed input accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("differs"));}
        assertFalse(out.exists());
    }
    @Test public void refusesMalformedZipAndDeletesPartialBuild()throws Exception {
        Map<String,byte[]> parts=sample();
        parts.put("../escape.txt",new byte[]{3});
        File apk=archive("bad.apk",parts);
        ApkPatchWorkspace plan=new ApkPatchWorkspace(apk);
        plan.stage(apk,"assets/theme.css","safe");
        File out=new File(tmp.getRoot(),"badout.apk");
        try{plan.buildUnsigned(apk,out);fail("Traversal accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("Unsafe"));}
        assertFalse(out.exists());
    }
    @Test public void refusesCompressedBombAndOverlargeUnicode()throws Exception {
        Map<String,byte[]> parts=sample();
        parts.put("assets/compressed.bin",new byte[3_000_000]);
        File apk=archive("bomb.apk",parts);
        ApkPatchWorkspace plan=new ApkPatchWorkspace(apk);
        plan.stage(apk,"assets/theme.css","safe");
        try{plan.stage(apk,"assets/theme.css","☕".repeat(23000));fail("Oversize");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("64 KiB"));}
        assertEquals(1,plan.size());
        File out=new File(tmp.getRoot(),"no-bomb.apk");
        try{plan.buildUnsigned(apk,out);fail("Zip bomb accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("compression ratio"));}
        assertFalse(out.exists());
    }
    @Test public void oversizedBatchRollsBackAllStagedChanges()throws Exception{
        Map<String,byte[]> assets=sample();
        for(int i=0;i<13;i++)
            assets.put("assets/replace"+i+".txt","findme in resource".getBytes(StandardCharsets.UTF_8));
        File original=archive("many.apk",assets);
        ApkPatchWorkspace plan=new ApkPatchWorkspace(original);
        plan.stage(original,"assets/theme.css","body { color: blue; }");
        int before=plan.size();
        try{
            plan.replaceLiteral(original,"findme","updated");
            fail("Thirteen-file batch accepted");
        }catch(IOException expected){
            assertTrue(expected.getMessage().contains("twelve-file"));
        }
        assertEquals(before,plan.size());
        assertTrue(plan.staged().get(0).path.equals("assets/theme.css"));
    }

    @Test public void multipleAutomationPassesRespectExistingStagedText()throws Exception{
        File source=archive("chain.apk",sample());
        ApkPatchWorkspace plan=new ApkPatchWorkspace(source);
        plan.stage(source,"assets/theme.css","body { color: blue; }");
        assertEquals(1,plan.replaceLiteral(source,"color: blue","color: green"));
        assertEquals(1,plan.size());
        ApkPatchWorkspace.Validation check=plan.validateStaged(source);
        assertEquals(1,check.stagedFiles);
        assertEquals(3,check.strippedSignatureEntries);
        File unsigned=new File(tmp.getRoot(),"chain-unsigned.apk");
        plan.buildUnsigned(source,unsigned);
        try(ZipFile zip=new ZipFile(unsigned)){
            String text=new String(zip.getInputStream(zip.getEntry("assets/theme.css"))
                .readAllBytes(),StandardCharsets.UTF_8);
            assertEquals("body { color: green; }",text);
        }
        assertTrue(plan.undo());
        assertEquals(1,plan.size());
        File reverted=new File(tmp.getRoot(),"chain-reverted.apk");
        plan.buildUnsigned(source,reverted);
        try(ZipFile zip=new ZipFile(reverted)){
            assertEquals("body { color: blue; }",
                new String(zip.getInputStream(zip.getEntry("assets/theme.css"))
                    .readAllBytes(),StandardCharsets.UTF_8));
        }
    }
    @Test public void preflightDetectsChangedInputWithoutExport()throws Exception{
        File source=archive("preflight.apk",sample());
        ApkPatchWorkspace plan=new ApkPatchWorkspace(source);
        plan.stage(source,"assets/theme.css","body { color: blue; }");
        assertEquals(1,plan.validateStaged(source).stagedFiles);
        try(FileOutputStream out=new FileOutputStream(source,true)){out.write(21);}
        try{plan.validateStaged(source);fail("Modified source accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("differs"));}
        assertEquals(1,plan.size());
    }

}
