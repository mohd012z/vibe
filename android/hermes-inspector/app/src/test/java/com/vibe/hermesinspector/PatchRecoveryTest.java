package com.vibe.hermesinspector;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class PatchRecoveryTest {
    @Rule public TemporaryFolder folder=new TemporaryFolder();

    private File fixture(String filename,String originalText)throws Exception{
        File apk=folder.newFile(filename);
        try(ZipOutputStream zip=new ZipOutputStream(new FileOutputStream(apk))){
            zip.putNextEntry(new ZipEntry("assets/theme.css"));
            zip.write(originalText.getBytes(StandardCharsets.UTF_8));zip.closeEntry();
            zip.putNextEntry(new ZipEntry("assets/strings.txt"));
            zip.write("label=A".getBytes(StandardCharsets.UTF_8));zip.closeEntry();
            zip.putNextEntry(new ZipEntry("classes.dex"));
            zip.write(new byte[]{'d','e','x','\n'});zip.closeEntry();
        }
        return apk;
    }

    @Test public void checkpointRestoresAuthorizedUnicodeEditsAndUndoQueue()throws Exception{
        File original=fixture("authorized.apk","body { color: red; }");
        ApkPatchWorkspace plan=new ApkPatchWorkspace(original);
        plan.stage(original,"assets/theme.css","body { color: blue; }");
        plan.stage(original,"assets/strings.txt","label=café ☕");
        assertEquals(2,plan.size());
        assertTrue(plan.canUndo());
        PatchPlanStore store=new PatchPlanStore(folder.newFolder("plans"));
        store.save(plan);
        assertTrue(store.has(plan.sourceSha256()));
        ApkPatchWorkspace restored=store.load(original);
        assertEquals(2,restored.size());
        assertFalse(restored.canUndo());
        assertEquals(plan.sourceSha256(),restored.sourceSha256());
        File output=new File(folder.getRoot(),"unsigned.apk");
        assertEquals(2,restored.buildUnsigned(original,output).changedFiles);
        try(java.util.zip.ZipFile saved=new java.util.zip.ZipFile(original)){
            assertEquals("body { color: red; }",
                new String(saved.getInputStream(saved.getEntry("assets/theme.css"))
                    .readAllBytes(),StandardCharsets.UTF_8));
        }
        store.delete(plan.sourceSha256());
        assertFalse(store.has(plan.sourceSha256()));
    }

    @Test public void rejectsDifferentApkEvenIfPathsMatch()throws Exception{
        File first=fixture("first.apk","body { color: red; }");
        File other=fixture("other.apk","body { color: green; }");
        ApkPatchWorkspace plan=new ApkPatchWorkspace(first);
        plan.stage(first,"assets/theme.css","body { color: blue; }");
        String json=PatchPlanCodec.encode(plan);
        try{PatchPlanCodec.restore(other,json);fail("Cross-file plan accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("different APK"));}
    }
    @Test public void rejectsTamperedReplacementAndUnsafePath()throws Exception{
        File source=fixture("tamper.apk","body { color: red; }");
        ApkPatchWorkspace plan=new ApkPatchWorkspace(source);
        plan.stage(source,"assets/theme.css","body { color: blue; }");
        JSONObject item=new JSONObject(PatchPlanCodec.encode(plan));
        item.getJSONArray("changes").getJSONObject(0).put("replacement","body { color: purple; }");
        try{PatchPlanCodec.restore(source,item.toString());fail("Tampered bytes accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("digest mismatch"));}
        item=new JSONObject(PatchPlanCodec.encode(plan));
        item.getJSONArray("changes").getJSONObject(0).put("path","../classes.dex");
        try{PatchPlanCodec.restore(source,item.toString());fail("Unsafe path accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("ineligible"));}
    }
    @Test public void malformedCheckpointFailsClosedWithoutDestroyingPriorPlan()throws Exception{
        File source=fixture("malformed.apk","body { color: red; }");
        ApkPatchWorkspace plan=new ApkPatchWorkspace(source);
        plan.stage(source,"assets/theme.css","body { color: blue; }");
        PatchPlanStore store=new PatchPlanStore(folder.newFolder("store"));
        store.save(plan);
        String sha=plan.sourceSha256();
        String existing=PatchPlanCodec.encode(store.load(source));
        JSONObject bad=new JSONObject(existing);
        bad.put("format","unsupported");
        try{PatchPlanCodec.restore(source,bad.toString());fail("Wrong format accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("version"));}
        assertEquals(1,store.load(source).size());
    }
    @Test public void undoBoundsAndCheckpointAfterUndo()throws Exception{
        File source=fixture("undo.apk","body { color: red; }");
        ApkPatchWorkspace plan=new ApkPatchWorkspace(source);
        plan.stage(source,"assets/theme.css","body { color: blue; }");
        plan.stage(source,"assets/strings.txt","label=café");
        assertTrue(plan.undo());
        assertEquals(1,plan.size());
        assertTrue(plan.undo());
        assertEquals(0,plan.size());
        assertFalse(plan.undo());
        for(int i=0;i<12;i++)plan.stage(source,"assets/strings.txt","label="+i);
        int undos=0;while(plan.undo())undos++;
        assertEquals(8,undos);
    }
    @Test public void checkpointWriteAndStartupCleanupPreserveValidFile()throws Exception{
        File source=fixture("crash.apk","body { color: red; }");
        ApkPatchWorkspace plan=new ApkPatchWorkspace(source);
        plan.stage(source,"assets/strings.txt","label=ok");
        File root=folder.newFolder("atomic");
        PatchPlanStore store=new PatchPlanStore(root);
        store.save(plan);
        File temp=new File(root,"vibe-draft-interrupted.part");
        Files.write(temp.toPath(),new byte[]{12,32,56});
        assertTrue(temp.isFile());
        PatchPlanStore recoveredStore=new PatchPlanStore(root);
        assertFalse(temp.exists());
        assertEquals(1,recoveredStore.load(source).size());
    }
    @Test public void checkpointDoesNotAllowTraversalSha()throws Exception{
        PatchPlanStore store=new PatchPlanStore(folder.newFolder("safe"));
        try{store.has("../evil");fail("Path traversal SHA accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("SHA-256"));}
    }
    @Test public void rejectNestedJsonBeforeParserRecurses()throws Exception{
        File source=fixture("nested.apk","body { color: red; }");
        ApkPatchWorkspace plan=new ApkPatchWorkspace(source);
        plan.stage(source,"assets/theme.css","body { color: blue; }");
        String valid=PatchPlanCodec.encode(plan);
        String attack="[".repeat(200)+"0"+"]".repeat(200);
        try{PatchPlanCodec.restore(source,attack);fail("Nesting bomb accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("nesting"));}
        assertEquals(1,PatchPlanCodec.restore(source,valid).size());
    }
    @Test public void escapedBracketsDoNotTriggerNestingLimit()throws Exception{
        File source=fixture("braces.apk","{ text: red }");
        ApkPatchWorkspace plan=new ApkPatchWorkspace(source);
        plan.stage(source,"assets/theme.css","test [ brackets ] with quoted \\\" text");
        assertEquals(1,PatchPlanCodec.restore(source,PatchPlanCodec.encode(plan)).size());
    }

}
