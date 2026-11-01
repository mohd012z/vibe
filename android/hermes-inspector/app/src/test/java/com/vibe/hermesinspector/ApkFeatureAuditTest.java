package com.vibe.hermesinspector;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import static org.junit.Assert.*;

public class ApkFeatureAuditTest {
    @Rule public TemporaryFolder temp=new TemporaryFolder();

    private File create(Map<String,byte[]> entries)throws IOException{
        File file=temp.newFile("audit-"+System.nanoTime()+".apk");
        try(ZipOutputStream zip=new ZipOutputStream(new FileOutputStream(file))){
            for(Map.Entry<String,byte[]> entry:entries.entrySet()){
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue());
                zip.closeEntry();
            }
        }
        return file;
    }
    private byte[] fixture()throws IOException{
        try(InputStream in=getClass().getResourceAsStream("/source-explorer-fixture.dex")){
            if(in==null)throw new IOException("Missing genuine D8 test DEX");
            return in.readAllBytes();
        }
    }
    @Test public void topicBoundariesAvoidFalsePositiveSubstring(){
        assertFalse(ApkFeatureAudit.matches(ApkFeatureAudit.Topic.PREMIUM,"property/process/progress"));
        assertFalse(ApkFeatureAudit.matches(ApkFeatureAudit.Topic.ADVERTISING,"AddressAccessor"));
        assertTrue(ApkFeatureAudit.matches(ApkFeatureAudit.Topic.PREMIUM,"VIP"));
        assertTrue(ApkFeatureAudit.matches(ApkFeatureAudit.Topic.PREMIUM,"premium"));
        assertTrue(ApkFeatureAudit.matches(ApkFeatureAudit.Topic.SUBSCRIPTION,"subscription paywall"));
        assertTrue(ApkFeatureAudit.matches(ApkFeatureAudit.Topic.BILLING,"BillingClient"));
        assertTrue(ApkFeatureAudit.matches(ApkFeatureAudit.Topic.ADVERTISING,"com.google.android.gms.ads.AdView"));
        assertTrue(ApkFeatureAudit.matches(ApkFeatureAudit.Topic.TRACKING,"AppsFlyer attribution"));
    }
    @Test public void authenticD8DexYieldsAllStaticFeatureCategories()throws Exception{
        byte[] bytes=fixture();
        Map<String,byte[]> entries=new HashMap<>();
        entries.put("classes.dex",bytes);
        File archive=create(entries);
        String before=ApkInspector.sha256(archive);
        ApkFeatureAudit.Result result=ApkFeatureAudit.analyze(archive);
        assertEquals(1,result.dexIndexed);
        assertTrue(result.stringsScanned>1);
        assertTrue(result.classesScanned>0);
        assertTrue(result.methodsScanned>0);
        for(ApkFeatureAudit.Topic topic:ApkFeatureAudit.Topic.values()){
            assertTrue("No static refs for "+topic,result.count(topic)>0);
        }
        assertTrue(result.hits.get(ApkFeatureAudit.Topic.BILLING).stream()
                .anyMatch(h->h.evidence.contains("BillingClient")));
        assertTrue(result.warnings.stream().anyMatch(s->s.contains("not proof")));
        assertEquals(before,ApkInspector.sha256(archive));
    }

    @Test public void genuineD8ConstantStringUseLinksToOwningMethod()throws Exception{
        File archive=create(java.util.Collections.singletonMap("classes.dex",fixture()));
        ApkFeatureAudit.Result report=ApkFeatureAudit.analyze(archive);
        assertTrue(report.opcodeInstructionsScanned>0);
        assertTrue(report.stringUseSites>0);
        ApkFeatureAudit.Hit hit=report.hits.get(ApkFeatureAudit.Topic.BILLING).stream()
            .filter(h->h.kind.equals("Method string use") &&
                h.classDescriptor!=null && h.evidence.contains("BillingClient"))
            .findFirst().orElse(null);
        assertNotNull("Could not attribute BillingClient string to its DEX method",hit);
        assertEquals("Lcom/vibe/fixture/Greeter;",hit.classDescriptor);
        assertTrue(hit.evidence.contains("billingEvidence"));
        assertTrue(report.warnings.stream().anyMatch(s->s.contains("do not prove actual execution")));
    }
    @Test public void fourDexFilesAreIndexedWithoutLosingOwners()throws Exception{
        byte[] raw=fixture();
        Map<String,byte[]> values=new HashMap<>();
        values.put("classes.dex",raw);
        values.put("classes2.dex",raw);
        values.put("classes3.dex",raw);
        values.put("classes4.dex",raw);
        File apk=create(values);
        String originalHash=ApkInspector.sha256(apk);
        ApkFeatureAudit.Result report=ApkFeatureAudit.analyze(apk);
        assertEquals(4,report.dexIndexed);
        assertTrue(report.stringUseSites>=4);
        assertTrue(report.hits.get(ApkFeatureAudit.Topic.PREMIUM).stream()
            .anyMatch(hit->"classes4.dex".equals(hit.dexPath) &&
                hit.classDescriptor!=null));
        assertEquals(originalHash,ApkInspector.sha256(apk));
    }
    @Test public void maliciousCompressedDexIsRejectedBeforeParsing()throws Exception{
        File apk=create(java.util.Collections.singletonMap("classes.dex",new byte[3_000_000]));
        try{
            ApkFeatureAudit.analyze(apk);
            fail("Compressed archive bomb accepted");
        }catch(IOException expected){
            assertTrue(expected.getMessage().contains("compressed DEX ratio"));
        }
    }
    @Test public void unsupportedOrUnrelatedAssetsYieldZeroMatches()throws Exception{
        Map<String,byte[]> entries=new HashMap<>();
        entries.put("assets/plain.txt","ordinary source".getBytes(StandardCharsets.UTF_8));
        ApkFeatureAudit.Result result=ApkFeatureAudit.analyze(create(entries));
        assertEquals(0,result.dexIndexed);
        for(ApkFeatureAudit.Topic topic:ApkFeatureAudit.Topic.values())
            assertEquals(0,result.count(topic));
    }
    @Test public void maliciousZipMemberRejected()throws Exception{
        Map<String,byte[]> entries=new HashMap<>();
        entries.put("../classes.dex",fixture());
        try{ApkFeatureAudit.analyze(create(entries));fail("ZIP traversal accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("Unsafe"));}
    }
    @Test public void randomizedMalformedDexNeverRunsUntrustedCode()throws Exception{
        byte[] original=fixture();
        java.util.Random random=new java.util.Random(20261101L);
        for(int i=0;i<100;i++){
            byte[] copy=original.clone();
            int edits=1+random.nextInt(4);
            for(int j=0;j<edits;j++)
                copy[random.nextInt(copy.length)]^=(byte)(1+random.nextInt(255));
            File file=create(java.util.Collections.singletonMap("classes.dex",copy));
            try{ApkFeatureAudit.analyze(file);}
            catch(IOException rejected){/* bounded decoder or ZIP refusal */ }
        }
    }
}
