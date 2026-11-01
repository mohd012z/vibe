package com.vibe.hermesinspector;
import org.junit.Test;
import org.json.JSONArray;
import org.json.JSONObject;
import static org.junit.Assert.*;

public class ReportExporterTest {
    private ApkInspector.Report sample(){
        ApkInspector.Report r=new ApkInspector.Report();
        r.sha256="a".repeat(64);
        r.byteSize=1024;
        r.dexParsed=1;
        r.dexStrings.add("#0  Lcom/example/Test;");
        r.hermesStrings.add("HBC str#0 [UTF-16] café");
        r.warnings.add("Records are bounded");
        return r;
    }
    @Test public void roundtripPreservesMetadataUnicodeAndLimits()throws Exception{
        String payload=ReportExporter.toJson(sample(),"demo.apk");
        JSONObject parsed=new JSONObject(payload);
        assertEquals("vibe-hermes-offline-report-v2",parsed.getString("format"));
        assertEquals("a".repeat(64),parsed.getString("sha256"));
        assertEquals("demo.apk",parsed.getString("file_name"));
        assertEquals("HBC str#0 [UTF-16] café",
            parsed.getJSONArray("hermes_strings").getString(0));
        assertTrue(parsed.getString("analysis_limits").contains("bounded"));
        assertEquals(1,parsed.getInt("dex_files_indexed"));
    }
    @Test public void oversizedReportFailsBeforeExport()throws Exception{
        ApkInspector.Report r=sample();
        for(int i=0;i<6000;i++)r.dexStrings.add("big-"+i+"-"+"x".repeat(900));
        try{ReportExporter.toJson(r,"oversize.apk");fail("Expected safe export limit");}
        catch(IllegalArgumentException expected){
            assertTrue(expected.getMessage().contains("4 MiB"));
        }
    }
}
