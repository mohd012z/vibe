package com.vibe.hermesinspector;
import org.junit.Test;
import static org.junit.Assert.*;
import java.io.IOException;
import org.json.JSONObject;

public class ReportImporterTest {
    private String exported()throws Exception{
        ApkInspector.Report report=new ApkInspector.Report();
        report.sha256="a".repeat(64);
        report.byteSize=1200;
        report.entries=3;
        report.dexStrings.add("unicode: café ☕");
        return ReportExporter.toJson(report,"authorized.apk");
    }
    @Test public void exportedJsonCanBeImportedWithUnicode()throws Exception{
        ApkInspector.Report reread=ReportImporter.parse(exported());
        assertEquals("a".repeat(64),reread.sha256);
        assertEquals(1200,reread.byteSize);
        assertEquals("unicode: café ☕",reread.dexStrings.get(0));
        assertTrue(reread.warnings.get(reread.warnings.size()-1).contains("IMPORTED REPORT"));
    }
    @Test public void modifiedOrWrongFormatRejected()throws Exception{
        JSONObject wrong=new JSONObject(exported());
        wrong.put("format","untrusted");
        try{ReportImporter.parse(wrong.toString());fail("Version spoof accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("format"));}
        wrong=new JSONObject(exported());
        wrong.put("sha256","wrong");
        try{ReportImporter.parse(wrong.toString());fail("Missing SHA accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("SHA"));}
    }
    @Test public void rejectsDeeplyNestedAndMalformedJson()throws Exception{
        try{ReportImporter.parse("[".repeat(1000)+"]".repeat(1000));fail("Deep JSON accepted");}
        catch(IOException expected){assertNotNull(expected.getMessage());}
        try{ReportImporter.parse("{");fail("Broken JSON accepted");}
        catch(IOException expected){assertNotNull(expected.getMessage());}
    }
    @Test public void oversizedRecordArrayRejected()throws Exception{
        JSONObject report=new JSONObject(exported());
        org.json.JSONArray huge=new org.json.JSONArray();
        for(int i=0;i<6001;i++)huge.put("x");
        report.put("dex_strings",huge);
        try{ReportImporter.parse(report.toString());fail("Oversized report accepted");}
        catch(IOException expected){assertTrue(expected.getMessage().contains("record limit"));}
    }
}
