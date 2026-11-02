package com.vibe.hermesinspector;

import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;
import static org.junit.Assert.*;

public class DexViewsTest {
    @Rule public TemporaryFolder tmp=new TemporaryFolder();

    @Test public void genuineD8InvokeReferencesAndCommentary()throws Exception{
        try(InputStream input=getClass().getResourceAsStream("/source-explorer-fixture.dex")){
            assertNotNull(input);
            File archive=tmp.newFile("classcall.apk");
            try(ZipOutputStream z=new ZipOutputStream(new FileOutputStream(archive))){
                z.putNextEntry(new ZipEntry("classes.dex"));
                z.write(input.readAllBytes());
                z.closeEntry();
            }
            ApkSourceExplorer.Result index=ApkSourceExplorer.index(archive);
            ApkSourceExplorer.Entry greeter=null;
            for(ApkSourceExplorer.Entry e:index.entries)if("class".equals(e.kind)&&
                 "Lcom/vibe/fixture/Greeter;".equals(e.classDescriptor)){greeter=e;break;}
            assertNotNull(greeter);
            String bytecode=ApkSourceExplorer.open(archive,greeter,0);
            String comments=ApkSourceExplorer.open(archive,greeter,1);
            String callsites=ApkSourceExplorer.open(archive,greeter,2);
            List<String> targets=ApkSourceExplorer.callTargets(archive,greeter);
            assertTrue(bytecode.contains("invoke-static"));
            assertTrue(comments.contains("NOT original Java/Kotlin"));
            assertTrue(comments.contains("callsite"));
            assertTrue(callsites.contains("invoke-static"));
            assertTrue(targets.stream().anyMatch(x->x.contains("Lcom/vibe/fixture/Greeter;->echo")));
            assertFalse(callsites.contains("dynamic call graph proven"));
        }
    }
}
