package com.vibe.hermesinspector;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Exports reconstructed previews from one visible results page, not raw binary APK contents. */
public final class SourceBundleExporter {
    public static final int MAX_ITEMS=25;
    public static final int MAX_UNCOMPRESSED=6*1024*1024;
    private SourceBundleExporter(){}

    public static byte[] create(File apk,List<ApkSourceExplorer.Entry> entries,int mode)throws IOException{
        if(apk==null||entries==null||entries.isEmpty()||entries.size()>MAX_ITEMS)
            throw new IOException("Select 1–25 source records to export");
        if(mode<0||mode>2)throw new IOException("Unknown source export mode");
        ByteArrayOutputStream raw=new ByteArrayOutputStream();
        int total=0;
        Set<String> used=new HashSet<>();
        try(ZipOutputStream out=new ZipOutputStream(raw,StandardCharsets.UTF_8)){
            StringBuilder manifest=new StringBuilder("Vibe APK Source Explorer\n"+
               "Source APK SHA-256: "+ApkInspector.sha256(apk)+"\n"+
               "Preview mode: "+mode+"\n"+
               "WARNING: reconstructed code is not original Java/Kotlin/Dart source.\n"+
               "Text previews are partial, not guaranteed recompilable.\n\n");
            int number=0;
            for(ApkSourceExplorer.Entry entry:entries){
                if(Thread.currentThread().isInterrupted())
                    throw new IOException("Export cancelled");
                if(entry==null)throw new IOException("Invalid selection");
                String content=ApkSourceExplorer.open(apk,entry,mode);
                byte[] bytes=content.getBytes(StandardCharsets.UTF_8);
                if(bytes.length>ApkSourceExplorer.MAX_TEXT+4096)
                    throw new IOException("Individual source preview exceeds safe bound");
                if(total>MAX_UNCOMPRESSED-bytes.length)
                    throw new IOException("Selected sources exceed 6 MiB export budget");
                total+=bytes.length;
                String stem=entry.classDescriptor==null?entry.archivePath:entry.classDescriptor;
                String title=stem.replaceAll("[^A-Za-z0-9._-]","_");
                if(title.length()>110)title=title.substring(title.length()-110);
                String name=String.format(Locale.ROOT,"%03d_",++number)+title+
                    ("class".equals(entry.kind)?".smali.txt":".preview.txt");
                if(!used.add(name))throw new IOException("Duplicate archive output name");
                ZipEntry item=new ZipEntry("source/"+name);
                item.setTime(0);
                out.putNextEntry(item);
                out.write(bytes);
                out.closeEntry();
                manifest.append(number).append(". ").append(entry.title).append(" => ")
                    .append(name).append("\n");
            }
            byte[] index=manifest.toString().getBytes(StandardCharsets.UTF_8);
            total+=index.length;
            if(total>MAX_UNCOMPRESSED)throw new IOException("Export manifest over budget");
            ZipEntry top=new ZipEntry("README.txt");
            top.setTime(0);
            out.putNextEntry(top);
            out.write(index);
            out.closeEntry();
        }
        if(raw.size()>MAX_UNCOMPRESSED)
            throw new IOException("Compressed preview archive exceeds 6 MiB");
        return raw.toByteArray();
    }
}
