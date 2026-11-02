package com.vibe.hermesinspector;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * Offline read/edit/repack engine for non-executable text assets in authorized APKs.
 *
 * Original bytes and signing identity are never modified. Any rebuilt APK is
 * UNSIGNED AND UNALIGNED and cannot be installed until independently aligned,
 * signed with an authorized private key, and validated with Android tools.
 */
public final class ApkPatchWorkspace {
    public static final int MAX_STAGE=12;
    public static final int MAX_UNDO=8;
    public static final int MAX_ASSET_BYTES=64*1024;
    public static final int MAX_REPLACEMENTS=100;
    private static final long MAX_OUTPUT=256L*1024*1024;
    private static final long MAX_EXPANDED=1024L*1024*1024;
    private static final int MAX_ZIP_MEMBERS=20000;

    public static final class Change {
        public final String path, beforeSha256, afterSha256;
        public final int beforeBytes, afterBytes;
        private final byte[] replacement;
        private Change(String path, byte[] before,byte[] after)throws IOException{
            this.path=path;
            this.beforeSha256=hash(before);
            this.afterSha256=hash(after);
            this.beforeBytes=before.length;
            this.afterBytes=after.length;
            this.replacement=after.clone();
        }
        public String describe(){
            return path+"  "+beforeBytes+"→"+afterBytes+" bytes  "+beforeSha256.substring(0,12)+"→"+afterSha256.substring(0,12);
        }
    }
    public static final class Result {
        public final String originalSha256, outputSha256;
        public final long sourceBytes, outputBytes;
        public final int changedFiles, strippedV1SignatureEntries;
        Result(String a,String b,long sourceBytes,long outputBytes,int changes,int signatures){
            originalSha256=a;outputSha256=b;this.sourceBytes=sourceBytes;this.outputBytes=outputBytes;
            changedFiles=changes;strippedV1SignatureEntries=signatures;
        }
    }
    private final String sourceSha256;
    private final LinkedHashMap<String,Change> changes=new LinkedHashMap<>();
    private final java.util.ArrayDeque<LinkedHashMap<String,Change>> history=new java.util.ArrayDeque<>();

    public ApkPatchWorkspace(File original)throws IOException{
        if(original==null||!original.isFile()||original.length()<22||
           original.length()>ApkInspector.MAX_APK_BYTES)
            throw new IOException("Invalid or oversized APK");
        sourceSha256=FileComparator.sha256(original);
    }
    public String sourceSha256(){return sourceSha256;}
    public List<Change> staged(){return Collections.unmodifiableList(new ArrayList<>(changes.values()));}
    public int size(){return changes.size();}
    public void clear(){
        if(changes.isEmpty())return;
        remember();
        changes.clear();
    }
    public void remove(String path){
        if(!changes.containsKey(path))return;
        remember();
        changes.remove(path);
    }
    public boolean undo(){
        if(history.isEmpty())return false;
        changes.clear();
        changes.putAll(history.removeLast());
        return true;
    }
    public boolean canUndo(){return !history.isEmpty();}
    void clearUndoHistory(){history.clear();}
    String replacementText(String path)throws IOException{
        Change item=changes.get(path);
        if(item==null)throw new IOException("No staged replacement for "+path);
        return decode(item.replacement);
    }
    private void remember(){
        if(history.size()>=MAX_UNDO)history.removeFirst();
        history.addLast(new LinkedHashMap<>(changes));
    }

    public static boolean editable(String path){
        if(path==null||path.isEmpty()||!safeName(path))return false;
        String lower=path.toLowerCase(Locale.ROOT);
        if(lower.equals("androidmanifest.xml")||lower.equals("resources.arsc")||
           lower.startsWith("meta-inf/")||lower.endsWith(".dex")||lower.endsWith(".so")||
           lower.endsWith(".hbc")||lower.endsWith(".bundle"))return false;
        // Only packaged non-executable user-facing text/resource documents.
        if(!(lower.startsWith("assets/")||lower.startsWith("res/raw/")))return false;
        for(String ext:new String[]{".txt",".md",".css",".html",".htm",
            ".csv",".xml",".svg",".properties",".yaml",".yml",".ini"}){
            if(lower.endsWith(ext))return true;
        }
        return false;
    }

    public void stage(File original,String path,String newText)throws IOException{
        validateSource(original);
        if(!editable(path))throw new IOException("Not an editable non-executable text asset");
        byte[] after=utf8(newText);
        if(after.length>MAX_ASSET_BYTES)throw new IOException("Replacement exceeds 64 KiB");
        if(!changes.containsKey(path)&&changes.size()>=MAX_STAGE)
            throw new IOException("Maximum twelve staged text assets");
        byte[] before=readOriginalText(original,path);
        Change replacement=new Change(path,before,after);
        if(replacement.beforeSha256.equals(replacement.afterSha256)){
            if(changes.containsKey(path)){remember();changes.remove(path);}
        }else{
            Change existing=changes.get(path);
            if(existing==null||!existing.afterSha256.equals(replacement.afterSha256)){
                remember();
                changes.put(path,replacement);
            }
        }
    }

    /** Deterministic exact literal replacement on *eligible* text entries only.
        No regex, binary patching, entitlement/runtime edits, or arbitrary paths. */
    public int replaceLiteral(File original,String find,String replace)throws IOException{
        validateSource(original);
        if(find==null||find.length()<2||find.length()>200||
           replace==null||replace.length()>1000)
            throw new IOException("Search or replacement length outside bounds");
        LinkedHashMap<String,Change> pending=new LinkedHashMap<>(changes);
        int affected=0;
        long declared=0;
        try(ZipFile zip=new ZipFile(original)){
            Set<String> seen=new HashSet<>();
            Enumeration<? extends ZipEntry> all=zip.entries();
            int members=0;
            while(all.hasMoreElements()){
                if(Thread.currentThread().isInterrupted())throw new IOException("Batch replacement cancelled");
                ZipEntry entry=all.nextElement();
                if(++members>MAX_ZIP_MEMBERS)throw new IOException("ZIP member budget exceeded");
                String path=entry.getName();
                if(!safeName(path)||!seen.add(path))throw new IOException("Unsafe/duplicate ZIP path");
                long size=entry.getSize(),packed=entry.getCompressedSize();
                if(size<0||packed<0||size>MAX_EXPANDED||declared>MAX_EXPANDED-size)
                    throw new IOException("ZIP size budget exceeded");
                declared+=size;
                if(size>1024*1024 && (packed==0||size/Math.max(1,packed)>200))
                    throw new IOException("Suspicious APK compression ratio");
                if(!editable(path)||entry.isDirectory()||size>MAX_ASSET_BYTES)continue;
                byte[] beforeBytes=readEntry(zip,entry,MAX_ASSET_BYTES);
                String before=decode(beforeBytes);
                if(!before.contains(find))continue;
                if(!pending.containsKey(path)&&pending.size()>=MAX_STAGE)
                    throw new IOException("Batch replacement exceeds twelve-file limit");
                String after=before.replace(find,replace);
                byte[] next=utf8(after);
                Change change=new Change(path,beforeBytes,next);
                if(change.beforeSha256.equals(change.afterSha256))
                    pending.remove(path);
                else pending.put(path,change);
                affected++;
            }
        }
        // Commit only after every candidate and ZIP member has passed validation.
        if(!equalChanges(pending,changes)){
            remember();
            changes.clear();
            changes.putAll(pending);
        }
        return affected;
    }

    private static boolean equalChanges(Map<String,Change> a,Map<String,Change> b){
        if(a.size()!=b.size())return false;
        for(Map.Entry<String,Change> entry:a.entrySet()){
            Change other=b.get(entry.getKey());
            if(other==null||!entry.getValue().afterSha256.equals(other.afterSha256))
                return false;
        }
        return true;
    }

    /**
     * Builds a NEW unsigned APK. The source APK remains byte-identical. No output
     * file is published until ZIP entry checks, replacement hashes and source
     * integrity have passed. Caller must use a different output file path.
     */
    public Result buildUnsigned(File original,File target)throws IOException{
        validateSource(original);
        if(changes.isEmpty())throw new IOException("No changes staged");
        if(target==null||target.exists()||
           original.getCanonicalPath().equals(target.getCanonicalPath()))
            throw new IOException("Output must be a new, distinct file");
        File parent=target.getAbsoluteFile().getParentFile();
        if(parent==null||!parent.isDirectory())throw new IOException("Invalid export directory");
        File scratch=File.createTempFile("vibe-repack-", ".partial", parent);
        int signatureCount=0,applied=0;
        long declared=0;
        try{
            try(ZipFile input=new ZipFile(original);
                ZipOutputStream output=new ZipOutputStream(new FileOutputStream(scratch),StandardCharsets.UTF_8)){
                output.setLevel(6);
                Set<String> seen=new HashSet<>();
                Set<String> appliedNames=new HashSet<>();
                Enumeration<? extends ZipEntry> entries=input.entries();
                int memberCount=0;
                while(entries.hasMoreElements()){
                    if(Thread.currentThread().isInterrupted())throw new IOException("Build cancelled");
                    ZipEntry source=entries.nextElement();
                    String path=source.getName();
                    if(++memberCount>MAX_ZIP_MEMBERS)throw new IOException("ZIP member budget exceeded");
                    if(!safeName(path)||!seen.add(path))throw new IOException("Unsafe/duplicate ZIP path");
                    long size=source.getSize(),packed=source.getCompressedSize();
                    if(size<0||packed<0||size>MAX_EXPANDED||declared>MAX_EXPANDED-size)
                        throw new IOException("APK declared expanded-size budget exceeded");
                    declared+=size;
                    if(size>1024*1024 && (packed==0||size/Math.max(1,packed)>200))
                        throw new IOException("Suspicious APK compression ratio");
                    if(signatureFile(path)){signatureCount++;continue;}
                    Change change=changes.get(path);
                    if(change!=null&&source.isDirectory())
                        throw new IOException("Cannot replace a directory");
                    ZipEntry dest=new ZipEntry(path);
                    if(source.getTime()>=0)dest.setTime(source.getTime());
                    output.putNextEntry(dest);
                    if(change==null){
                        try(InputStream in=input.getInputStream(source)){
                            boundedCopy(in,output,size);
                        }
                    }else{
                        byte[] before=readEntry(input,source,MAX_ASSET_BYTES);
                        if(!hash(before).equals(change.beforeSha256))
                            throw new IOException("Source entry changed after staging: "+path);
                        output.write(change.replacement);
                        applied++;
                        appliedNames.add(path);
                    }
                    output.closeEntry();
                    if(scratch.length()>MAX_OUTPUT)
                        throw new IOException("Unsigned APK output exceeds 256 MiB limit");
                }
                if(applied!=changes.size())
                    throw new IOException("Staged path absent from original APK");
            }
            if(scratch.length()>MAX_OUTPUT)throw new IOException("Unsigned APK exceeds 256 MiB");
            try(ZipFile verified=new ZipFile(scratch)){
                for(Change change:changes.values()){
                    ZipEntry member=verified.getEntry(change.path);
                    if(member==null||!hash(readEntry(verified,member,MAX_ASSET_BYTES))
                            .equals(change.afterSha256))
                        throw new IOException("Modified entry failed readback verification");
                }
            }
            validateSource(original);
            String finalDigest=FileComparator.sha256(scratch);
            Files.move(scratch.toPath(),target.toPath(),StandardCopyOption.ATOMIC_MOVE);
            return new Result(sourceSha256,finalDigest,original.length(),target.length(),
                applied,signatureCount);
        }finally{
            if(scratch.exists())scratch.delete();
        }
    }

    private void validateSource(File file)throws IOException{
        if(file==null||!file.isFile()||file.length()<22||
           file.length()>ApkInspector.MAX_APK_BYTES)
            throw new IOException("Source APK missing");
        if(!sourceSha256.equals(FileComparator.sha256(file)))
            throw new IOException("Source APK differs from pinned SHA-256");
    }
    private static boolean signatureFile(String name){
        String n=name.toUpperCase(Locale.ROOT);
        if(!n.startsWith("META-INF/"))return false;
        return n.endsWith(".SF")||n.endsWith(".RSA")||n.endsWith(".DSA")||
               n.endsWith(".EC")||n.equals("META-INF/MANIFEST.MF")||
               n.startsWith("META-INF/SIG-");
    }
    private static boolean safeName(String name){
        if(name==null||name.isEmpty()||name.startsWith("/")||
           name.indexOf('\\')>=0||name.indexOf('\0')>=0)return false;
        for(String part:name.split("/",-1))
            if(part.equals(".")||part.equals(".."))return false;
        return true;
    }
    private static void boundedCopy(InputStream source,ZipOutputStream target,long expected)
            throws IOException{
        byte[] buf=new byte[32768];
        long copied=0;int n;
        while((n=source.read(buf))!=-1){
            if(Thread.currentThread().isInterrupted())throw new IOException("Copy cancelled");
            if(n==0)continue;
            copied+=n;
            if(copied>expected)throw new IOException("ZIP member exceeded declared bounds");
            target.write(buf,0,n);
        }
        if(copied!=expected)throw new IOException("ZIP member truncated");
    }
    private static byte[] readEntry(ZipFile zip,ZipEntry entry,int limit)throws IOException{
        long length=entry.getSize();
        if(length<0||length>limit)throw new IOException("Selected asset exceeds preview budget");
        try(InputStream in=zip.getInputStream(entry)){
            ByteArrayOutputStream out=new ByteArrayOutputStream((int)length);
            byte[] buffer=new byte[8192];int n;
            while((n=in.read(buffer))!=-1){
                if(n==0)continue;
                if(out.size()>limit-n)throw new IOException("Asset expands beyond budget");
                out.write(buffer,0,n);
            }
            if(out.size()!=length)throw new IOException("Truncated text member");
            return out.toByteArray();
        }
    }
    private static byte[] utf8(String value)throws IOException{
        if(value==null)throw new IOException("Missing text");
        byte[] b=value.getBytes(StandardCharsets.UTF_8);
        if(b.length>MAX_ASSET_BYTES)throw new IOException("Text exceeds 64 KiB");
        decode(b);
        return b;
    }
    private static String decode(byte[] bytes)throws IOException{
        for(byte b:bytes)if(b==0)throw new IOException("NUL bytes are not valid text assets");
        try{
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString();
        }catch(CharacterCodingException invalid){
            throw new IOException("Invalid UTF-8 in text asset",invalid);
        }
    }
    private static byte[] readOriginalText(File apk,String path)throws IOException{
        try(ZipFile zip=new ZipFile(apk)){
            ZipEntry entry=zip.getEntry(path);
            if(entry==null||entry.isDirectory())throw new IOException("Text asset missing");
            byte[] bytes=readEntry(zip,entry,MAX_ASSET_BYTES);
            decode(bytes);
            return bytes;
        }
    }
    private static String hash(byte[] data)throws IOException{
        try{
            MessageDigest digest=MessageDigest.getInstance("SHA-256");
            byte[] hash=digest.digest(data);
            StringBuilder out=new StringBuilder();
            for(byte b:hash)out.append(String.format(Locale.ROOT,"%02x",b&255));
            return out.toString();
        }catch(NoSuchAlgorithmException e){throw new IOException("SHA-256 unavailable",e);}
    }
}
