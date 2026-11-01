package com.vibe.hermesinspector;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Read-only comparison engine for user-selected files and ZIP/APK entries. */
public final class FileComparator {
    public static final long MAX_FILE=96L*1024*1024;
    public static final int MAX_TEXT=256*1024;
    public static final int MAX_ENTRY=4*1024*1024;
    public static final int MAX_MEMBERS=20000;
    public static final int MAX_DIFF_LINES=100;
    public static final int MAX_DISPLAY=18000;
    private FileComparator(){}

    public static final class Result {
        public final boolean identical;
        public final boolean bothText;
        public final String leftHash;
        public final String rightHash;
        public final long leftBytes;
        public final long rightBytes;
        public final String detail;
        Result(boolean equal,boolean text,String a,String b,long sa,long sb,String detail){
            identical=equal;bothText=text;leftHash=a;rightHash=b;
            leftBytes=sa;rightBytes=sb;this.detail=detail;
        }
    }
    public static final class ZipInfo {
        public final String name;
        public final long size,crc,compressed;
        ZipInfo(ZipEntry entry){
            name=entry.getName();size=entry.getSize();crc=entry.getCrc();
            compressed=entry.getCompressedSize();
        }
    }
    private static void permitted(File f)throws IOException{
        if(f==null||!f.isFile()||f.length()<0||f.length()>MAX_FILE)
            throw new IOException("File absent or exceeds 96 MiB inspection budget");
    }
    private static String hash(byte[] input)throws IOException{
        try {
            MessageDigest md=MessageDigest.getInstance("SHA-256");
            md.update(input);
            return hex(md.digest());
        }catch(NoSuchAlgorithmException missing){throw new IOException("SHA-256 unavailable",missing);}
    }
    public static String sha256(File f)throws IOException{
        permitted(f);
        try{
            MessageDigest md=MessageDigest.getInstance("SHA-256");
            try(InputStream stream=new FileInputStream(f)){
                byte[] buffer=new byte[65536];int n;long sum=0;
                while((n=stream.read(buffer))!=-1){
                    if(Thread.currentThread().isInterrupted())throw new IOException("Comparison cancelled");
                    sum+=n;
                    if(sum>MAX_FILE)throw new IOException("File read exceeds budget");
                    md.update(buffer,0,n);
                }
            }
            return hex(md.digest());
        }catch(NoSuchAlgorithmException missing){throw new IOException("SHA-256 unavailable",missing);}
    }
    private static String hex(byte[] bytes){
        StringBuilder b=new StringBuilder(bytes.length*2);
        for(byte x:bytes)b.append(String.format(java.util.Locale.ROOT,"%02x",x&255));
        return b.toString();
    }
    private static byte[] bytes(File f,int cap)throws IOException{
        if(f.length()>cap)throw new IOException("Preview exceeds size limit");
        try(InputStream in=new FileInputStream(f)){return read(in,(int)f.length(),cap);}
    }
    private static byte[] read(InputStream stream,int expected,int cap)throws IOException{
        if(expected<0||expected>cap)throw new IOException("Byte preview exceeds memory budget");
        ByteArrayOutputStream out=new ByteArrayOutputStream(Math.min(expected,16384));
        byte[] b=new byte[32768];int n;
        while((n=stream.read(b))!=-1){
            if(Thread.currentThread().isInterrupted())throw new IOException("Reading cancelled");
            if(n==0)continue;
            if(out.size()>cap-n)throw new IOException("Byte preview exceeded memory budget");
            out.write(b,0,n);
        }
        if(out.size()!=expected)throw new IOException("Truncated or altered input during preview");
        return out.toByteArray();
    }
    private static String text(byte[] data){
        if(data.length>MAX_TEXT)return null;
        for(byte b:data)if(b==0)return null;
        try {
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(data)).toString();
        }catch(CharacterCodingException invalid){return null;}
    }
    public static String preview(File file)throws IOException{
        permitted(file);
        StringBuilder out=new StringBuilder();
        out.append("File: ").append(file.getName()).append("\n")
           .append("Bytes: ").append(file.length()).append("\n")
           .append("SHA-256: ").append(sha256(file)).append("\n\n");
        if(file.length()>MAX_TEXT)return out.append("Text preview unavailable (larger than 256 KiB).\n").toString();
        String value=text(bytes(file,MAX_TEXT));
        if(value==null)return out.append("Binary or non-UTF-8 file.").toString();
        return out.append(value,0,Math.min(value.length(),MAX_DISPLAY)).toString();
    }
    public static Result compare(File left,File right)throws IOException{
        permitted(left);permitted(right);
        String lhs=sha256(left),rhs=sha256(right);
        boolean equal=lhs.equals(rhs)&&left.length()==right.length();
        StringBuilder diff=new StringBuilder("BYTE COMPARISON\n")
            .append(equal?"IDENTICAL BY SHA-256\n":"DIFFERENT BY SHA-256\n")
            .append("Left bytes: ").append(left.length()).append("\n")
            .append("Right bytes: ").append(right.length()).append("\n")
            .append("Left SHA-256: ").append(lhs).append("\n")
            .append("Right SHA-256: ").append(rhs).append("\n\n");
        String a=left.length()<=MAX_TEXT?text(bytes(left,MAX_TEXT)):null;
        String b=right.length()<=MAX_TEXT?text(bytes(right,MAX_TEXT)):null;
        boolean textFiles=a!=null&&b!=null;
        if(textFiles)diff.append(lineDifferences(a,b));
        else diff.append("Binary/large data: compare hashes, bytes and (for APKs) the entry inventory.\n");
        if(looksZip(left)&&looksZip(right))
            diff.append("\n").append(zipDifferences(left,right));
        return new Result(equal,textFiles,lhs,rhs,left.length(),right.length(),trim(diff.toString()));
    }
    public static Result compareEntries(File left,String leftEntry,File right,String rightEntry)throws IOException{
        byte[] a=loadEntry(left,leftEntry,MAX_ENTRY),b=loadEntry(right,rightEntry,MAX_ENTRY);
        String ah=hash(a),bh=hash(b);
        boolean equal=ah.equals(bh)&&a.length==b.length;
        String ta=text(a),tb=text(b);
        StringBuilder detail=new StringBuilder("APK ENTRY COMPARISON\n")
            .append("Left: ").append(leftEntry).append(" (").append(a.length).append(" bytes)\n")
            .append("Right: ").append(rightEntry).append(" (").append(b.length).append(" bytes)\n")
            .append(equal?"IDENTICAL\n":"DIFFERENT\n")
            .append("Left SHA-256: ").append(ah).append("\nRight SHA-256: ").append(bh).append("\n\n");
        if(ta!=null&&tb!=null)detail.append(lineDifferences(ta,tb));
        else detail.append("Binary/large entry: hash-only comparison; no source text decoded.");
        return new Result(equal,ta!=null&&tb!=null,ah,bh,a.length,b.length,trim(detail.toString()));
    }
    public static String previewEntry(File archive,String name)throws IOException{
        byte[] raw=loadEntry(archive,name,MAX_ENTRY);
        String info="ZIP entry: "+name+"\nBytes: "+raw.length+"\nSHA-256: "+hash(raw)+"\n\n";
        String value=text(raw);
        if(value==null)return info+"Binary or over-256-KiB entry; text preview unavailable.";
        return info+trim(value);
    }
    private static String trim(String s){
        return s.length()>MAX_DISPLAY?s.substring(0,MAX_DISPLAY)+"\n... preview truncated ...":s;
    }
    private static String excerpt(String s){
        s=s.replace("\r","\\r").replace("\t","  ");
        return s.length()>150?s.substring(0,150)+"…":s;
    }
    static String lineDifferences(String a,String b){
        String[] aa=a.split("\n",-1),bb=b.split("\n",-1);
        int total=Math.max(aa.length,bb.length);
        StringBuilder result=new StringBuilder("TEXT DIFF (same-index lines, not a semantic merge)\n");
        int changes=0,visible=0;
        for(int i=0;i<total;i++){
            String left=i<aa.length?aa[i]:null,right=i<bb.length?bb[i]:null;
            if(java.util.Objects.equals(left,right))continue;
            changes++;
            if(visible++>=MAX_DIFF_LINES)continue;
            result.append("@ line ").append(i+1).append('\n');
            result.append("- ").append(left==null?"[missing]":excerpt(left)).append('\n');
            result.append("+ ").append(right==null?"[missing]":excerpt(right)).append('\n');
            if(result.length()>MAX_DISPLAY-500)break;
        }
        result.append("Mismatching line positions: ").append(changes).append("\n");
        if(changes>MAX_DIFF_LINES)result.append("Showing first ").append(MAX_DIFF_LINES).append(" differences.\n");
        if(changes==0)result.append("No line differences.\n");
        return trim(result.toString());
    }
    private static boolean looksZip(File f)throws IOException{
        permitted(f);
        if(f.length()<4)return false;
        try(InputStream in=new FileInputStream(f)){
            byte[] prefix=new byte[4];
            if(in.read(prefix)!=4)return false;
            return prefix[0]=='P' && prefix[1]=='K' &&
                ((prefix[2]==3&&prefix[3]==4)||
                 (prefix[2]==5&&prefix[3]==6)||
                 (prefix[2]==7&&prefix[3]==8));
        }
    }
    private static boolean safeName(String name){
        if(name==null||name.isEmpty()||name.startsWith("/")||name.indexOf('\\')>=0||
           name.indexOf('\0')>=0)return false;
        for(String part:name.split("/",-1))
            if(part.equals(".")||part.equals(".."))return false;
        return true;
    }
    public static Map<String,ZipInfo> inventory(File archive)throws IOException{
        permitted(archive);
        LinkedHashMap<String,ZipInfo> results=new LinkedHashMap<>();
        long total=0;
        try(ZipFile zip=new ZipFile(archive)){
            Enumeration<? extends ZipEntry> all=zip.entries();
            int memberCount=0;
            while(all.hasMoreElements()){
                if(Thread.currentThread().isInterrupted())throw new IOException("ZIP inspection cancelled");
                ZipEntry entry=all.nextElement();
                if(++memberCount>MAX_MEMBERS)throw new IOException("Too many ZIP entries");
                if(!safeName(entry.getName())||results.containsKey(entry.getName()))
                    throw new IOException("Unsafe or duplicate ZIP entry");
                if(entry.getSize()<0||entry.getCompressedSize()<0)
                    throw new IOException("Unbounded ZIP entry");
                if(total>1024L*1024L*1024L-entry.getSize())
                    throw new IOException("ZIP uncompressed budget exceeded");
                total+=entry.getSize();
                if(entry.getSize()>1048576 &&
                    (entry.getCompressedSize()==0||entry.getSize()/Math.max(1,entry.getCompressedSize())>200))
                    throw new IOException("Suspicious ZIP compression ratio");
                if(!entry.isDirectory())results.put(entry.getName(),new ZipInfo(entry));
            }
        }
        return results;
    }
    private static byte[] loadEntry(File archive,String name,int cap)throws IOException{
        if(!safeName(name))throw new IOException("Unsafe archive selection");
        inventory(archive); // verify all entries, not just the selected member
        try(ZipFile zip=new ZipFile(archive)){
            ZipEntry item=zip.getEntry(name);
            if(item==null||item.isDirectory()||item.getSize()<0||item.getSize()>cap)
                throw new IOException("ZIP entry missing or exceeds "+cap+"-byte limit");
            try(InputStream in=zip.getInputStream(item)){
                return read(in,(int)item.getSize(),cap);
            }
        }
    }
    public static String zipDifferences(File left,File right)throws IOException{
        Map<String,ZipInfo> a=inventory(left),b=inventory(right);
        Set<String> all=new LinkedHashSet<>(a.keySet());
        all.addAll(b.keySet());
        int missingLeft=0,missingRight=0,changed=0,identical=0,listed=0;
        StringBuilder out=new StringBuilder("APK ZIP ENTRY COMPARISON (size + ZIP CRC metadata)\n");
        for(String name:all){
            ZipInfo l=a.get(name),r=b.get(name);
            if(l==null){
                missingLeft++;
                if(listed++<100&&out.length()<MAX_DISPLAY-500)
                    out.append("+ only right: ").append(name).append('\n');
            }else if(r==null){
                missingRight++;
                if(listed++<100&&out.length()<MAX_DISPLAY-500)
                    out.append("- only left: ").append(name).append('\n');
            }else if(l.size!=r.size||l.crc!=r.crc){
                changed++;
                if(listed++<100&&out.length()<MAX_DISPLAY-500)
                    out.append("~ changed: ").append(name).append('\n');
            }else identical++;
        }
        out.append("Left-only: ").append(missingRight).append("\nRight-only: ").append(missingLeft)
           .append("\nChanged metadata: ").append(changed)
           .append("\nMatching metadata: ").append(identical)
           .append("\nNOTE: matching ZIP CRC is not cryptographic proof of entry equality.\n");
        return trim(out.toString());
    }
}
