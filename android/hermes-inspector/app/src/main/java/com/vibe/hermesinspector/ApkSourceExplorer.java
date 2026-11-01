package com.vibe.hermesinspector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Field;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.instruction.OneRegisterInstruction;
import org.jf.dexlib2.iface.instruction.TwoRegisterInstruction;
import org.jf.dexlib2.iface.instruction.ThreeRegisterInstruction;
import org.jf.dexlib2.iface.instruction.FiveRegisterInstruction;
import org.jf.dexlib2.iface.instruction.RegisterRangeInstruction;
import org.jf.dexlib2.iface.instruction.NarrowLiteralInstruction;
import org.jf.dexlib2.iface.instruction.WideLiteralInstruction;
import org.jf.dexlib2.iface.instruction.OffsetInstruction;

/**
 * Offline source browser for the bytes *actually packaged* inside an authorized APK.
 * DEX output is Smali-like bytecode, not original Java/Kotlin; Flutter ELF is native.
 * Never executes code, requests network permissions, or modifies input.
 */
public final class ApkSourceExplorer {
    public static final int MAX_INDEX=45000;
    public static final int MAX_DEX=32*1024*1024;
    public static final int MAX_TEXT=256*1024;
    public static final int MAX_INSTRUCTIONS=12000;
    public static final int MAX_CLASS_METHODS=1500;
    private static final int MAX_ASSET=256*1024;
    private ApkSourceExplorer(){}

    public static final class Entry {
        public final String kind;
        public final String archivePath;
        public final String classDescriptor;
        public final String title;
        public Entry(String kind,String archivePath,String classDescriptor,String title){
            this.kind=kind;
            this.archivePath=archivePath;
            this.classDescriptor=classDescriptor;
            this.title=title;
        }
        @Override public String toString(){return title;}
    }

    public static final class Result {
        public final List<Entry> entries=new ArrayList<>();
        public int dexFiles;
        public int totalDexClasses;
        public int totalAssets;
        public boolean truncated;
        public final List<String> warnings=new ArrayList<>();
    }

    public static Result index(File apk)throws IOException{
        if(apk==null || !apk.isFile() || apk.length()>ApkInspector.MAX_APK_BYTES ||
           apk.length()<22)throw new IOException("No valid bounded APK selected");
        Result result=new Result();
        try(ZipFile zip=new ZipFile(apk)){
            Enumeration<? extends ZipEntry> all=zip.entries();
            int members=0;
            while(all.hasMoreElements()){
                if(Thread.currentThread().isInterrupted())
                    throw new IOException("Source indexing interrupted");
                ZipEntry member=all.nextElement();
                if(++members>ApkInspector.MAX_ENTRIES)
                    throw new IOException("APK has too many ZIP entries");
                String path=member.getName();
                if(!safePath(path))throw new IOException("Unsafe ZIP member");
                if(member.isDirectory())continue;
                if(result.entries.size()<MAX_INDEX){
                    result.entries.add(new Entry("file",path,null,"FILE  "+path));
                    result.totalAssets++;
                }else result.truncated=true;
                if(!isDex(path))continue;
                result.dexFiles++;
                if(member.getSize()<=0 || member.getSize()>MAX_DEX){
                    result.warnings.add(path+": DEX too large to browse");
                    continue;
                }
                try{
                    byte[] bytes=readBounded(zip,member,MAX_DEX);
                    DexBackedDexFile dex=DexBackedDexFile.fromInputStream(null,
                                           new ByteArrayInputStream(bytes));
                    for(ClassDef cls:dex.getClasses()){
                        result.totalDexClasses++;
                        if(result.entries.size()<MAX_INDEX){
                            result.entries.add(new Entry("class",path,cls.getType(),
                                "CLASS  "+cls.getType()+"  ["+path+"]"));
                        }else result.truncated=true;
                    }
                }catch(RuntimeException | IOException malformed){
                    result.warnings.add(path+": cannot browse DEX classes: "+reason(malformed));
                }
            }
        }
        if(result.truncated)result.warnings.add("Index capped at "+MAX_INDEX+" items");
        return result;
    }

    public static String open(File apk,Entry entry)throws IOException {
        if(apk==null||entry==null)throw new IOException("No APK source entry selected");
        if(apk.length()>ApkInspector.MAX_APK_BYTES || !apk.isFile())
            throw new IOException("APK no longer available");
        if(!safePath(entry.archivePath))throw new IOException("Unsafe source path");
        try(ZipFile zip=new ZipFile(apk)){
            ZipEntry member=zip.getEntry(entry.archivePath);
            if(member==null||member.isDirectory())
                throw new IOException("Requested APK file is missing");
            if("class".equals(entry.kind)){
                if(!isDex(entry.archivePath)||entry.classDescriptor==null)
                    throw new IOException("Invalid DEX class reference");
                return openClass(zip,member,entry.classDescriptor);
            }
            if(!"file".equals(entry.kind))throw new IOException("Unknown source type");
            String name=entry.archivePath.toLowerCase(Locale.ROOT);
            if(isDex(name))return dexSummary(zip,member);
            if(name.endsWith(".so") || name.endsWith(".o") || name.endsWith(".a"))
                return binarySummary(member,"Native ELF / binary library: source not included");
            if(name.equals("resources.arsc"))
                return binarySummary(member,"Android binary resource table: requires a resource decoder");
            if(name.equals("androidmanifest.xml"))
                return binarySummary(member,"Compiled AndroidManifest.xml binary XML; original XML unavailable");
            if(!isText(name))
                return binarySummary(member,"Binary or unsupported asset; original source unavailable");
            if(member.getSize()<0||member.getSize()>MAX_ASSET)
                throw new IOException("Text asset larger than 256 KiB preview limit");
            byte[] data=readBounded(zip,member,MAX_ASSET);
            if(containsNull(data))throw new IOException("Text source contains binary NUL bytes");
            try{
                String decoded=StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(data)).toString();
                return "# Packaged text asset: "+entry.archivePath+"\n\n"+decoded;
            }catch(CharacterCodingException invalid){
                throw new IOException("Asset is not valid UTF-8 source text",invalid);
            }
        }
    }

    private static String dexSummary(ZipFile zip,ZipEntry member)throws IOException{
        byte[] data=readBounded(zip,member,MAX_DEX);
        try{
            DexBackedDexFile file=DexBackedDexFile.fromInputStream(null,
                                        new ByteArrayInputStream(data));
            StringBuilder out=new StringBuilder();
            out.append("# ").append(member.getName()).append("\n");
            out.append("# Dalvik executable. Select a CLASS entry to see method bodies.\n");
            out.append("# Original Java/Kotlin files are NOT contained in a DEX.\n\n");
            out.append("DEX classes: ").append(file.getClasses().size()).append("\n");
            return out.toString();
        }catch(RuntimeException invalid){
            throw new IOException("Malformed DEX",invalid);
        }
    }

    private static String openClass(ZipFile zip,ZipEntry member,String descriptor)
            throws IOException {
        if(descriptor.length()>1000||!descriptor.startsWith("L")||!descriptor.endsWith(";"))
            throw new IOException("Invalid class descriptor");
        byte[] data=readBounded(zip,member,MAX_DEX);
        try{
            DexBackedDexFile file=DexBackedDexFile.fromInputStream(null,
                                                 new ByteArrayInputStream(data));
            ClassDef found=null;
            for(ClassDef cls:file.getClasses()){
                if(cls.getType().equals(descriptor)){found=cls;break;}
            }
            if(found==null)throw new IOException("Class not found in selected DEX");
            return formatClass(found);
        }catch(RuntimeException malformed){
            throw new IOException("DEX class could not be disassembled safely",malformed);
        }
    }

    static String formatClass(ClassDef cls){
        StringBuilder out=new StringBuilder();
        out.append("# Reconstructed Smali-like bytecode view; not compilable original source.\n");
        out.append(".class ").append(cls.getType())
           .append("  # flags: 0x").append(Integer.toHexString(cls.getAccessFlags())).append("\n");
        if(cls.getSuperclass()!=null)out.append(".super ").append(cls.getSuperclass()).append("\n");
        for(String iface:cls.getInterfaces())out.append(".implements ").append(iface).append("\n");
        out.append("\n");
        for(Field field:cls.getFields()){
            if(out.length()>MAX_TEXT){out.append("\n# Output truncated\n");return out.toString();}
            out.append(".field ").append(field.getName()).append(":").append(field.getType())
               .append("  # flags: 0x").append(Integer.toHexString(field.getAccessFlags())).append("\n");
        }
        out.append("\n");
        int methods=0,opcodes=0;
        for(Method method:cls.getMethods()){
            if(++methods>MAX_CLASS_METHODS||out.length()>MAX_TEXT){
                out.append("\n# Method/output budget exceeded\n");break;
            }
            out.append(".method ").append(method.getName()).append("(");
            for(CharSequence param:method.getParameterTypes())out.append(param);
            out.append(")").append(method.getReturnType());
            out.append("  # flags: 0x").append(Integer.toHexString(method.getAccessFlags())).append("\n");
            MethodImplementation body=method.getImplementation();
            if(body!=null){
                out.append("    .registers ").append(body.getRegisterCount()).append("\n");
                int address=0;
                for(Instruction ins:body.getInstructions()){
                    if(++opcodes>MAX_INSTRUCTIONS||out.length()>MAX_TEXT){
                        out.append("    # Instruction/preview budget exceeded\n");break;
                    }
                    out.append("    # +").append(address).append("  ")
                        .append(ins.getOpcode().name).append(formatOperands(ins)).append("\n");
                    address+=ins.getCodeUnits();
                }
            }else out.append("    # No bytecode body (native/abstract method)\n");
            out.append(".end method\n\n");
            if(opcodes>MAX_INSTRUCTIONS)break;
        }
        return out.toString();
    }

    private static String formatOperands(Instruction op){
        List<String> registers=new ArrayList<>(5);
        if(op instanceof FiveRegisterInstruction){
            FiveRegisterInstruction i=(FiveRegisterInstruction)op;
            int n=i.getRegisterCount();
            if(n>0)registers.add("v"+i.getRegisterC());
            if(n>1)registers.add("v"+i.getRegisterD());
            if(n>2)registers.add("v"+i.getRegisterE());
            if(n>3)registers.add("v"+i.getRegisterF());
            if(n>4)registers.add("v"+i.getRegisterG());
        }else if(op instanceof RegisterRangeInstruction){
            RegisterRangeInstruction i=(RegisterRangeInstruction)op;
            if(i.getRegisterCount()>0)
                registers.add("{v"+i.getStartRegister()+" .. v"+
                    (i.getStartRegister()+i.getRegisterCount()-1)+"}");
        }else if(op instanceof ThreeRegisterInstruction){
            ThreeRegisterInstruction i=(ThreeRegisterInstruction)op;
            registers.add("v"+i.getRegisterA());
            registers.add("v"+i.getRegisterB());
            registers.add("v"+i.getRegisterC());
        }else if(op instanceof TwoRegisterInstruction){
            TwoRegisterInstruction i=(TwoRegisterInstruction)op;
            registers.add("v"+i.getRegisterA());
            registers.add("v"+i.getRegisterB());
        }else if(op instanceof OneRegisterInstruction){
            registers.add("v"+((OneRegisterInstruction)op).getRegisterA());
        }
        if(op instanceof ReferenceInstruction)
            registers.add(String.valueOf(((ReferenceInstruction)op).getReference()));
        if(op instanceof WideLiteralInstruction)
            registers.add("#"+((WideLiteralInstruction)op).getWideLiteral());
        else if(op instanceof NarrowLiteralInstruction)
            registers.add("#"+((NarrowLiteralInstruction)op).getNarrowLiteral());
        if(op instanceof OffsetInstruction)
            registers.add("offset "+((OffsetInstruction)op).getCodeOffset());
        return registers.isEmpty()?"":"  "+String.join(", ",registers);
    }

    static boolean isText(String name){
        String lower=name.toLowerCase(Locale.ROOT);
        for(String ext:new String[]{".js",".jsx",".ts",".tsx",".json",".html",".htm",
            ".css",".xml",".txt",".md",".yaml",".yml",".properties",".cfg",".ini",
            ".sh",".py",".lua",".csv",".svg",".webmanifest",".map",".gradle",".pro",
            ".kt",".java",".smali",".c",".cpp",".h",".wasm.txt"}){
            if(lower.endsWith(ext))return true;
        }
        return false;
    }
    private static boolean isDex(String name){
        return name.matches("classes[0-9]*\\.dex");
    }
    private static boolean safePath(String name){
        if(name==null||name.isEmpty()||name.startsWith("/")||name.indexOf('\\')>=0||
           name.indexOf('\0')>=0)return false;
        for(String part:name.split("/",-1))if(part.equals("..")||part.equals("."))return false;
        return true;
    }
    private static boolean containsNull(byte[] raw){
        for(byte b:raw)if(b==0)return true;
        return false;
    }
    private static String binarySummary(ZipEntry member,String reason){
        return "# "+member.getName()+"\n# "+reason+
          "\n# Uncompressed bytes: "+member.getSize()+
          "\n# Only read-only metadata exposed; original text source cannot be recovered.";
    }
    private static byte[] readBounded(ZipFile zip,ZipEntry member,int cap)throws IOException{
        if(member.getSize()<0||member.getSize()>cap)throw new IOException("Source exceeds per-item limit");
        ByteArrayOutputStream buffer=new ByteArrayOutputStream();
        try(InputStream input=zip.getInputStream(member)){
            byte[] block=new byte[32768];int count;
            while((count=input.read(block))!=-1){
                if(Thread.currentThread().isInterrupted())throw new IOException("Source read cancelled");
                if(buffer.size()>cap-count)throw new IOException("Source exceeds memory limit");
                buffer.write(block,0,count);
            }
        }
        if(buffer.size()!=member.getSize())throw new IOException("Truncated ZIP member");
        return buffer.toByteArray();
    }
    private static String reason(Throwable e){
        String why=e.getMessage();
        if(why==null)return e.getClass().getSimpleName();
        return why.length()>180?why.substring(0,180):why;
    }
}
