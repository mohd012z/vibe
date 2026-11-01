package com.vibe.hermesinspector;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.json.JSONArray;
import org.json.JSONException;

/** Verified-layout Hermes metadata, string, and function bytecode reader.
 * Uses pinned upstream HBC-Tool opcode mappings in assets/opcodes.
 * Does not execute bytecode or claim JavaScript source-level decompilation.
 */
public final class HbcAnalyzer {
    public static final int MAX_SOURCE = 16 * 1024 * 1024;
    public static final int MAX_NAMES = 1500;
    public static final int MAX_OPCODES = 5000;
    public static final int MAX_FUNCTIONS = 2000;
    public static final int MAX_STRING_COUNT = 500000;
    public static final int MAX_STR_LEN = 131072;
    private HbcAnalyzer() {}

    public static final class Result {
        public int version;
        public int declaredFunctions, declaredStrings, stringsIndexed, functionsIndexed, instructionsDecoded;
        public boolean truncated;
        public final List<String> strings = new ArrayList<>();
        public final List<String> functions = new ArrayList<>();
        public final List<String> instructions = new ArrayList<>();
        public final List<String> references = new ArrayList<>();
        public final List<String> warnings = new ArrayList<>();
    }
    private static long unsigned32(byte[] a,long at)throws IOException {
        int p=atPosition(a,at,4);
        return ((long)(a[p]&255))|((long)(a[p+1]&255)<<8)|
            ((long)(a[p+2]&255)<<16)|((long)(a[p+3]&255)<<24);
    }
    private static int atPosition(byte[] data,long start,int size)throws IOException{
        if(start<0||size<0||start>data.length||size>data.length-start)
            throw new IOException("HBC section exceeds supplied bytecode length");
        return (int)start;
    }
    private static long align4(long value)throws IOException {
        if(value<0||value>Long.MAX_VALUE-3)throw new IOException("HBC section overflow");
        return (value+3)&~3L;
    }
    private static long table(byte[] data,long offset,long count,long width)throws IOException {
        if(count<0||width<0||count>1_000_000L||count>Long.MAX_VALUE/Math.max(1,width))
            throw new IOException("HBC table record budget exceeded");
        long end=offset+count*width;
        if(end<offset)throw new IOException("HBC table pointer overflow");
        atPosition(data,offset,(int)Math.min(Integer.MAX_VALUE,end-offset));
        return align4(end);
    }
    private static int narrow(long value,String label)throws IOException {
        if(value>Integer.MAX_VALUE)throw new IOException("HBC "+label+" exceeds Android bounds");
        return (int)value;
    }
    private static String decoded(byte[] data,long pos,int units,boolean utf16)throws IOException {
        if(units<0||units>MAX_STR_LEN)throw new IOException("HBC string size exceeds budget");
        long bytes=(long)units*(utf16?2:1);
        int off=atPosition(data,pos,narrow(bytes,"string length"));
        try{
            return (utf16?StandardCharsets.UTF_16LE:StandardCharsets.UTF_8)
                  .newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                  .onUnmappableCharacter(CodingErrorAction.REPORT)
                  .decode(ByteBuffer.wrap(data,off,(int)bytes)).toString();
        }catch(CharacterCodingException malformed){throw new IOException("Invalid HBC UTF-8/UTF-16 string",malformed);}
    }
    private static String safe(String text) {
        StringBuilder out=new StringBuilder();
        for(int i=0;i<text.length()&&i<280;i++){
            char ch=text.charAt(i);
            out.append(Character.isISOControl(ch)?' ':ch);
        }
        return out.toString();
    }
    private static String getName(String[] cache,int id){
        if(id<0||id>=cache.length)return "<string "+id+">";
        return cache[id]!=null?safe(cache[id]):"<string "+id+">";
    }
    private static JSONArray opcodes(InputStream in)throws IOException {
        try{
            java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream();
            byte[] buffer=new byte[16384];int n;
            while((n=in.read(buffer))!=-1){
                if(out.size()+n>160000)throw new IOException("Opcode schema too large");
                out.write(buffer,0,n);
            }
            JSONArray arr=new JSONArray(out.toString("UTF-8"));
            if(arr.length()<100||arr.length()>256)throw new IOException("Invalid opcode table length");
            return arr;
        }catch(JSONException invalid){throw new IOException("Malformed opcode table",invalid);}
    }
    private static int operandWidth(String kind)throws IOException {
        if(kind.startsWith("Reg8")||kind.startsWith("UInt8")||kind.startsWith("Int8")||
           kind.startsWith("Addr8"))return 1;
        if(kind.startsWith("Reg16")||kind.startsWith("UInt16")||kind.startsWith("Int16")||
           kind.startsWith("Addr16"))return 2;
        if(kind.startsWith("Reg32")||kind.startsWith("UInt32")||kind.startsWith("Int32")||
           kind.startsWith("Addr32")||kind.startsWith("Imm32"))return 4;
        if(kind.startsWith("Double")||kind.startsWith("UInt64")||kind.startsWith("Int64"))return 8;
        throw new IOException("Unsupported Hermes operand schema: "+kind);
    }
    private static String operand(byte[] data,int offset,int size,String kind)throws IOException {
        atPosition(data,offset,size);
        long raw=0;
        for(int i=0;i<size;i++)raw|=((long)data[offset+i]&255L)<<(8*i);
        if(kind.startsWith("Double")){
            return String.valueOf(Double.longBitsToDouble(raw));
        }
        if(kind.startsWith("Addr")||kind.startsWith("Int")){
            long signed=size==1?(byte)raw:size==2?(short)raw:size==4?(int)raw:raw;
            return Long.toString(signed);
        }
        return Long.toUnsignedString(raw);
    }
    public static Result parse(byte[] data,InputStream schema)throws IOException {
        if(data==null||data.length<128||data.length>MAX_SOURCE)
            throw new IOException("Unsupported HBC bytecode size");
        if(unsigned32(data,0)!= (ApkInspector.HERMES_MAGIC & 0xffffffffL) ||
           unsigned32(data,4)!=((ApkInspector.HERMES_MAGIC>>>32)&0xffffffffL))
            throw new IOException("Missing Hermes magic");
        int version=narrow(unsigned32(data,8),"version");
        if(!ApkInspector.supportedHbc(version))
            throw new IOException("Unregistered Hermes version "+version);
        int declaredFunctions=narrow(unsigned32(data,40),"functions");
        int declaredStrings=narrow(unsigned32(data,52),"strings");
        if(declaredFunctions>1_000_000 || declaredStrings>MAX_STRING_COUNT)
            throw new IOException("HBC header table record limit exceeded");
        int kindCount=narrow(unsigned32(data,44),"string kinds");
        int identifierCount=narrow(unsigned32(data,48),"identifiers");
        int overflowCount=narrow(unsigned32(data,56),"overflow strings");
        int storageSize=narrow(unsigned32(data,60),"string storage");
        if(declaredFunctions<0||declaredStrings<0||storageSize>data.length)
            throw new IOException("HBC declared section too large");
        Result result=new Result();
        result.version=version;
        result.declaredFunctions=declaredFunctions;
        result.declaredStrings=declaredStrings;

        long functionTable=128;
        int functionHeaderWidth=version<=96?16:12;
        long offset=table(data,functionTable,declaredFunctions,functionHeaderWidth);
        offset=table(data,offset,kindCount,4);
        offset=table(data,offset,identifierCount,4);
        long stringTable=offset;
        offset=table(data,offset,declaredStrings,4);
        long overflowTable=offset;
        offset=table(data,offset,overflowCount,8);
        long stringStorage=offset;
        atPosition(data,stringStorage,storageSize);
        String[] cache=new String[declaredStrings];

        for(int id=0;id<declaredStrings;id++){
            long entry=unsigned32(data,stringTable+(long)id*4);
            boolean utf16=(entry&1)!=0;
            long strOff=(entry>>>1)&0x7fffff;
            long units=(entry>>>24)&255;
            if(units==255){
                if(strOff>=overflowCount)throw new IOException("Invalid HBC overflow string index");
                units=unsigned32(data,overflowTable+8*strOff+4);
                strOff=unsigned32(data,overflowTable+8*strOff);
            }
            if(units>MAX_STR_LEN) {
                result.truncated=true;
                continue;
            }
            String value=decoded(data,stringStorage+strOff,narrow(units,"string length"),utf16);
            if(id<5000)cache[id]=value;
            if(result.strings.size()<MAX_NAMES && !value.isEmpty()){
                result.strings.add(String.format(Locale.ROOT,"HBC str#%d [%s] %s",
                        id,utf16?"UTF-16":"UTF-8",safe(value)));
            }else if(result.strings.size()>=MAX_NAMES)result.truncated=true;
            result.stringsIndexed++;
        }
        boolean modern=version>=98;
        JSONArray definitions=opcodes(schema);
        int fnLimit=Math.min(declaredFunctions,MAX_FUNCTIONS);
        for(int fid=0;fid<fnLimit;fid++){
            long header=functionTable+(long)fid*functionHeaderWidth;
            long w0=unsigned32(data,header),w1=unsigned32(data,header+4);
            long absolute=w0&0x1ffffffL;
            int functionName=(int)((w1 >>> (modern?14:15))& (modern?255:0x1ffff));
            long byteSize=w1& (modern?0x3fff:0x7fff);
            int flags=data[atPosition(data,header+functionHeaderWidth-1,1)]&255;
            if((flags&0x20)!=0){
                long largeOffset=((long)functionName<<24)|absolute;
                atPosition(data,largeOffset,modern?32:32);
                absolute=unsigned32(data,largeOffset);
                byteSize=unsigned32(data,largeOffset+(modern?12:8));
                functionName=narrow(unsigned32(data,largeOffset+(modern?16:12)),"large function name");
            }
            String name=getName(cache,functionName);
            result.functions.add(String.format(Locale.ROOT,
                "fn#%d  %s  byte@%d  length %d",fid,name,absolute,byteSize));
            result.functionsIndexed++;
            if(byteSize==0)continue;
            if(byteSize>MAX_SOURCE||absolute<0||absolute+byteSize>data.length){
                result.warnings.add("Function #"+fid+" bytecode outside scanned source");
                result.truncated=true;continue;
            }
            int pos=(int)absolute,end=(int)(absolute+byteSize);
            int ordinal=0;
            while(pos<end){
                if(result.instructionsDecoded>=MAX_OPCODES){result.truncated=true;break;}
                int at=pos,opcode=data[pos++]&255;
                if(opcode>=definitions.length())
                    throw new IOException("Unknown Hermes opcode "+opcode+" in function "+fid);
                try{
                    JSONArray def=definitions.getJSONArray(opcode);
                    String mnemonic=def.getString(0);
                    JSONArray operands=def.getJSONArray(1);
                    StringBuilder line=new StringBuilder();
                    line.append("fn#").append(fid).append(" +").append(at-absolute)
                        .append(" ").append(mnemonic);
                    for(int a=0;a<operands.length();a++){
                        String kind=operands.getString(a);
                        int width=operandWidth(kind);
                        if(pos+width>end)throw new IOException("Truncated opcode operand in function "+fid);
                        String v=operand(data,pos,width,kind);
                        pos+=width;
                        line.append(a==0?"  ":", ").append(kind).append(":").append(v);
                        if(kind.endsWith(":S")){
                            long sid=Long.parseLong(v);
                            if(sid>=0&&sid<cache.length && result.references.size()<MAX_NAMES){
                                result.references.add("fn#"+fid+" +"+(at-absolute)+
                                    " "+mnemonic+" → HBC str#"+sid+" "+getName(cache,(int)sid));
                            }
                        }
                    }
                    result.instructions.add(line.toString());
                    result.instructionsDecoded++;ordinal++;
                }catch(JSONException malformed){
                    throw new IOException("Invalid opcode definition for "+opcode,malformed);
                }
            }
            if(result.instructionsDecoded>=MAX_OPCODES)break;
        }
        if(fnLimit<declaredFunctions)result.truncated=true;
        if(result.truncated)
            result.warnings.add("Native Hermes index is bounded; not all records/bytecode are shown.");
        result.warnings.add("Hermes opcode listings are bytecode disassembly, not reconstructed JavaScript source.");
        return result;
    }
}
