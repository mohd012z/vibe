package com.vibe.hermesinspector;

import java.io.IOException;
import java.nio.charset.CharacterCodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Read-only, bounds checked Android DEX indexing (not a Dalvik decompiler). */
public final class DexAnalyzer {
    public static final int MAX_DEX_BYTES = 32 * 1024 * 1024;
    private static final int MAX_TABLE_ROWS = 1_000_000;
    private static final int MAX_NAMES = 2000;
    private static final int MAX_METHOD_REFS = 2500;
    private static final int MAX_STRINGS = 4000;
    private static final int MAX_STRING_BYTES = 65536;
    private DexAnalyzer() {}

    public static final class Result {
        public String version;
        public int declaredStrings, declaredTypes, declaredMethods, declaredClasses;
        public final List<String> strings = new ArrayList<>();
        public final List<String> classNames = new ArrayList<>();
        public final List<String> methodReferences = new ArrayList<>();
        public final List<String> issues = new ArrayList<>();
    }

    private static long uint(byte[] x,int index) throws IOException {
        if(index<0 || index> x.length-4)throw new IOException("Truncated DEX number");
        return Integer.toUnsignedLong(ByteBuffer.wrap(x,index,4).order(ByteOrder.LITTLE_ENDIAN).getInt());
    }
    private static int u16(byte[] x,int index) throws IOException {
        if(index<0 || index>x.length-2)throw new IOException("Truncated DEX short");
        return (x[index]&255)|((x[index+1]&255)<<8);
    }
    private static int checked(long n,String what) throws IOException {
        if(n<0 || n> Integer.MAX_VALUE) throw new IOException("DEX "+what+" exceeds indexed range");
        return (int)n;
    }
    private static void table(byte[] data,int count,int offset,int rowSize,String label)throws IOException{
        if(count<0||count>MAX_TABLE_ROWS)throw new IOException(label+" row limit exceeded");
        if(offset<0 || (long)offset+(long)count*rowSize>data.length)
            throw new IOException(label+" table outside DEX file");
    }
    private static int[] lebU(byte[] data,int pos) throws IOException {
        long value=0;
        for(int i=0;i<5;i++){
            if(pos+i>=data.length)throw new IOException("Truncated DEX string size");
            int octet=data[pos+i]&255;
            value|=(long)(octet&127)<<(i*7);
            if((octet&128)==0){
                if(value>0xffffffffL)throw new IOException("DEX ULEB overflow");
                return new int[]{checked(value,"string size"),pos+i+1};
            }
        }
        throw new IOException("Malformed DEX ULEB128");
    }

    /**
     * Decode Modified UTF-8 as used in DEX string_data_item.
     * Enforces declared UTF16 code-unit count, rejects invalid byte sequences.
     */
    static String stringAt(byte[] data,int offset) throws IOException {
        if(offset<=0 || offset>=data.length)throw new IOException("Invalid DEX string-data offset");
        int[] length=lebU(data,offset);
        int expected=length[0],pos=length[1],begin=pos;
        if(expected>MAX_STRING_BYTES)throw new IOException("Oversized DEX string");
        StringBuilder value=new StringBuilder(Math.min(expected,4096));
        while(true){
            if(pos>=data.length || pos-begin>MAX_STRING_BYTES*3)throw new IOException("Truncated DEX string");
            int a=data[pos++]&255;
            if(a==0)break;
            int cp;
            if(a<128) cp=a;
            else if((a&0xe0)==0xc0){
                if(pos>=data.length)throw new IOException("Truncated two-byte DEX string");
                int b=data[pos++]&255;
                if((b&0xc0)!=0x80)throw new IOException("Malformed DEX continuation");
                cp=((a&31)<<6)|(b&63);
                if(cp<128 && !(a==0xc0 && b==0x80))throw new IOException("Overlong DEX string");
            }else if((a&0xf0)==0xe0){
                if(pos+1>=data.length)throw new IOException("Truncated three-byte DEX string");
                int b=data[pos++]&255, c=data[pos++]&255;
                if((b&0xc0)!=0x80||(c&0xc0)!=0x80)throw new IOException("Malformed DEX continuation");
                cp=((a&15)<<12)|((b&63)<<6)|(c&63);
                if(cp<2048)throw new IOException("Overlong DEX string");
            }else throw new IOException("Unsupported DEX string encoding");
            value.append((char)cp);
            if(value.length()>expected)throw new IOException("DEX string exceeds declared length");
        }
        if(value.length()!=expected)throw new IOException("DEX string length mismatch");
        return value.toString();
    }

    private static String validLabel(String text){
        StringBuilder b=new StringBuilder();
        for(int i=0;i<text.length() && i<240;i++){
            char c=text.charAt(i);
            b.append(Character.isISOControl(c)?' ':c);
        }
        return b.toString();
    }

    public static Result inspect(byte[] data)throws IOException{
        if(data==null||data.length<112||data.length>MAX_DEX_BYTES)
            throw new IOException("DEX file size invalid or exceeds 32 MiB");
        if(data[0]!='d'||data[1]!='e'||data[2]!='x'||data[3]!='\n'||
           data[7]!=0||data[4]<'0'||data[4]>'9'||
           data[5]<'0'||data[5]>'9'||data[6]<'0'||data[6]>'9')
            throw new IOException("DEX magic/version invalid");
        if(uint(data,32)!=data.length) throw new IOException("DEX declared file length mismatch");
        if(uint(data,36)<112 || uint(data,36)>data.length)
            throw new IOException("DEX header size invalid");
        if(uint(data,40)!=0x12345678L) throw new IOException("Unsupported DEX byte order");
        int countStr=checked(uint(data,56),"strings"),offStr=checked(uint(data,60),"strings");
        int countType=checked(uint(data,64),"types"),offType=checked(uint(data,68),"types");
        int countMeth=checked(uint(data,88),"methods"),offMeth=checked(uint(data,92),"methods");
        int countClass=checked(uint(data,96),"classes"),offClass=checked(uint(data,100),"classes");
        table(data,countStr,offStr,4,"stringIds");
        table(data,countType,offType,4,"typeIds");
        table(data,countMeth,offMeth,8,"methodIds");
        table(data,countClass,offClass,32,"classDefs");
        Result out=new Result();
        out.version=new String(data,4,3,StandardCharsets.US_ASCII);
        out.declaredStrings=countStr;out.declaredTypes=countType;
        out.declaredMethods=countMeth;out.declaredClasses=countClass;
        java.util.HashMap<Integer,String> cache=new java.util.HashMap<>();
        class StringLookup {
            String get(int id)throws IOException {
                if(id<0||id>=countStr)throw new IOException("DEX invalid string ID");
                String value=cache.get(id);
                if(value!=null)return value;
                int item=checked(uint(data,offStr+id*4),"string-data");
                value=stringAt(data,item);
                if(cache.size()<12000)cache.put(id,value);
                return value;
            }
        }
        StringLookup lookup=new StringLookup();
        Set<String> seen=new HashSet<>();
        for(int i=0;i<countClass && out.classNames.size()<MAX_NAMES;i++){
            int type=checked(uint(data,offClass+32*i),"class type");
            if(type>=countType)throw new IOException("DEX class index exceeds types");
            int stringIdx=checked(uint(data,offType+4*type),"class descriptor index");
            if(stringIdx>=countStr)throw new IOException("DEX class descriptor index exceeds strings");
            String name=lookup.get(stringIdx);
            if(name!=null && seen.add(name))out.classNames.add(validLabel(name));
        }
        for(int i=0;i<countMeth && out.methodReferences.size()<MAX_METHOD_REFS;i++){
            int classId=u16(data,offMeth+8*i);
            int proto=u16(data,offMeth+8*i+2);
            int nameId=checked(uint(data,offMeth+8*i+4),"method name");
            if(classId>=countType || nameId>=countStr)
                throw new IOException("DEX method index exceeds referenced tables");
            String owner=lookup.get(checked(uint(data,offType+4*classId),"method owner descriptor"));
            String method=lookup.get(nameId);
            if(owner!=null && method!=null)
                out.methodReferences.add(String.format(Locale.ROOT,"%d  %s → %s [proto %d]",
                         i,validLabel(owner),validLabel(method),proto));
        }
        for(int i=0;i<countStr && out.strings.size()<MAX_STRINGS;i++){
            String value=lookup.get(i);
            if(value!=null && !value.isEmpty())out.strings.add(String.format(Locale.ROOT,"#%d  %s",i,validLabel(value)));
        }
        if(out.strings.size()<countStr)out.issues.add("DEX strings capped at "+MAX_STRINGS+" display items");
        if(out.methodReferences.size()<countMeth)out.issues.add("Method references capped at "+MAX_METHOD_REFS+" display items");
        if(out.classNames.size()<countClass)out.issues.add("Class names capped at "+MAX_NAMES+" display items");
        out.issues.add("DEX method IDs reference methods; this is not a control-flow or source-code decompiler.");
        return out;
    }
}
