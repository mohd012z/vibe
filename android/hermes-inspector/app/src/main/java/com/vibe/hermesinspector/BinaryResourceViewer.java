package com.vibe.hermesinspector;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Bounded Android binary XML/resource-table and ELF header inspector.
 * Preview output is a partial structural decoding, NOT lossless aapt2 output.
 */
public final class BinaryResourceViewer {
    public static final int MAX_BYTES=1024*1024;
    public static final int MAX_TEXT=128*1024;
    private BinaryResourceViewer(){}

    private static int u16(byte[] data,int pos)throws IOException{
        if(pos<0||pos>data.length-2)throw new IOException("Truncated binary chunk");
        return (data[pos]&255)|((data[pos+1]&255)<<8);
    }
    private static long u32(byte[] data,int pos)throws IOException{
        if(pos<0||pos>data.length-4)throw new IOException("Truncated binary chunk");
        return ((long)data[pos]&255)|(((long)data[pos+1]&255)<<8)|
               (((long)data[pos+2]&255)<<16)|(((long)data[pos+3]&255)<<24);
    }
    private static int check(long n,int size,int width)throws IOException{
        if(n<0||width<0||n>size||width>size-n||n>Integer.MAX_VALUE)
            throw new IOException("Binary resource section exceeds preview");
        return (int)n;
    }
    private static int length8(byte[] data,int[] p,int end)throws IOException{
        int first=data[check(p[0]++,end,1)]&255;
        if((first&0x80)==0)return first;
        return ((first&127)<<8)|(data[check(p[0]++,end,1)]&255);
    }
    private static int length16(byte[] data,int[] p,int end)throws IOException{
        int first=u16(data,check(p[0],end,2));p[0]+=2;
        if((first&0x8000)==0)return first;
        int second=u16(data,check(p[0],end,2));p[0]+=2;
        return ((first&0x7fff)<<16)|second;
    }
    private static String clean(String s){
        StringBuilder b=new StringBuilder();
        for(int i=0;i<s.length()&&i<512;i++){
            char ch=s.charAt(i);
            b.append(Character.isISOControl(ch)?' ':ch);
        }
        return b.toString();
    }
    private static String decode(byte[] data,int pos,int len,boolean utf16)throws IOException{
        check(pos,data.length,len);
        try{
            return clean((utf16?StandardCharsets.UTF_16LE:StandardCharsets.UTF_8)
                .newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(data,pos,len)).toString());
        }catch(CharacterCodingException invalid){
            throw new IOException("Malformed binary resource string",invalid);
        }
    }
    private static List<String> pool(byte[] data,int base,int limit)throws IOException{
        int header=u16(data,base+2);
        long chunkSize=u32(data,base+4);
        if(header<28||chunkSize<header||chunkSize>limit-base)
            throw new IOException("Invalid Android string pool size");
        long count=u32(data,base+8);
        if(count>60000)throw new IOException("Too many resource strings");
        boolean utf8=(u32(data,base+16)&0x100)!=0;
        long stringsStart=u32(data,base+20);
        if(header+count*4>chunkSize)
            throw new IOException("Resource string offsets truncated");
        ArrayList<String> output=new ArrayList<>();
        for(int i=0;i<count && i<3000;i++){
            long at=u32(data,base+header+i*4);
            int[] pos={check((long)base+stringsStart+at,base+(int)chunkSize,1)};
            final int chars,bytes;
            if(utf8){
                chars=length8(data,pos,base+(int)chunkSize);
                bytes=length8(data,pos,base+(int)chunkSize);
            }else{
                chars=length16(data,pos,base+(int)chunkSize);
                if(chars>4096)throw new IOException("Oversized UTF-16 resource string");
                bytes=chars*2;
            }
            if(bytes>32768)throw new IOException("Oversized binary resource string");
            check(pos[0],base+(int)chunkSize,bytes+ (utf8?1:2));
            String value=decode(data,pos[0],bytes,!utf8);
            output.add(value);
        }
        return output;
    }
    private static String string(List<String> values,long index){
        if(index==0xffffffffL)return "";
        return index>=0&&index<values.size()?values.get((int)index):"@string-index-"+index;
    }
    private static String attrValue(byte[] data,int base,List<String> strings)throws IOException{
        long raw=u32(data,base+8);
        if(raw!=0xffffffffL)return string(strings,raw);
        int type=data[check(base+15,data.length,1)]&255;
        long value=u32(data,base+16);
        if(type==3)return string(strings,value);
        if(type==0x12)return value==0?"false":"true";
        if(type==0x10)return Long.toString(value);
        return String.format(Locale.ROOT,"@typed(%02x):0x%08x",type,value);
    }
    private static String escape(String value){
        return value.replace("&","&amp;").replace("\"","&quot;")
                    .replace("<","&lt;").replace(">","&gt;");
    }

    public static String manifest(byte[] data)throws IOException{
        if(data==null||data.length<8||data.length>MAX_BYTES)
            throw new IOException("Binary XML unavailable or exceeds preview limit");
        if(u16(data,0)!=0x0003||u16(data,2)!=8)
            throw new IOException("Not compiled Android binary XML");
        long declared=u32(data,4);
        if(declared>data.length||declared<8)
            throw new IOException("Truncated Android binary XML");
        int offset=8;
        List<String> strings=new ArrayList<>();
        int depth=0,lines=0;
        StringBuilder out=new StringBuilder(
            "# Decoded Android binary XML (selected tags/attributes; not lossless)\n");
        while(offset<declared){
            if(++lines>700||out.length()>MAX_TEXT){out.append("<!-- preview limited -->\n");break;}
            int kind=u16(data,offset),header=u16(data,offset+2);
            long size=u32(data,offset+4);
            if(size<header||header<8||size>declared-offset)
                throw new IOException("Corrupt binary XML chunk size");
            if(kind==0x0001){
                strings=pool(data,offset,(int)declared);
            }else if(kind==0x0102 && strings.size()>0){
                if(header<16||size<36)throw new IOException("Short XML start element");
                int extension=offset+16;
                String name=string(strings,u32(data,extension+4));
                int attrStart=u16(data,extension+8);
                int attrWidth=u16(data,extension+10);
                int count=u16(data,extension+12);
                if(count>128||attrWidth<20||count*(long)attrWidth>size)
                    throw new IOException("XML attribute budget exceeded");
                StringBuilder line=new StringBuilder();
                for(int j=0;j<Math.min(depth,24);j++)line.append("  ");
                line.append('<').append(name);
                for(int i=0;i<count;i++){
                    long a=(long)extension+attrStart+(long)i*attrWidth;
                    int at=check(a,offset+(int)size,20);
                    String label=string(strings,u32(data,at+4));
                    line.append(' ').append(label).append("=\"")
                        .append(escape(attrValue(data,at,strings))).append('"');
                }
                out.append(line).append(">\n");
                depth++;
            }else if(kind==0x0103 && strings.size()>0){
                if(header<16||size<24)throw new IOException("Short XML closing element");
                depth=Math.max(0,depth-1);
                for(int j=0;j<Math.min(depth,24);j++)out.append("  ");
                out.append("</").append(string(strings,u32(data,offset+20))).append(">\n");
            }
            offset+=(int)size;
        }
        return out.toString();
    }

    public static String resourceTable(byte[] data,long trueSize)throws IOException{
        if(data==null||data.length<12||data.length>MAX_BYTES)
            throw new IOException("Resources preview size invalid");
        if(u16(data,0)!=0x0002)
            throw new IOException("Not compiled resources.arsc");
        long declared=u32(data,4);
        if(declared<12||declared!=trueSize)
            throw new IOException("Resource table length mismatch");
        StringBuilder out=new StringBuilder("# Compiled resources.arsc; global string pool preview only\n");
        out.append("Total binary bytes: ").append(trueSize).append('\n');
        long packages=u32(data,8);
        out.append("Declared resource packages: ").append(packages).append('\n');
        int offset=u16(data,2);
        if(offset>0&&offset+8<data.length&&u16(data,offset)==1){
            try{
                List<String> strings=pool(data,offset,data.length);
                out.append("Global strings indexed: ").append(strings.size()).append('\n');
                for(int i=0;i<strings.size()&&i<150&&out.length()<MAX_TEXT;i++)
                    out.append("  #").append(i).append(' ').append(strings.get(i)).append('\n');
            }catch(IOException truncated){
                out.append("# Global string pool unavailable under 1 MiB preview limit\n");
            }
        }
        out.append("# Resource IDs/type mappings not fully reconstructed.\n");
        return out.toString();
    }

    public static String elf(byte[] data,String path,long trueSize)throws IOException{
        if(data==null||data.length<20||data[0]!=0x7f||data[1]!='E'||data[2]!='L'||data[3]!='F')
            throw new IOException("Native library missing ELF signature");
        int kind=data[4]&255,endian=data[5]&255;
        if((kind!=1&&kind!=2)||(endian!=1&&endian!=2))
            throw new IOException("Unsupported ELF class or endian");
        int machine=endian==1?
            ((data[18]&255)|((data[19]&255)<<8)):
            ((data[19]&255)|((data[18]&255)<<8));
        String architecture=machine==3?"x86":machine==40?"ARM 32":
            machine==62?"x86_64":machine==183?"AArch64":
            machine==243?"RISC-V": "machine-"+machine;
        return "# Native compiled ELF library\n"+
               "File: "+path+"\n"+
               "Length: "+trueSize+" bytes\n"+
               "ELF class: "+(kind==1?"32-bit":"64-bit")+"\n"+
               "Byte order: "+(endian==1?"little":"big")+"\n"+
               "Architecture: "+architecture+"\n"+
               "# This binary does not contain original C/C++/Rust source text.\n"+
               "# Symbol tables and code flow are not reconstructed here.\n";
    }
}
