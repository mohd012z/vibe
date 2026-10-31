package org.r2aistudio.editor;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CodingErrorAction;
import java.util.Objects;
public final class Utf8DocumentCodec {
 public static final int MAX_BYTES=8*1024*1024;
 public static final class Document {
  public final String text;public final boolean bom;
  public Document(String text,boolean bom){this.text=Objects.requireNonNull(text,"text");this.bom=bom;}
 }
 private Utf8DocumentCodec(){}
 public static Document decode(byte[] bytes)throws CharacterCodingException{
  Objects.requireNonNull(bytes,"bytes");
  if(bytes.length>MAX_BYTES)throw new IllegalArgumentException("file too large");
  boolean bom=bytes.length>=3&&(bytes[0]&255)==239&&(bytes[1]&255)==187&&(bytes[2]&255)==191;
  int start=bom?3:0;
  CharBuffer chars=StandardCharsets.UTF_8.newDecoder()
   .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
   .decode(ByteBuffer.wrap(bytes,start,bytes.length-start));
  return new Document(chars.toString(),bom);
 }
 public static byte[] encode(Document doc){
  Objects.requireNonNull(doc,"doc");
  byte[] payload=doc.text.getBytes(StandardCharsets.UTF_8);
  if(payload.length+(doc.bom?3:0)>MAX_BYTES)throw new IllegalArgumentException("file too large");
  if(!doc.bom)return payload;
  byte[] result=new byte[payload.length+3];
  result[0]=(byte)0xef;result[1]=(byte)0xbb;result[2]=(byte)0xbf;
  System.arraycopy(payload,0,result,3,payload.length);
  return result;
 }
}
