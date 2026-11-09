package org.r2aistudio.editor;
import java.io.*;
import java.util.Objects;
public final class StreamDocumentIO {
 private StreamDocumentIO(){}
 public static Utf8DocumentCodec.Document read(InputStream input)throws IOException{
  Objects.requireNonNull(input,"input");
  ByteArrayOutputStream output=new ByteArrayOutputStream();
  byte[] buffer=new byte[8192];int n;
  while((n=input.read(buffer))!=-1){
   if(n==0){
    int single=input.read();if(single==-1)break;
    if(output.size()>=Utf8DocumentCodec.MAX_BYTES)throw new IOException("file too large");
    output.write(single);continue;
   }
   if(n>Utf8DocumentCodec.MAX_BYTES-output.size())throw new IOException("file too large");
   output.write(buffer,0,n);
  }
  return Utf8DocumentCodec.decode(output.toByteArray());
 }
 public static void write(OutputStream output,Utf8DocumentCodec.Document doc)throws IOException{
  Objects.requireNonNull(output,"output");
  output.write(Utf8DocumentCodec.encode(doc));output.flush();
 }
}
