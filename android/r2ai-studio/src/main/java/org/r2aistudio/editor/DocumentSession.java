package org.r2aistudio.editor;
import java.util.Objects;
public final class DocumentSession {
 private final EditorPort editor;
 private String savedText;
 private String documentId;
 public DocumentSession(EditorPort editor) {this.editor=Objects.requireNonNull(editor,"editor");}
 public void open(String id,String text,boolean readOnly) {
  Objects.requireNonNull(id,"id");Objects.requireNonNull(text,"text");
  if(id.isEmpty())throw new IllegalArgumentException("empty id");
  editor.setText(text);editor.setReadOnly(readOnly);documentId=id;savedText=text;
 }
 public String id(){return documentId;}
 public boolean isDirty(){ensureOpen();return !savedText.equals(editor.getText());}
 public String snapshot(){ensureOpen();return Objects.requireNonNull(editor.getText(),"editor text");}
 public void acknowledgeSaved(String persistedSnapshot){
  ensureOpen();Objects.requireNonNull(persistedSnapshot,"persistedSnapshot");
  if(!persistedSnapshot.equals(editor.getText()))throw new IllegalStateException("editor changed during save");
  savedText=persistedSnapshot;
 }
 public void gotoLine(int line){
  ensureOpen();
  if(line<1||line>countLines(editor.getText()))throw new IllegalArgumentException("line out of range");
  editor.gotoLine(line);
 }
 public static int countLines(String s){
  Objects.requireNonNull(s,"text");int n=1;
  for(int i=0;i<s.length();i++)if(s.charAt(i)=='\n')n++;
  return n;
 }
 private void ensureOpen(){if(documentId==null)throw new IllegalStateException("no document open");}
}
