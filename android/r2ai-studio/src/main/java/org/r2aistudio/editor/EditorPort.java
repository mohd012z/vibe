package org.r2aistudio.editor;
public interface EditorPort {
 String getText();
 void setText(String text);
 void gotoLine(int oneBasedLine);
 void setReadOnly(boolean value);
}
