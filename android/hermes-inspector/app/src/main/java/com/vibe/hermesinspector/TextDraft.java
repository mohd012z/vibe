package com.vibe.hermesinspector;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;

/** In-memory local text-copy history. Does not write to or re-sign imported APKs. */
public final class TextDraft {
    public static final int MAX_UTF8_BYTES=65536;
    public static final int MAX_UNDO=8;
    private final String original;
    private String current;
    private final ArrayDeque<String> undo=new ArrayDeque<>();
    public TextDraft(String original){
        if(original==null)throw new IllegalArgumentException("Missing original text");
        validate(original);
        this.original=original;
        this.current=original;
    }
    private static void validate(String text){
        if(text==null || text.getBytes(StandardCharsets.UTF_8).length>MAX_UTF8_BYTES)
            throw new IllegalArgumentException("Draft exceeds 64 KiB UTF-8 editing limit");
    }
    public String original(){return original;}
    public String current(){return current;}
    public boolean changed(){return !original.equals(current);}
    public boolean canUndo(){return !undo.isEmpty();}
    public void apply(String proposed){
        validate(proposed);
        if(current.equals(proposed))return;
        if(undo.size()>=MAX_UNDO)undo.removeFirst();
        undo.addLast(current);
        current=proposed;
    }
    public boolean undo(){
        if(undo.isEmpty())return false;
        current=undo.removeLast();
        return true;
    }
    public String diff(){
        return FileComparator.lineDifferences(original,current);
    }
}
