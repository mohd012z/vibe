package com.vibe.hermesinspector;
import org.junit.Test;
import static org.junit.Assert.*;

public class TextDraftTest {
    @Test public void unicodeEditAndUndo(){
        TextDraft text=new TextDraft("hello\ncafé ☕");
        assertFalse(text.changed());
        text.apply("hello\nVIP demo labels ☕");
        assertTrue(text.changed());
        assertTrue(text.diff().contains("- café ☕"));
        assertTrue(text.diff().contains("+ VIP demo labels ☕"));
        assertTrue(text.undo());
        assertEquals("hello\ncafé ☕",text.current());
        assertFalse(text.undo());
    }
    @Test public void noOpChangesDoNotAddHistory(){
        TextDraft text=new TextDraft("original");
        text.apply("original");
        assertFalse(text.canUndo());
    }
    @Test public void multiStepHistoryBoundedToEight(){
        TextDraft text=new TextDraft("0");
        for(int i=1;i<=15;i++)text.apply(Integer.toString(i));
        int undone=0;while(text.undo())undone++;
        assertEquals(8,undone);
        assertEquals("7",text.current());
    }
    @Test public void oversizedUnicodeRejected(){
        TextDraft text=new TextDraft("safe");
        String huge="☕".repeat(23000);
        try{text.apply(huge);fail("Over budget accepted");}
        catch(IllegalArgumentException expected){}
        assertEquals("safe",text.current());
    }
}
