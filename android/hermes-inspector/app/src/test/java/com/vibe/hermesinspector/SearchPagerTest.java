package com.vibe.hermesinspector;
import org.junit.Test;
import static org.junit.Assert.*;

public class SearchPagerTest {
    @Test public void zeroAndExactBoundary(){
        assertEquals(1,SearchPager.pageCount(0));
        assertEquals(1,SearchPager.pageCount(50));
        assertEquals(2,SearchPager.pageCount(51));
        assertEquals(50,SearchPager.end(0,51));
        assertEquals(50,SearchPager.start(1,51));
        assertEquals(51,SearchPager.end(1,51));
    }
    @Test public void clampAndMoreThan2000(){
        assertEquals(0,SearchPager.clamp(-9,5000));
        assertEquals(99,SearchPager.clamp(999,5000));
        assertEquals(4950,SearchPager.start(999,5000));
        assertEquals(5000,SearchPager.end(999,5000));
    }
    @Test public void rejectsImpossibleTotals(){
        try{SearchPager.pageCount(-1);fail("Negative totals must fail");}
        catch(IllegalArgumentException expected){assertNotNull(expected.getMessage());}
    }
}
