package com.vibe.hermesinspector;

/** Pure, bounded pagination math used by the Android results view. */
public final class SearchPager {
    public static final int PAGE_SIZE=50;
    private SearchPager(){}

    public static int pageCount(int total){
        if(total<0)throw new IllegalArgumentException("Negative item count");
        return Math.max(1,1+(Math.max(0,total)-1)/PAGE_SIZE);
    }
    public static int clamp(int requestedPage,int total){
        return Math.min(Math.max(0,requestedPage),pageCount(total)-1);
    }
    public static int start(int requestedPage,int total){
        return clamp(requestedPage,total)*PAGE_SIZE;
    }
    public static int end(int requestedPage,int total){
        return Math.min(total,start(requestedPage,total)+PAGE_SIZE);
    }
}
