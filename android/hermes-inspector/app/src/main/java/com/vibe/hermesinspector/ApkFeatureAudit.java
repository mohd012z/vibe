package com.vibe.hermesinspector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Method;

/**
 * Evidence-first keyword audit for authorized APKs.
 * Matches are static references, not proof that a feature is enabled or charged.
 * This class never edits bytecode, purchases, signatures, or entitlement checks.
 */
public final class ApkFeatureAudit {
    public enum Topic {
        PREMIUM("Premium / VIP / Pro"),
        SUBSCRIPTION("Subscription / Paywall"),
        BILLING("Store / Billing SDK"),
        ADVERTISING("Advertising SDK / Ads"),
        TRACKING("Analytics / Attribution");

        public final String title;
        Topic(String title){this.title=title;}
    }

    public static final int MAX_APK_BYTES=ApkInspector.MAX_APK_BYTES > Integer.MAX_VALUE
        ? Integer.MAX_VALUE : (int)ApkInspector.MAX_APK_BYTES;
    public static final int MAX_DEX_BYTES=32*1024*1024;
    public static final int MAX_TOTAL_DEX_BYTES=64*1024*1024;
    public static final int MAX_HITS_PER_TOPIC=400;
    public static final int MAX_PREVIEW=220;
    public static final int MAX_STRINGS_SCANNED=400000;
    public static final int MAX_CLASSES_SCANNED=60000;
    public static final int MAX_METHODS_SCANNED=350000;

    private static final Map<Topic,Pattern> PATTERNS=new EnumMap<>(Topic.class);
    static {
        PATTERNS.put(Topic.PREMIUM,Pattern.compile(
            "(?:\\bvip\\b|\\bpremium\\b|\\bpro\\b|\\bentitlement\\b|pro[_/-]?user|premium[_/-]?user)",
            Pattern.CASE_INSENSITIVE));
        PATTERNS.put(Topic.SUBSCRIPTION,Pattern.compile(
            "(?:\\bsubscription\\b|\\bsubscribe\\b|\\bpaywall\\b|subscribed|renewal|restore[_-]?purchase)",
            Pattern.CASE_INSENSITIVE));
        PATTERNS.put(Topic.BILLING,Pattern.compile(
            "(?:billingclient|billingresult|purchasesupdated|inapp[_-]?purchase|\\bpurchase\\b|\\bsku\\b|productdetails|play\\.billing)",
            Pattern.CASE_INSENSITIVE));
        PATTERNS.put(Topic.ADVERTISING,Pattern.compile(
            "(?:admob|adview|adrequest|adloader|adunit|interstitial|rewarded[_-]?ad|app[_-]?lovin|maxsdk|ironsource|unityads|gms[./]ads|mediation|\\badvertis(?:e|ing|ement)\\b)",
            Pattern.CASE_INSENSITIVE));
        PATTERNS.put(Topic.TRACKING,Pattern.compile(
            "(?:firebase[_./]?analytics|adjust\\.sdk|appsflyer|branch\\.io|attribution|facebook[_./]?analytics|analytics[_-]?event|mixpanel)",
            Pattern.CASE_INSENSITIVE));
    }

    public static final class Hit {
        public final Topic topic;
        public final String kind;
        public final String dexPath;
        public final String classDescriptor;
        public final String evidence;
        Hit(Topic topic,String kind,String dexPath,String classDescriptor,String evidence){
            this.topic=topic;this.kind=kind;this.dexPath=dexPath;
            this.classDescriptor=classDescriptor;this.evidence=evidence;
        }
        public String display(){
            return "["+kind+" / "+dexPath+"] "+evidence;
        }
    }
    public static final class Result {
        public final EnumMap<Topic,List<Hit>> hits=new EnumMap<>(Topic.class);
        public final List<String> warnings=new ArrayList<>();
        public int dexIndexed, stringsScanned, classesScanned, methodsScanned;
        public boolean limitReached;
        public Result(){
            for(Topic topic:Topic.values())hits.put(topic,new ArrayList<>());
        }
        public int count(Topic topic){return hits.get(topic).size();}
    }
    private ApkFeatureAudit(){}

    static boolean matches(Topic topic,String value){
        return value!=null&&PATTERNS.get(topic).matcher(value).find();
    }
    private static String shorten(String raw){
        StringBuilder out=new StringBuilder();
        for(int i=0;i<raw.length()&&out.length()<MAX_PREVIEW;i++){
            char c=raw.charAt(i);
            out.append(Character.isISOControl(c)?' ':c);
        }
        return out.toString();
    }
    private static void match(Result result,String kind,String path,String owner,String value){
        for(Topic topic:Topic.values()){
            if(!matches(topic,value))continue;
            List<Hit> topicHits=result.hits.get(topic);
            if(topicHits.size()>=MAX_HITS_PER_TOPIC){
                result.limitReached=true;
                continue;
            }
            topicHits.add(new Hit(topic,kind,path,owner,shorten(value)));
        }
    }
    private static boolean dexName(String path){return path.matches("classes[0-9]*\\.dex");}

    private static byte[] readDex(ZipFile zip,ZipEntry entry)throws IOException{
        long declared=entry.getSize();
        if(declared<=0 || declared>MAX_DEX_BYTES)throw new IOException("DEX exceeds 32 MiB");
        int size=(int)declared;
        byte[] bytes=new byte[size];
        try(InputStream in=zip.getInputStream(entry)){
            int offset=0;
            while(offset<size){
                if(Thread.currentThread().isInterrupted())throw new IOException("Feature audit cancelled");
                int n=in.read(bytes,offset,Math.min(size-offset,65536));
                if(n<0)throw new IOException("Truncated DEX payload");
                if(n==0)continue;
                offset+=n;
            }
        }
        return bytes;
    }

    public static Result analyze(File apk)throws IOException{
        if(apk==null||!apk.isFile()||apk.length()<22||apk.length()>MAX_APK_BYTES)
            throw new IOException("APK file unavailable or exceeds limit");
        Result result=new Result();
        long cumulative=0;
        int members=0;
        Set<String> names=new HashSet<>();
        try(ZipFile zip=new ZipFile(apk)){
            Enumeration<? extends ZipEntry> entries=zip.entries();
            while(entries.hasMoreElements()){
                if(Thread.currentThread().isInterrupted())throw new IOException("Audit cancelled");
                ZipEntry entry=entries.nextElement();
                if(++members>ApkInspector.MAX_ENTRIES)throw new IOException("Excessive ZIP entries");
                String name=entry.getName();
                if(name==null||name.startsWith("/")||name.indexOf('\\')>=0||
                   name.contains("../")||name.startsWith("../")||
                   !names.add(name))throw new IOException("Unsafe or duplicate ZIP member");
                if(!dexName(name)||entry.isDirectory())continue;
                long size=entry.getSize(),packed=entry.getCompressedSize();
                if(size<=0||size>MAX_DEX_BYTES||packed<0||
                   cumulative+size>MAX_TOTAL_DEX_BYTES){
                    result.warnings.add(name+": skipped due to bounded DEX memory budget");
                    result.limitReached=true;continue;
                }
                if(size>1024*1024 && (packed==0||size/Math.max(1,packed)>200)){
                    throw new IOException("Excessive compressed DEX ratio");
                }
                cumulative+=size;
                try{
                    byte[] raw=readDex(zip,entry);
                    DexBackedDexFile dex=DexBackedDexFile.fromInputStream(
                        null,new ByteArrayInputStream(raw));
                    result.dexIndexed++;
                    DexBackedDexFile.OptionalIndexedSection<String> strings=dex.getStringSection();
                    for(int stringIndex=0;stringIndex<strings.size();stringIndex++){
                        if(result.stringsScanned>=MAX_STRINGS_SCANNED){
                            result.limitReached=true;break;
                        }
                        String value=strings.get(stringIndex);
                        result.stringsScanned++;
                        match(result,"DEX string #"+stringIndex,name,null,value);
                    }
                    for(ClassDef cls:dex.getClasses()){
                        if(result.classesScanned++>=MAX_CLASSES_SCANNED){
                            result.limitReached=true;break;
                        }
                        String owner=cls.getType();
                        match(result,"Class",name,owner,owner);
                        for(Method method:cls.getMethods()){
                            if(result.methodsScanned++>=MAX_METHODS_SCANNED){
                                result.limitReached=true;break;
                            }
                            String signature=owner+"->"+method.getName();
                            match(result,"Method definition",name,owner,signature);
                        }
                        if(result.methodsScanned>=MAX_METHODS_SCANNED)break;
                    }
                }catch(RuntimeException|IOException invalid){
                    String why=invalid.getMessage()==null?
                        "malformed DEX":invalid.getMessage();
                    result.warnings.add(name+": index unavailable: "+
                        (why.length()>130?why.substring(0,130):why));
                }
            }
        }
        result.warnings.add("These are static keyword references, not proof of a purchase, entitlement, active advertisement, or feature availability.");
        if(result.limitReached)
            result.warnings.add("Resource limits reached: some matches may be omitted.");
        return result;
    }
}
