package com.vibe.hermesinspector;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.io.IOException;
import java.util.List;

/** Validates untrusted offline JSON reports; imported values are not re-verified against APK bytes. */
public final class ReportImporter {
    public static final int MAX_JSON_BYTES=4*1024*1024;
    private ReportImporter(){}

    public static ApkInspector.Report parse(String text)throws IOException{
        if(text==null||text.isEmpty()||text.length()>MAX_JSON_BYTES)
            throw new IOException("Missing or oversized JSON report");
        validateNesting(text);
        final JSONObject root;
        try{root=new JSONObject(text);}
        catch(JSONException bad){throw new IOException("Malformed JSON report",bad);}
        if(!"vibe-hermes-offline-report-v2".equals(root.optString("format","")))
            throw new IOException("Unsupported JSON report format");
        String sha=root.optString("sha256","");
        if(!sha.matches("[0-9a-f]{64}"))throw new IOException("Invalid report SHA-256");
        ApkInspector.Report result=new ApkInspector.Report();
        result.sha256=sha;
        try{
            result.byteSize=bounded(root,"bytes",ApkInspector.MAX_APK_BYTES);
            result.entries=(int)bounded(root,"zip_members",ApkInspector.MAX_ENTRIES);
            result.hermesBundles=(int)bounded(root,"hermes_bundle_count",1000);
            result.functionCount=bounded(root,"hermes_declared_functions",1000000);
            result.dexParsed=(int)bounded(root,"dex_files_indexed",1000);
            result.dexDeclaredClasses=(int)bounded(root,"dex_declared_classes",1000000);
            result.dexDeclaredMethods=(int)bounded(root,"dex_declared_methods",1000000);
            result.dexDeclaredStrings=(int)bounded(root,"dex_declared_strings",1000000);
            result.hermesDecodedInstructions=(int)bounded(root,"hermes_decoded_instructions",5000);
            copy(root,"technologies",result.technologies,12);
            copy(root,"hbc_bundle_details",result.bundleDetails,50);
            copy(root,"dex_classes",result.dexClasses,3000);
            copy(root,"dex_method_references",result.dexMethods,4000);
            copy(root,"dex_strings",result.dexStrings,6000);
            copy(root,"hermes_strings",result.hermesStrings,6000);
            copy(root,"hermes_functions",result.hermesFunctions,3000);
            copy(root,"hermes_instructions",result.hermesInstructions,6000);
            copy(root,"hermes_string_references",result.hermesReferences,3000);
            copy(root,"printable_candidates",result.candidates,2000);
            copy(root,"warnings",result.warnings,100);
        }catch(JSONException invalid){throw new IOException("Incompatible report fields",invalid);}
        result.warnings.add("IMPORTED REPORT: metadata is not revalidated against original APK bytes.");
        return result;
    }
    private static long bounded(JSONObject obj,String key,long limit)throws JSONException,IOException{
        if(!obj.has(key) || !(obj.get(key) instanceof Number))
            throw new IOException("Missing numeric report field: "+key);
        long n=obj.getLong(key);
        if(n<0||n>limit)throw new IOException("Out-of-bounds report value: "+key);
        return n;
    }
    private static void copy(JSONObject obj,String name,List<String> out,int max)throws JSONException,IOException{
        JSONArray list=obj.getJSONArray(name);
        if(list.length()>max)throw new IOException("Report record limit exceeded: "+name);
        for(int i=0;i<list.length();i++){
            Object item=list.get(i);
            if(!(item instanceof String)||((String)item).length()>4096)
                throw new IOException("Invalid report record in "+name);
            out.add((String)item);
        }
    }
    private static void validateNesting(String text)throws IOException{
        int depth=0;
        boolean quoted=false,escaped=false;
        for(int i=0;i<text.length();i++){
            char c=text.charAt(i);
            if(quoted){
                if(escaped){escaped=false;continue;}
                if(c=='\\'){escaped=true;continue;}
                if(c=='"'){quoted=false;continue;}
            }else{
                if(c=='"'){quoted=true;continue;}
                if(c=='{'||c=='['){if(++depth>20)throw new IOException("JSON nesting too deep");}
                else if(c=='}'||c==']'){if(--depth<0)throw new IOException("JSON bracket mismatch");}
            }
        }
        if(quoted||depth!=0)throw new IOException("Truncated JSON report");
    }
}
