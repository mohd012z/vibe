package com.vibe.hermesinspector;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** Strict, source-hash-pinned serialization of a patch plan, not original APK bytes. */
public final class PatchPlanCodec {
    public static final int MAX_JSON_BYTES=1024*1024;
    public static final String VERSION="vibe-patch-plan-v1";
    private PatchPlanCodec(){}

    public static String encode(ApkPatchWorkspace plan)throws IOException{
        if(plan==null)throw new IOException("No patch workspace available");
        try{
            JSONObject data=new JSONObject();
            data.put("format",VERSION);
            data.put("source_sha256",plan.sourceSha256());
            JSONArray entries=new JSONArray();
            for(ApkPatchWorkspace.Change change:plan.staged()){
                JSONObject item=new JSONObject();
                item.put("path",change.path);
                item.put("before_sha256",change.beforeSha256);
                item.put("after_sha256",change.afterSha256);
                item.put("replacement",plan.replacementText(change.path));
                entries.put(item);
            }
            data.put("changes",entries);
            String json=data.toString();
            if(json.getBytes(StandardCharsets.UTF_8).length>MAX_JSON_BYTES)
                throw new IOException("Patch plan exceeds 1 MiB");
            return json;
        }catch(JSONException malformed){
            throw new IOException("Cannot encode staged patch plan",malformed);
        }
    }

    public static ApkPatchWorkspace restore(File original,String json)throws IOException{
        if(json==null||json.isEmpty()||
           json.getBytes(StandardCharsets.UTF_8).length>MAX_JSON_BYTES)
            throw new IOException("Patch plan missing or exceeds 1 MiB");
        final JSONObject data;
        try{data=new JSONObject(json);}
        catch(JSONException malformed){throw new IOException("Corrupt patch plan JSON",malformed);}
        if(!VERSION.equals(data.optString("format","")))
            throw new IOException("Unsupported patch plan version");
        ApkPatchWorkspace plan=new ApkPatchWorkspace(original);
        String expected=data.optString("source_sha256","");
        if(!expected.matches("[a-f0-9]{64}")||!expected.equals(plan.sourceSha256()))
            throw new IOException("Saved plan belongs to a different APK SHA-256");
        try{
            JSONArray list=data.getJSONArray("changes");
            if(list.length()>ApkPatchWorkspace.MAX_STAGE)
                throw new IOException("Patch plan exceeds staged-file budget");
            Set<String> paths=new HashSet<>();
            for(int i=0;i<list.length();i++){
                JSONObject item=list.getJSONObject(i);
                String path=item.getString("path");
                String before=item.getString("before_sha256");
                String after=item.getString("after_sha256");
                String replacement=item.getString("replacement");
                if(!paths.add(path)||!before.matches("[a-f0-9]{64}")||
                   !after.matches("[a-f0-9]{64}"))
                    throw new IOException("Duplicate or malformed patch entry");
                if(!ApkPatchWorkspace.editable(path))
                    throw new IOException("Checkpoint contains an ineligible text path");
                plan.stage(original,path,replacement);
                ApkPatchWorkspace.Change changed=null;
                for(ApkPatchWorkspace.Change entry:plan.staged())
                    if(entry.path.equals(path)){changed=entry;break;}
                if(changed==null||!changed.beforeSha256.equals(before)||
                   !changed.afterSha256.equals(after))
                    throw new IOException("Checkpoint content or source entry digest mismatch");
            }
            // Restored state starts as a fresh undo baseline.
            plan.clearUndoHistory();
            return plan;
        }catch(JSONException malformed){
            throw new IOException("Invalid patch entry fields",malformed);
        }
    }
}
