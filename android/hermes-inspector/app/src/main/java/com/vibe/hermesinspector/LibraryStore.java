package com.vibe.hermesinspector;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.content.Intent;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

import java.util.ArrayList;
import java.util.List;

/** Remembers only persisted read-only SAF URI grants and display names. Never stores APK bytes. */
public final class LibraryStore {
    public static final int MAX_HISTORY = 12;
    private static final String PREFS = "vibe_hermes_private_library_v2";
    private static final String INDEX = "recent_apk_uris";
    private final Context context;

    public static final class Item {
        public final String uri;
        public final String name;
        public final String sha;
        public final long created;
        Item(String uri,String name,String sha,long created) {
            this.uri=uri;this.name=name;this.sha=sha;this.created=created;
        }
    }
    public LibraryStore(Context ctx) {context=ctx.getApplicationContext();}

    private SharedPreferences prefs(){return context.getSharedPreferences(PREFS,Context.MODE_PRIVATE);}

    public List<Item> list() {
        ArrayList<Item> result=new ArrayList<>();
        try {
            JSONArray array=new JSONArray(prefs().getString(INDEX,"[]"));
            for(int i=0;i<array.length()&&result.size()<MAX_HISTORY;i++){
                JSONObject o=array.optJSONObject(i);
                if(o==null)continue;
                String uri=o.optString("uri",""),name=o.optString("name","APK"),
                    sha=o.optString("sha","");
                long date=o.optLong("created",0);
                if(uri.startsWith("content://") && uri.length()<4096 &&
                    name.length()<150 && sha.matches("[a-f0-9]{64}"))
                    result.add(new Item(uri,name,sha,date));
            }
        }catch(JSONException corrupt){
            prefs().edit().remove(INDEX).apply();
        }
        return result;
    }

    public boolean grant(Uri uri) {
        if(uri==null || !"content".equals(uri.getScheme()))return false;
        try{
            context.getContentResolver().takePersistableUriPermission(
                uri,Intent.FLAG_GRANT_READ_URI_PERMISSION);
            return true;
        }catch(SecurityException providerNotPersistable){
            return false;
        }
    }

    public void save(Uri uri,String name,String sha){
        if(uri==null||!"content".equals(uri.getScheme())||
           name==null||sha==null||!sha.matches("[a-f0-9]{64}"))return;
        List<Item> list=list();
        JSONArray out=new JSONArray();
        try{
            java.util.HashSet<String> kept=new java.util.HashSet<>();
            kept.add(uri.toString());
            out.put(toJson(new Item(uri.toString(),
                name.length()>100?name.substring(0,100):name,sha,
                System.currentTimeMillis())));
            for(Item item:list){
                if(out.length()>=MAX_HISTORY)break;
                if(!item.uri.equals(uri.toString())){
                    out.put(toJson(item));
                    kept.add(item.uri);
                }
            }
            if(!prefs().edit().putString(INDEX,out.toString()).commit())
                throw new IllegalStateException("Cannot persist local APK library");
            for(Item old:list)if(!kept.contains(old.uri))release(old.uri);
        }catch(JSONException error){
            throw new IllegalStateException("Failed to serialize local library",error);
        }
    }

    public void remove(String target){
        if(target==null)return;
        JSONArray output=new JSONArray();
        try{
            for(Item item:list())if(!item.uri.equals(target))output.put(toJson(item));
            if(!prefs().edit().putString(INDEX,output.toString()).commit())
                throw new IllegalStateException("Cannot remove saved APK reference");
        }catch(JSONException error){throw new IllegalStateException(error);}
        release(target);
    }

    public void clear(){
        List<Item> old=list();
        if(!prefs().edit().remove(INDEX).commit())
            throw new IllegalStateException("Cannot clear local APK references");
        for(Item item:old)release(item.uri);
    }

    private void release(String savedUri) {
        if(savedUri==null || !savedUri.startsWith("content://"))return;
        try {
            context.getContentResolver().releasePersistableUriPermission(
                Uri.parse(savedUri),Intent.FLAG_GRANT_READ_URI_PERMISSION);
        } catch(SecurityException ignored) {
            // Already revoked or document-provider grant has expired.
        }
    }

    private static JSONObject toJson(Item item)throws JSONException {
        return new JSONObject()
            .put("uri",item.uri)
            .put("name",item.name)
            .put("sha",item.sha)
            .put("created",item.created);
    }
}
