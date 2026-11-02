package com.vibe.hermesinspector;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/** App-private, bounded patch-plan checkpoint storage. No APK copies or keys stored. */
public final class PatchPlanStore {
    private static final String DIRECTORY="patch-plans";
    private final File root;

    public PatchPlanStore(Context context)throws IOException{
        this(context==null?null:new File(context.getApplicationContext().getFilesDir(),DIRECTORY));
    }
    // Testable private-directory constructor; callers cannot escape via the hash filename.
    PatchPlanStore(File directory)throws IOException{
        if(directory==null)throw new IOException("Missing private patch directory");
        root=directory;
        if(!root.isDirectory()&&!root.mkdirs())
            throw new IOException("Cannot create private patch checkpoint directory");
        File[] old=root.listFiles();
        if(old!=null){
            int cleaned=0;
            for(File candidate:old){
                if(candidate.isFile() && candidate.getName().startsWith("vibe-draft-") &&
                   candidate.getName().endsWith(".part") && candidate.delete())cleaned++;
                if(cleaned>=40)break;
            }
        }
    }
    private File checkpoint(String sha)throws IOException{
        if(sha==null||!sha.matches("[a-f0-9]{64}"))
            throw new IOException("Invalid patch source SHA-256");
        return new File(root,sha+".json");
    }
    public boolean has(String sha)throws IOException{return checkpoint(sha).isFile();}

    public ApkPatchWorkspace load(File apk)throws IOException{
        ApkPatchWorkspace initial=new ApkPatchWorkspace(apk);
        File stored=checkpoint(initial.sourceSha256());
        if(!stored.exists())return initial;
        long length=stored.length();
        if(length<=0||length>PatchPlanCodec.MAX_JSON_BYTES)
            throw new IOException("Saved plan is empty or oversized");
        byte[] bytes=Files.readAllBytes(stored.toPath());
        final String json;
        try{
            json=StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString();
        }catch(java.nio.charset.CharacterCodingException invalid){
            throw new IOException("Patch checkpoint is not valid UTF-8",invalid);
        }
        return PatchPlanCodec.restore(apk,json);
    }
    public void save(ApkPatchWorkspace plan)throws IOException{
        if(plan==null)throw new IOException("No workspace to save");
        File path=checkpoint(plan.sourceSha256());
        if(plan.size()==0){
            delete(plan.sourceSha256());
            return;
        }
        byte[] encoded=PatchPlanCodec.encode(plan).getBytes(StandardCharsets.UTF_8);
        if(encoded.length>PatchPlanCodec.MAX_JSON_BYTES)
            throw new IOException("Checkpoint too large");
        File tmp=File.createTempFile("vibe-draft-", ".part",root);
        try{
            try(FileOutputStream output=new FileOutputStream(tmp)){
                output.write(encoded);
                output.flush();
                output.getFD().sync();
            }
            try{
                Files.move(tmp.toPath(),path.toPath(),
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
            }catch(java.nio.file.AtomicMoveNotSupportedException notAtomic){
                throw new IOException("Atomic checkpoint replacement unavailable; existing plan left intact",notAtomic);
            }
        }finally{
            if(tmp.exists())tmp.delete();
        }
    }
    public void delete(String sha)throws IOException{
        File checkpoint=checkpoint(sha);
        if(checkpoint.exists()&&!checkpoint.delete())
            throw new IOException("Cannot remove private patch plan");
    }
}
