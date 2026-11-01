package com.vibe.hermesinspector;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.provider.DocumentsContract;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Two independent SAF file/folder browser panes, with read-only preview and diff.
 * No MANAGE_EXTERNAL_STORAGE, INTERNET, file modification or APK resigning.
 */
public final class DualPaneActivity extends Activity {
    private static final int PICK_FILE_LEFT=5101,PICK_FILE_RIGHT=5102;
    private static final int PICK_TREE_LEFT=5103,PICK_TREE_RIGHT=5104;
    private static final int BG=0xff0d1420,PANEL=0xff1c283b,MUTED=0xffb1c3d9;
    private static final int ACCENT=0xff59acf6,WHITE=0xffedf6ff;
    private static final int PAGE_SIZE=15;
    private static final int MAX_CHILDREN=600;
    private final ExecutorService io=Executors.newSingleThreadExecutor();
    private final Pane[] panes={new Pane("LEFT"),new Pane("RIGHT")};
    private TextView comparison,headline;
    private Button compareButton,swapButton;
    private LinearLayout root;
    private boolean destroyed=false;

    private static final class Document {
        final Uri uri;final String name;final boolean directory;final long size;
        Document(Uri uri,String name,boolean directory,long size){
            this.uri=uri;this.name=name;this.directory=directory;this.size=size;
        }
    }
    private static final class Pane {
        final String side;
        Uri tree;
        final List<Uri> history=new ArrayList<>();
        final List<Document> documents=new ArrayList<>();
        File cache;
        Uri selectedUri;
        String selectedName="",zipEntry=null;
        boolean zipBrowser=false;
        int page=0,epoch=0;
        LinearLayout card,list;
        TextView selection,preview,pageLabel;
        Button previous,next,back,zipButton;
        Pane(String side){this.side=side;}
    }

    private int dp(int n){return Math.round(n*getResources().getDisplayMetrics().density);}
    private GradientDrawable fill(int color,int radius){
        GradientDrawable d=new GradientDrawable();
        d.setColor(color);d.setCornerRadius(dp(radius));return d;
    }
    private TextView label(String text,int size,int color,boolean bold){
        TextView t=new TextView(this);
        t.setText(text);t.setTextColor(color);t.setTextSize(size);
        t.setLineSpacing(dp(2),1);
        if(bold)t.setTypeface(Typeface.DEFAULT,Typeface.BOLD);
        return t;
    }
    private Button action(String title){
        Button b=new Button(this);b.setText(title);b.setAllCaps(false);
        b.setTextSize(12);b.setTextColor(WHITE);
        b.setBackground(fill(0xff265d96,9));
        b.setMinHeight(dp(48));b.setPadding(dp(7),dp(6),dp(7),dp(6));
        return b;
    }
    private LinearLayout column(){
        LinearLayout v=new LinearLayout(this);v.setOrientation(LinearLayout.VERTICAL);return v;
    }
    private void margin(LinearLayout to,View view,int top){
        LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,-2);
        p.setMargins(0,dp(top),0,0);to.addView(view,p);
    }
    @Override public void onCreate(Bundle state){
        super.onCreate(state);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        getWindow().getDecorView().setSystemUiVisibility(0);
        createUi();
    }
    private void createUi(){
        ScrollView scroll=new ScrollView(this);
        scroll.setBackgroundColor(BG);
        scroll.setFillViewport(true);
        root=column();
        root.setPadding(dp(10),dp(12),dp(10),dp(20));
        scroll.addView(root);
        setContentView(scroll);
        scroll.setOnApplyWindowInsetsListener((v,insets)->{
            int top,bottom;
            if(android.os.Build.VERSION.SDK_INT>=30){
                android.graphics.Insets bars=insets.getInsets(WindowInsets.Type.systemBars());
                top=bars.top;bottom=bars.bottom;
            }else {
                top=insets.getSystemWindowInsetTop();
                bottom=insets.getSystemWindowInsetBottom();
            }
            root.setPadding(dp(10),top+dp(10),dp(10),bottom+dp(20));
            return insets;
        });
        scroll.requestApplyInsets();
        margin(root,label("VIBE  /  DUAL-PANE FILE MANAGER",12,ACCENT,true),0);
        margin(root,label("Compare files side by side",24,WHITE,true),7);
        margin(root,label("Two independent file or folder pickers · SHA-256 · UTF-8 diff · APK contents · read-only",12,MUTED,false),6);

        LinearLayout commands=new LinearLayout(this);
        commands.setOrientation(LinearLayout.HORIZONTAL);
        compareButton=action("⇄ Compare");
        swapButton=action("Swap files");
        commands.addView(compareButton,new LinearLayout.LayoutParams(0,dp(52),2));
        LinearLayout.LayoutParams swapParams=new LinearLayout.LayoutParams(0,dp(52),1);
        swapParams.setMargins(dp(5),0,0,0);
        commands.addView(swapButton,swapParams);
        margin(root,commands,12);
        compareButton.setOnClickListener(v->compare());
        swapButton.setOnClickListener(v->swap());

        headline=label("Select LEFT and RIGHT files, or open folders to browse.",13,MUTED,false);
        headline.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        margin(root,headline,9);

        HorizontalScrollView horizontal=new HorizontalScrollView(this);
        horizontal.setFillViewport(true);
        horizontal.setHorizontalScrollBarEnabled(true);
        LinearLayout sides=new LinearLayout(this);
        sides.setOrientation(LinearLayout.HORIZONTAL);
        horizontal.addView(sides);
        for(int i=0;i<2;i++){
            Pane pane=panes[i];
            buildPane(pane,i);
            LinearLayout.LayoutParams params=new LinearLayout.LayoutParams(
                0,-2,1);
            params.width=Math.max(dp(214),
                getResources().getDisplayMetrics().widthPixels/2-dp(17));
            params.weight=0;
            params.setMargins(i==0?0:dp(4),0,i==0?dp(4):0,0);
            sides.addView(pane.card,params);
        }
        margin(root,horizontal,12);
        margin(root,label("Comparison result",18,WHITE,true),12);
        comparison=label("No files compared yet.",12,WHITE,false);
        comparison.setTypeface(Typeface.MONOSPACE);
        comparison.setTextIsSelectable(true);
        comparison.setBackground(fill(PANEL,12));
        comparison.setPadding(dp(12),dp(12),dp(12),dp(12));
        comparison.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        margin(root,comparison,8);
        margin(root,label("No files are modified. Original APKs remain signed and unchanged. Binary XML, encrypted files and compiled code are not treated as original source.",12,MUTED,false),12);
    }
    private void buildPane(Pane pane,int index){
        pane.card=column();
        pane.card.setPadding(dp(8),dp(10),dp(8),dp(12));
        pane.card.setBackground(fill(PANEL,12));
        margin(pane.card,label(pane.side+" FILE / FOLDER",16,WHITE,true),0);
        LinearLayout pickers=new LinearLayout(this);
        pickers.setOrientation(LinearLayout.HORIZONTAL);
        Button chooseFile=action("Open file");
        Button chooseFolder=action("Open folder");
        pickers.addView(chooseFile,new LinearLayout.LayoutParams(0,dp(48),1));
        LinearLayout.LayoutParams folder=new LinearLayout.LayoutParams(0,dp(48),1);
        folder.setMargins(dp(3),0,0,0);
        pickers.addView(chooseFolder,folder);
        margin(pane.card,pickers,8);
        chooseFile.setOnClickListener(v->selectFile(index));
        chooseFolder.setOnClickListener(v->selectTree(index));
        pane.selection=label("No file selected",12,MUTED,false);
        margin(pane.card,pane.selection,9);

        pane.back=action("← Folder back");
        pane.back.setEnabled(false);
        margin(pane.card,pane.back,7);
        pane.back.setOnClickListener(v->back(index));
        pane.zipButton=action("Browse APK entries");
        pane.zipButton.setEnabled(false);
        margin(pane.card,pane.zipButton,5);
        pane.zipButton.setOnClickListener(v->toggleZip(index));

        LinearLayout pageNavigation=new LinearLayout(this);
        pageNavigation.setOrientation(LinearLayout.HORIZONTAL);
        pane.previous=action("‹");
        pane.previous.setContentDescription("Previous "+pane.side+" folder page");
        pane.next=action("›");
        pane.next.setContentDescription("Next "+pane.side+" folder page");
        pane.pageLabel=label("1 / 1",12,WHITE,true);
        pane.pageLabel.setGravity(Gravity.CENTER);
        pageNavigation.addView(pane.previous,new LinearLayout.LayoutParams(0,dp(46),1));
        pageNavigation.addView(pane.pageLabel,new LinearLayout.LayoutParams(0,dp(46),2));
        pageNavigation.addView(pane.next,new LinearLayout.LayoutParams(0,dp(46),1));
        margin(pane.card,pageNavigation,8);
        pane.previous.setOnClickListener(v->{if(pane.page>0){pane.page--;renderList(index);}});
        pane.next.setOnClickListener(v->{
            if((pane.page+1)*PAGE_SIZE<pane.documents.size()){pane.page++;renderList(index);}
        });
        ScrollView entriesScroll=new ScrollView(this);
        pane.list=column();entriesScroll.addView(pane.list);
        entriesScroll.setBackground(fill(BG,8));
        pane.card.addView(entriesScroll,new LinearLayout.LayoutParams(-1,dp(240)));
        margin(pane.card,label("Preview",14,ACCENT,true),10);
        ScrollView previewScroll=new ScrollView(this);
        pane.preview=label("Choose a file.",12,WHITE,false);
        pane.preview.setTypeface(Typeface.MONOSPACE);
        pane.preview.setTextIsSelectable(true);
        pane.preview.setPadding(dp(7),dp(7),dp(7),dp(7));
        previewScroll.addView(pane.preview);
        previewScroll.setBackground(fill(BG,8));
        pane.card.addView(previewScroll,new LinearLayout.LayoutParams(-1,dp(220)));
        renderList(index);
    }

    private void selectFile(int i){
        Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try{startActivityForResult(intent,i==0?PICK_FILE_LEFT:PICK_FILE_RIGHT);}
        catch(android.content.ActivityNotFoundException missing){headline.setText("No Android document picker available.");}
    }
    private void selectTree(int i){
        Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try{startActivityForResult(intent,i==0?PICK_TREE_LEFT:PICK_TREE_RIGHT);}
        catch(android.content.ActivityNotFoundException missing){headline.setText("No Android folder picker available.");}
    }
    @Override protected void onActivityResult(int request,int result,Intent data){
        super.onActivityResult(request,result,data);
        if(result!=RESULT_OK||data==null||data.getData()==null)return;
        Uri uri=data.getData();
        if(request==PICK_FILE_LEFT || request==PICK_FILE_RIGHT){
            int index=request==PICK_FILE_LEFT?0:1;
            openDocument(index,uri,describe(uri));
        }else if(request==PICK_TREE_LEFT||request==PICK_TREE_RIGHT){
            int index=request==PICK_TREE_LEFT?0:1;
            Pane pane=panes[index];
            try{
                pane.tree=uri;
                String documentId=DocumentsContract.getTreeDocumentId(uri);
                Uri rootUri=DocumentsContract.buildDocumentUriUsingTree(uri,documentId);
                pane.history.clear();pane.history.add(rootUri);
                pane.zipBrowser=false;pane.zipEntry=null;
                listFolder(index);
            }catch(RuntimeException invalid){headline.setText("Unable to open selected folder: "+shortReason(invalid));}
        }
    }
    private String describe(Uri uri){
        try(Cursor c=getContentResolver().query(uri,
                new String[]{DocumentsContract.Document.COLUMN_DISPLAY_NAME},null,null,null)){
            if(c!=null&&c.moveToFirst()){
                String name=c.getString(0);
                if(name!=null&&!name.isEmpty())return name.length()>120?name.substring(0,120):name;
            }
        }catch(Exception ignored){}
        return "selected-file";
    }
    private void listFolder(int i){
        Pane pane=panes[i];
        if(pane.tree==null||pane.history.isEmpty())return;
        Uri folder=pane.history.get(pane.history.size()-1);
        int epoch=++pane.epoch;
        pane.selection.setText("Reading folder "+describe(folder)+"…");
        io.execute(()->{
            ArrayList<Document> found=new ArrayList<>();
            String error=null;
            try {
                String id=DocumentsContract.getDocumentId(folder);
                Uri children=DocumentsContract.buildChildDocumentsUriUsingTree(pane.tree,id);
                String[] projection={DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE,
                    DocumentsContract.Document.COLUMN_SIZE};
                try(Cursor cursor=getContentResolver().query(children,projection,null,null,null)){
                    if(cursor==null)throw new IOException("Document provider returned no listing");
                    int visited=0;
                    while(cursor.moveToNext()){
                        if(++visited>MAX_CHILDREN)throw new IOException("Folder exceeds 600-entry listing budget");
                        String childId=cursor.getString(0);
                        String name=cursor.getString(1);
                        String mime=cursor.getString(2);
                        long bytes=cursor.isNull(3)?-1:cursor.getLong(3);
                        if(childId==null)continue;
                        Uri doc=DocumentsContract.buildDocumentUriUsingTree(pane.tree,childId);
                        found.add(new Document(doc,
                            name==null?"[unnamed]":name.substring(0,Math.min(name.length(),120)),
                            DocumentsContract.Document.MIME_TYPE_DIR.equals(mime),bytes));
                    }
                }
                found.sort(Comparator.comparing((Document d)->!d.directory)
                          .thenComparing(d->d.name.toLowerCase(java.util.Locale.ROOT)));
            }catch(Exception e){error=shortReason(e);}
            String fail=error;
            runOnUiThread(()->{
                if(destroyed||epoch!=pane.epoch)return;
                pane.zipBrowser=false;
                pane.documents.clear();
                pane.documents.addAll(found);
                pane.page=0;
                pane.back.setEnabled(pane.history.size()>1);
                pane.selection.setText(fail==null?
                     pane.side+": "+describe(folder)+" ("+found.size()+" entries)":
                     "Folder listing refused: "+fail);
                renderList(i);
            });
        });
    }
    private void back(int index){
        Pane pane=panes[index];
        if(pane.zipBrowser){
            pane.zipBrowser=false;pane.zipEntry=null;
            listFolder(index);return;
        }
        if(pane.history.size()>1){pane.history.remove(pane.history.size()-1);listFolder(index);}
    }
    private void renderList(int index){
        Pane pane=panes[index];
        if(pane.list==null)return;
        pane.list.removeAllViews();
        int pages=Math.max(1,(pane.documents.size()+PAGE_SIZE-1)/PAGE_SIZE);
        pane.page=Math.max(0,Math.min(pane.page,pages-1));
        int end=Math.min(pane.documents.size(),(pane.page+1)*PAGE_SIZE);
        for(int n=pane.page*PAGE_SIZE;n<end;n++){
            Document row=pane.documents.get(n);
            Button b=action((row.directory?"📁 ":"📄 ")+row.name);
            b.setTextSize(12);
            b.setContentDescription((row.directory?"Open folder ":"Open file ")+row.name);
            margin(pane.list,b,3);
            b.setOnClickListener(v->{
                if(pane.zipBrowser){chooseEntry(index,row.name);return;}
                if(row.directory){
                    pane.history.add(row.uri);
                    listFolder(index);
                }else openDocument(index,row.uri,row.name);
            });
        }
        if(pane.documents.isEmpty())margin(pane.list,label("No entries. Pick a folder or file.",12,MUTED,false),6);
        pane.pageLabel.setText("Page "+(pane.page+1)+"/"+pages);
        pane.previous.setEnabled(pane.page>0);
        pane.next.setEnabled(pane.page+1<pages);
    }
    private void openDocument(int index,Uri uri,String name){
        Pane pane=panes[index];
        final int epoch=++pane.epoch;
        pane.selection.setText("Opening "+name+"…");
        pane.preview.setText("Reading selected file…");
        io.execute(()->{
            File temp=null;
            String error=null;
            try{
                temp=File.createTempFile("vibe-dual-"+index+"-",".dat",getCacheDir());
                try(InputStream in=getContentResolver().openInputStream(uri);
                    FileOutputStream out=new FileOutputStream(temp)){
                    if(in==null)throw new IOException("Selected document cannot be read");
                    byte[] bytes=new byte[65536];long total=0;int n;
                    while((n=in.read(bytes))!=-1){
                        if(Thread.currentThread().isInterrupted())throw new IOException("File import cancelled");
                        if(n==0)continue;
                        total+=n;
                        if(total>FileComparator.MAX_FILE)throw new IOException("File exceeds 96 MiB limit");
                        out.write(bytes,0,n);
                    }
                }
            }catch(Exception err){error=shortReason(err);}
            File completed=temp;
            String failure=error;
            runOnUiThread(()->{
                if(destroyed||epoch!=pane.epoch){
                    if(completed!=null)completed.delete();
                    return;
                }
                if(failure!=null){
                    if(completed!=null)completed.delete();
                    pane.selection.setText("Open refused: "+failure);
                    pane.preview.setText("No file loaded.");
                    return;
                }
                if(pane.cache!=null)pane.cache.delete();
                pane.cache=completed;
                pane.selectedUri=uri;
                pane.selectedName=name;
                pane.zipEntry=null;
                pane.zipBrowser=false;
                pane.zipButton.setEnabled(name.toLowerCase(java.util.Locale.ROOT).endsWith(".apk")||
                    name.toLowerCase(java.util.Locale.ROOT).endsWith(".zip"));
                pane.zipButton.setText("Browse APK/ZIP entries");
                pane.selection.setText(pane.side+": "+name+"\n"+
                    completed.length()+" bytes (local read-only copy)");
                pane.preview.setText("Preview loading…");
                preview(index);
            });
        });
    }
    private void preview(int index){
        Pane pane=panes[index];
        if(pane.cache==null)return;
        final File file=pane.cache;
        final String selectedEntry=pane.zipEntry;
        io.execute(()->{
            String preview;
            try{
                preview=selectedEntry==null?FileComparator.preview(file):
                    FileComparator.previewEntry(file,selectedEntry);
            }catch(Exception err){preview="Preview error: "+shortReason(err);}
            String value=preview;
            runOnUiThread(()->{
                if(!destroyed && pane.cache==file &&
                   java.util.Objects.equals(selectedEntry,pane.zipEntry)){
                    pane.preview.setText(value);
                }
            });
        });
    }
    private void toggleZip(int index){
        Pane pane=panes[index];
        if(pane.cache==null)return;
        if(pane.zipBrowser){
            pane.zipBrowser=false;
            pane.zipEntry=null;
            pane.zipButton.setText("Browse APK/ZIP entries");
            pane.documents.clear();pane.page=0;
            if(!pane.history.isEmpty())listFolder(index);
            else renderList(index);
            preview(index);
            return;
        }
        final File file=pane.cache;
        pane.selection.setText("Indexing "+pane.selectedName+" ZIP entries…");
        io.execute(()->{
            ArrayList<Document> entries=new ArrayList<>();
            String error=null;
            try{
                Map<String,FileComparator.ZipInfo> zip=FileComparator.inventory(file);
                for(FileComparator.ZipInfo item:zip.values()){
                    entries.add(new Document(null,item.name,false,item.size));
                }
                entries.sort(Comparator.comparing(d->d.name));
            }catch(Exception ex){error=shortReason(ex);}
            String fail=error;
            runOnUiThread(()->{
                if(destroyed||pane.cache!=file)return;
                if(fail!=null){pane.selection.setText("ZIP listing refused: "+fail);return;}
                pane.zipBrowser=true;
                pane.zipEntry=null;
                pane.documents.clear();pane.documents.addAll(entries);
                pane.page=0;
                pane.back.setEnabled(true);
                pane.zipButton.setText("Close APK/ZIP browser");
                pane.selection.setText(pane.side+": "+pane.selectedName+" · "+entries.size()+" entries");
                renderList(index);
            });
        });
    }
    private void chooseEntry(int index,String name){
        Pane pane=panes[index];
        if(!pane.zipBrowser||pane.cache==null)return;
        pane.zipEntry=name;
        pane.selection.setText(pane.side+": "+pane.selectedName+"\nEntry: "+name);
        pane.preview.setText("Opening archive entry…");
        preview(index);
    }
    private void compare(){
        Pane left=panes[0],right=panes[1];
        if(left.cache==null||right.cache==null){
            headline.setText("Choose a file in BOTH panes first.");
            return;
        }
        final File a=left.cache,b=right.cache;
        final String ae=left.zipEntry,be=right.zipEntry;
        comparison.setText("Comparing two selected sources…");
        compareButton.setEnabled(false);
        io.execute(()->{
            String result;
            try{
                FileComparator.Result diff=
                    (ae==null&&be==null)?FileComparator.compare(a,b):
                    (ae!=null&&be!=null)?FileComparator.compareEntries(a,ae,b,be):
                    null;
                if(diff==null)throw new IOException(
                    "Select either both whole files or one APK entry in each pane");
                result=(diff.identical?"MATCH\n":"DIFFERENT\n")+diff.detail;
            }catch(Exception err){result="Comparison refused: "+shortReason(err);}
            String output=result;
            runOnUiThread(()->{
                if(destroyed)return;
                if(left.cache==a&&right.cache==b &&
                   java.util.Objects.equals(ae,left.zipEntry)&&
                   java.util.Objects.equals(be,right.zipEntry)){
                    comparison.setText(output);
                    headline.setText("Comparison complete · originals unchanged");
                }
                compareButton.setEnabled(true);
            });
        });
    }
    private void swap(){
        Pane left=panes[0],right=panes[1];
        File f=left.cache;left.cache=right.cache;right.cache=f;
        Uri u=left.selectedUri;left.selectedUri=right.selectedUri;right.selectedUri=u;
        String n=left.selectedName;left.selectedName=right.selectedName;right.selectedName=n;
        String e=left.zipEntry;left.zipEntry=right.zipEntry;right.zipEntry=e;
        left.epoch++;right.epoch++;
        left.selection.setText("LEFT: "+left.selectedName+(left.zipEntry==null?"":"\nEntry: "+left.zipEntry));
        right.selection.setText("RIGHT: "+right.selectedName+(right.zipEntry==null?"":"\nEntry: "+right.zipEntry));
        left.zipButton.setEnabled(left.cache!=null);
        right.zipButton.setEnabled(right.cache!=null);
        preview(0);preview(1);
        comparison.setText("Sides swapped. Tap Compare to refresh.");
    }
    private static String shortReason(Throwable e){
        String msg=e.getMessage();
        if(msg==null)return e.getClass().getSimpleName();
        return msg.length()>150?msg.substring(0,150):msg;
    }
    @Override protected void onDestroy(){
        destroyed=true;
        io.shutdownNow();
        for(Pane pane:panes){pane.epoch++;if(pane.cache!=null)pane.cache.delete();}
        super.onDestroy();
    }
}
