package com.vibe.hermesinspector;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.Spinner;
import android.widget.ArrayAdapter;
import android.widget.AdapterView;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.text.Editable;
import android.text.TextWatcher;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Standalone Android on-device read-only APK/Hermes metadata viewer.
 * No INTERNET/storage permission, Python interpreter, dynamic target execution
 * or APK editing/signing. Function names and instructions are not decompiled.
 */
public final class MainActivity extends Activity {
    private static final int PICK_APK = 4201;
    private static final int EXPORT_REPORT = 4202;
    private static final int IMPORT_REPORT = 4203;
    private static final int EXPORT_SOURCE = 4204;
    private static final int EXPORT_PAGE = 4205;
    private static final int EXPORT_UNSIGNED_APK = 4206;
    private static final int SOURCE_PAGE_SIZE = 25;
    private static final int AUDIT_PAGE_SIZE = 20;
    private static final String[] MODES = {"DEX strings", "DEX classes", "DEX method references", "Hermes strings", "Hermes functions", "Hermes opcodes", "Hermes string references", "Printable candidates"};
    private static final int BACKGROUND = Color.rgb(13, 20, 32);
    private static final int SURFACE = Color.rgb(28, 40, 59);
    private static final int TEXT = Color.rgb(237, 246, 255);
    private static final int MUTED = Color.rgb(177, 195, 217);
    private static final int ACCENT = Color.rgb(89, 172, 246);
    private static final int PAGE_SIZE = SearchPager.PAGE_SIZE;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final AtomicBoolean busy = new AtomicBoolean(false);
    private final List<String> filtered = new ArrayList<>();
    private ApkInspector.Report report;
    private ApkFeatureAudit.Result featureAudit;
    private LinearLayout auditCard, auditList;
    private TextView auditSummary, auditPage;
    private Spinner auditTopic;
    private EditText auditFilter, assetEditor;
    private Button auditPrevious, auditNext, editCopy, applyCopy;
    private Button undoDraftButton, previewDiffButton;
    private LinearLayout draftActions;
    private TextView diffPreview;
    private TextDraft localDraft;
    private ApkPatchWorkspace patchWorkspace;
    private PatchPlanStore patchStore;
    private Button patchUndo;
    private LinearLayout patchCard;
    private TextView patchStatus;
    private EditText patchFind,patchReplacement;
    private Button patchStage,patchBatch,patchExport,patchReset;
    private final Button[] quickAuditButtons=new Button[5];
    private final List<ApkFeatureAudit.Hit> auditMatches=new ArrayList<>();
    private int auditPageNumber=0;
    private ApkSourceExplorer.Result sourceIndex;
    private File sourceApk;
    private String selectedSourceText;
    private String selectedSourceName;
    private final List<ApkSourceExplorer.Entry> sourceMatches=new ArrayList<>();
    private LinearLayout sourceCard, sourceList;
    private TextView sourceCounter, sourcePageLabel, sourceText;
    private EditText sourceSearch;
    private Button sourcePrevious, sourceNext, sourceExport, sourceExportPage;
    private Spinner sourceModePicker;
    private EditText previewFind;
    private LinearLayout sourceLinks;
    private ApkSourceExplorer.Entry selectedSourceEntry;
    private List<ApkSourceExplorer.Entry> pendingSourceExports = new ArrayList<>();
    private int sourcePage=0;
    private LibraryStore libraryStore;
    private LinearLayout libraryList;
    private Spinner modePicker;
    private Button exportReport;
    private String lastFilename = "APK";
    private int page = 0;
    private LinearLayout root;
    private LinearLayout resultList;
    private TextView status;
    private TextView summary;
    private TextView bundles;
    private TextView warnings;
    private TextView pageLabel;
    private TextView searchCaption;
    private Button choose;
    private Button previous;
    private Button next;
    private Button copyHash;
    private ProgressBar spinner;
    private EditText search;

    private int dp(float size) {
        return Math.round(getResources().getDisplayMetrics().density * size);
    }

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(BACKGROUND);
        getWindow().setNavigationBarColor(BACKGROUND);
        getWindow().getDecorView().setSystemUiVisibility(0);
        libraryStore = new LibraryStore(this);
        cleanupPreviousSessionTempFiles();
        try{patchStore=new PatchPlanStore(this);}
        catch(IOException unavailable){patchStore=null;}
        createView();
    }

    private void cleanupPreviousSessionTempFiles(){
        File[] files=getCacheDir().listFiles();
        if(files==null)return;
        int removed=0;
        for(File item:files){
            String name=item.getName();
            if(item.isFile() &&
               (name.startsWith("vibe-inspection-")||name.startsWith("vibe-unsigned-")) &&
               (name.endsWith(".apk")||name.endsWith(".partial"))){
                if(item.delete())removed++;
            }
            if(removed>=40)break;
        }
    }

    private GradientDrawable surface(int color, int radius) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(dp(radius));
        return drawable;
    }

    private LinearLayout vertical() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        return layout;
    }

    private TextView text(String value, int size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setLineSpacing(dp(2), 1f);
        if (bold) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return view;
    }

    private Button button(String title) {
        Button control = new Button(this);
        control.setText(title);
        control.setAllCaps(false);
        control.setTextColor(Color.WHITE);
        control.setTextSize(15);
        control.setBackground(surface(Color.rgb(35, 91, 154), 11));
        control.setMinHeight(dp(48));
        control.setPadding(dp(12), dp(8), dp(12), dp(8));
        return control;
    }

    private void margin(View child, LinearLayout parent, int top, int bottom) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        params.setMargins(0, dp(top), 0, dp(bottom));
        parent.addView(child, params);
    }

    private LinearLayout card(String heading) {
        LinearLayout container = vertical();
        container.setPadding(dp(15), dp(15), dp(15), dp(15));
        container.setBackground(surface(SURFACE, 14));
        margin(container, root, 10, 4);
        margin(text(heading, 18, TEXT, true), container, 0, 8);
        return container;
    }

    private void createView() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BACKGROUND);
        root = vertical();
        root.setPadding(dp(14), dp(12), dp(14), dp(24));
        root.setFocusableInTouchMode(true);
        scroll.addView(root);
        setContentView(scroll);

        scroll.setOnApplyWindowInsetsListener((view, insets) -> {
            int top, bottom;
            if (android.os.Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
                top = bars.top;
                bottom = bars.bottom;
            } else {
                top = insets.getSystemWindowInsetTop();
                bottom = insets.getSystemWindowInsetBottom();
            }
            root.setPadding(dp(14), dp(12) + top, dp(14), dp(24) + bottom);
            return insets;
        });
        scroll.requestApplyInsets();

        margin(text("VIBE  /  HERMES INSPECTOR", 12, ACCENT, true), root, 0, 5);
        margin(text("APK Source & Patch Studio", 26, TEXT, true), root, 0, 5);
        margin(text("Offline • Inspect, stage text edits, repack unsigned • Android 9+", 13, MUTED, false),
                root, 0, 10);

        LinearLayout importCard = card("Import APK");
        choose = button("＋  Choose APK file");
        choose.setContentDescription("Choose an APK through the Android document picker");
        margin(choose, importCard, 0, 9);
        choose.setOnClickListener(v -> chooseApk());
        Button dualFileManager=button("⇄  Dual-pane file manager / Compare");
        dualFileManager.setContentDescription("Open dual-pane file manager to browse and compare files or APKs");
        margin(dualFileManager,importCard,8,3);
        dualFileManager.setOnClickListener(v->
            startActivity(new Intent(this,DualPaneActivity.class)));

        spinner = new ProgressBar(this);
        spinner.setIndeterminate(true);
        spinner.setVisibility(View.GONE);
        margin(spinner, importCard, 4, 4);
        status = text("Select a local APK to inspect.", 14, MUTED, false);
        status.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        margin(status, importCard, 0, 0);

        auditCard=card("🔎 Feature evidence — VIP / Premium / Billing / Ads");
        margin(text("Searches real DEX strings, class names and method definitions. Results are references, not unlocked features.",12,MUTED,false),auditCard,0,8);
        auditSummary=text("Choose an APK to scan premium, subscription, billing and advertising references.",13,MUTED,false);
        auditSummary.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        margin(auditSummary,auditCard,0,9);
        auditTopic=new Spinner(this);
        ArrayList<String> topics=new ArrayList<>();
        for(ApkFeatureAudit.Topic t:ApkFeatureAudit.Topic.values())topics.add(t.title);
        ArrayAdapter<String> adapter=new ArrayAdapter<>(this,
            android.R.layout.simple_spinner_dropdown_item,topics);
        auditTopic.setAdapter(adapter);
        auditTopic.setContentDescription("Choose feature evidence category");
        margin(auditTopic,auditCard,0,9);
        String[] quickNames={"VIP / Pro","Subscription","Billing","Ads","Analytics"};
        for(int quickRow=0;quickRow<3;quickRow++){
            LinearLayout row= new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            for(int column=0;column<2;column++){
                int choice=quickRow*2+column;
                if(choice>=quickNames.length)break;
                Button quick=button(quickNames[choice]+" · 0");
                quick.setTextSize(12);
                quick.setContentDescription("Show "+quickNames[choice]+" evidence");
                quickAuditButtons[choice]=quick;
                LinearLayout.LayoutParams config=new LinearLayout.LayoutParams(0,dp(47),1);
                if(column==1)config.setMargins(dp(5),0,0,0);
                row.addView(quick,config);
                quick.setOnClickListener(v->{
                    auditTopic.setSelection(choice);
                    if(auditFilter!=null)auditFilter.setText("");
                    auditPageNumber=0;showAuditMatches();
                });
            }
            margin(row,auditCard,0,5);
        }
        auditTopic.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener(){
            @Override public void onItemSelected(AdapterView<?> parent,View view,int position,long id){
                auditPageNumber=0;showAuditMatches();
            }
            @Override public void onNothingSelected(AdapterView<?> parent){}
        });
        auditFilter=new EditText(this);
        auditFilter.setSingleLine(true);
        auditFilter.setTextColor(TEXT);
        auditFilter.setHintTextColor(MUTED);
        auditFilter.setHint("Filter feature references");
        auditFilter.setContentDescription("Search within selected premium, billing or ad evidence");
        auditFilter.setPadding(dp(12),dp(11),dp(12),dp(11));
        auditFilter.setBackground(surface(Color.rgb(14,26,43),10));
        margin(auditFilter,auditCard,0,9);
        auditFilter.addTextChangedListener(new TextWatcher(){
            @Override public void beforeTextChanged(CharSequence x,int a,int n,int b){}
            @Override public void onTextChanged(CharSequence x,int a,int b,int n){
                auditPageNumber=0;showAuditMatches();
            }
            @Override public void afterTextChanged(Editable x){}
        });
        LinearLayout auditNavigation=new LinearLayout(this);
        auditNavigation.setOrientation(LinearLayout.HORIZONTAL);
        auditPrevious=button("Previous");
        auditNext=button("Next");
        auditPage=text("Page 1 / 1",12,TEXT,true);
        auditPage.setGravity(Gravity.CENTER);
        auditPage.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        auditNavigation.addView(auditPrevious,new LinearLayout.LayoutParams(0,dp(48),2));
        auditNavigation.addView(auditPage,new LinearLayout.LayoutParams(0,dp(48),2));
        auditNavigation.addView(auditNext,new LinearLayout.LayoutParams(0,dp(48),2));
        margin(auditNavigation,auditCard,0,8);
        auditPrevious.setOnClickListener(v->{if(auditPageNumber>0){auditPageNumber--;showAuditPage();}});
        auditNext.setOnClickListener(v->{
            if((auditPageNumber+1)*AUDIT_PAGE_SIZE<auditMatches.size()){
                auditPageNumber++;showAuditPage();
            }
        });
        auditList=vertical();
        auditCard.addView(auditList);
        showAuditMatches();

        LinearLayout recentCard=card("Local APK library");
        margin(text("Saved document references only. A temporary APK copy is kept during this session for browsing and removed on close.",
                12,MUTED,false),recentCard,0,8);
        libraryList=vertical();
        recentCard.addView(libraryList);
        refreshLibrary();

        LinearLayout metadataCard = card("Package & bytecode metadata");
        summary = text("No APK selected", 14, TEXT, false);
        margin(summary, metadataCard, 2, 8);
        bundles = text("", 13, MUTED, false);
        margin(bundles, metadataCard, 2, 8);
        copyHash = button("Copy APK SHA-256");
        copyHash.setEnabled(false);
        margin(copyHash, metadataCard, 2, 1);
        copyHash.setOnClickListener(v -> {
            if (report == null) return;
            ClipboardManager manager = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (manager != null) {
                manager.setPrimaryClip(ClipData.newPlainText("APK SHA-256", report.sha256));
                status.setText("SHA-256 copied to clipboard.");
            }
        });
        exportReport=button("Export analysis report (.json)");
        exportReport.setEnabled(false);
        margin(exportReport,metadataCard,9,0);
        exportReport.setOnClickListener(v -> exportReport());
        Button importReport=button("Import saved analysis (.json)");
        margin(importReport,metadataCard,9,0);
        importReport.setContentDescription("Import a previously saved analysis report");
        importReport.setOnClickListener(v -> chooseReport());

        sourceCard=card("Explore APK source & files");
        sourceCard.setVisibility(View.GONE);
        margin(text("Files, bundled scripts and reconstructed DEX method bytecode. Original Kotlin/Java/Dart source is generally absent.",13,MUTED,false),sourceCard,0,10);
        sourceSearch=new EditText(this);
        sourceSearch.setTextColor(TEXT);
        sourceSearch.setHintTextColor(MUTED);
        sourceSearch.setSingleLine(true);
        sourceSearch.setHint("Find class, source file, or resource path");
        sourceSearch.setContentDescription("Search packaged APK files and DEX classes");
        sourceSearch.setBackground(surface(Color.rgb(14,26,43),10));
        sourceSearch.setPadding(dp(14),dp(11),dp(14),dp(11));
        margin(sourceSearch,sourceCard,0,8);
        sourceSearch.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence t,int start,int count,int after){}
            @Override public void onTextChanged(CharSequence t,int start,int before,int count){
                sourcePage=0; refreshSourceResults();
            }
            @Override public void afterTextChanged(Editable e){}
        });
        sourceCounter=text("No source index",13,MUTED,false);
        margin(sourceCounter,sourceCard,0,8);
        LinearLayout sourceNav=new LinearLayout(this);
        sourceNav.setOrientation(LinearLayout.HORIZONTAL);
        sourceNav.setGravity(Gravity.CENTER_VERTICAL);
        sourcePrevious=button("‹");
        sourcePrevious.setContentDescription("Previous APK source file page");
        sourceNext=button("›");
        sourceNext.setContentDescription("Next APK source file page");
        sourcePageLabel=text("Page 1/1",12,TEXT,true);
        sourcePageLabel.setGravity(Gravity.CENTER);
        sourcePageLabel.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        sourceNav.addView(sourcePrevious,new LinearLayout.LayoutParams(0,dp(48),1));
        sourceNav.addView(sourcePageLabel,new LinearLayout.LayoutParams(0,dp(48),3));
        sourceNav.addView(sourceNext,new LinearLayout.LayoutParams(0,dp(48),1));
        margin(sourceNav,sourceCard,0,6);
        sourcePrevious.setOnClickListener(v->{if(sourcePage>0){sourcePage--;showSourceResults();}});
        sourceNext.setOnClickListener(v->{
            if((sourcePage+1)*SOURCE_PAGE_SIZE<sourceMatches.size()){
                sourcePage++;showSourceResults();
            }
        });
        sourceList=vertical();
        sourceCard.addView(sourceList);
        margin(text("Source preview (read-only)",16,TEXT,true),sourceCard,12,6);
        sourceModePicker=new Spinner(this);
        sourceModePicker.setContentDescription("Smali, pseudocode or explicit calls view mode");
        ArrayAdapter<String> sourceViews=new ArrayAdapter<>(this,
            android.R.layout.simple_spinner_dropdown_item,
            new String[]{"DEX bytecode (Smali-like)","Java-like commentary (approximate)",
                "Explicit invoke callsites"});
        sourceModePicker.setAdapter(sourceViews);
        margin(sourceModePicker,sourceCard,0,8);
        sourceModePicker.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener(){
            @Override public void onItemSelected(AdapterView<?> parent,View view,int position,long id){
                if(selectedSourceEntry!=null)openSourceEntry(selectedSourceEntry);
            }
            @Override public void onNothingSelected(AdapterView<?> parent){}
        });
        previewFind=new EditText(this);
        previewFind.setSingleLine(true);
        previewFind.setTextColor(TEXT);
        previewFind.setHintTextColor(MUTED);
        previewFind.setHint("Highlight text in open source");
        previewFind.setContentDescription("Search within displayed source preview");
        previewFind.setPadding(dp(12),dp(8),dp(12),dp(8));
        previewFind.setBackground(surface(Color.rgb(14,26,43),10));
        margin(previewFind,sourceCard,0,8);
        previewFind.addTextChangedListener(new TextWatcher(){
            @Override public void beforeTextChanged(CharSequence t,int st,int n,int after){}
            @Override public void onTextChanged(CharSequence t,int st,int before,int count){
                if(selectedSourceText!=null)renderSourcePreview(selectedSourceText);
            }
            @Override public void afterTextChanged(Editable t){}
        });
        sourceExportPage=button("Export visible source page as ZIP (up to 25)");
        sourceExportPage.setEnabled(false);
        margin(sourceExportPage,sourceCard,0,7);
        sourceExportPage.setOnClickListener(v->startPageExport());
        sourceExport=button("Export selected text/source");
        sourceExport.setEnabled(false);
        margin(sourceExport,sourceCard,0,8);
        sourceExport.setOnClickListener(v->startSourceExport());
        editCopy=button("✎ Edit a local text copy");
        editCopy.setEnabled(false);
        margin(editCopy,sourceCard,0,8);
        editCopy.setOnClickListener(v->startEditCopy());
        assetEditor=new EditText(this);
        assetEditor.setTextColor(TEXT);
        assetEditor.setTextSize(13);
        assetEditor.setTypeface(Typeface.MONOSPACE);
        assetEditor.setGravity(Gravity.TOP);
        assetEditor.setMinLines(8);
        assetEditor.setMaxLines(18);
        assetEditor.setContentDescription("Editable local copy of packaged plaintext resource");
        assetEditor.setVisibility(View.GONE);
        assetEditor.setBackground(surface(Color.rgb(14,26,43),10));
        assetEditor.setPadding(dp(10),dp(10),dp(10),dp(10));
        margin(assetEditor,sourceCard,0,8);
        draftActions=new LinearLayout(this);
        draftActions.setOrientation(LinearLayout.HORIZONTAL);
        undoDraftButton=button("↶ Undo edit");
        previewDiffButton=button("Show changes");
        draftActions.addView(undoDraftButton,new LinearLayout.LayoutParams(0,dp(48),1));
        LinearLayout.LayoutParams diffButtonSize=new LinearLayout.LayoutParams(0,dp(48),1);
        diffButtonSize.setMargins(dp(5),0,0,0);
        draftActions.addView(previewDiffButton,diffButtonSize);
        draftActions.setVisibility(View.GONE);
        margin(draftActions,sourceCard,0,8);
        diffPreview=text("No changes.",12,MUTED,false);
        diffPreview.setTypeface(Typeface.MONOSPACE);
        diffPreview.setTextIsSelectable(true);
        diffPreview.setVisibility(View.GONE);
        margin(diffPreview,sourceCard,0,7);
        undoDraftButton.setOnClickListener(v->{
            if(localDraft==null)return;
            boolean reversed=localDraft.undo();
            assetEditor.setText(localDraft.current());
            diffPreview.setText(localDraft.diff());
            status.setText(reversed?"Last applied local edit undone.":"No older applied edit.");
        });
        previewDiffButton.setOnClickListener(v->{
            if(localDraft==null)return;
            try{
                TextDraft candidate=new TextDraft(localDraft.original());
                candidate.apply(assetEditor.getText().toString());
                diffPreview.setText(candidate.diff());
                status.setText("Diff shows local copy only; original APK unchanged.");
            }catch(IllegalArgumentException error){
                status.setText("Diff refused: "+error.getMessage());
            }
        });
        applyCopy=button("Use edited text for export");
        applyCopy.setVisibility(View.GONE);
        margin(applyCopy,sourceCard,0,8);
        applyCopy.setOnClickListener(v->{
            if(assetEditor.getVisibility()!=View.VISIBLE||localDraft==null)return;
            try{
                localDraft.apply(assetEditor.getText().toString());
                selectedSourceText="# Edited LOCAL COPY — original APK unchanged\n"+
                    localDraft.current();
                renderSourcePreview(selectedSourceText);
                diffPreview.setText(localDraft.diff());
                sourceExport.setEnabled(true);
                status.setText("Local copy modified for export only. Original APK unchanged.");
            }catch(IllegalArgumentException over){
                status.setText("Edit refused: "+over.getMessage());
            }
        });
        sourceText=text("Select a class or file to view its decoded content.",12,TEXT,false);
        sourceText.setTypeface(Typeface.MONOSPACE);
        sourceText.setTextIsSelectable(true);
        sourceText.setPadding(dp(12),dp(12),dp(12),dp(12));
        sourceText.setBackground(surface(Color.rgb(12,23,37),10));
        margin(sourceText,sourceCard,0,6);
        sourceLinks=vertical();
        sourceCard.addView(sourceLinks);

        patchCard=card("⚙️ Automated APK Text Patch Workspace");
        patchCard.setVisibility(View.GONE);
        margin(text("For your own or authorized APKs. Stage non-executable assets, inspect changes, then export a NEW UNSIGNED APK. Do not install until aligned and correctly signed.",12,MUTED,false),patchCard,0,8);
        patchStatus=text("No patches staged.",13,MUTED,false);
        patchStatus.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        patchStatus.setTextIsSelectable(true);
        margin(patchStatus,patchCard,0,8);
        patchStage=button("＋ Stage selected text-asset edit");
        margin(patchStage,patchCard,0,8);
        patchStage.setOnClickListener(v->stageSelectedPatch());
        patchFind=new EditText(this);
        patchFind.setSingleLine(true);
        patchFind.setTextColor(TEXT);
        patchFind.setHintTextColor(MUTED);
        patchFind.setHint("Exact text to find (non-executable assets)");
        patchFind.setContentDescription("Exact search string for automated text-resource replacements");
        patchFind.setBackground(surface(Color.rgb(14,26,43),10));
        patchFind.setPadding(dp(12),dp(10),dp(12),dp(10));
        margin(patchFind,patchCard,8,6);
        patchReplacement=new EditText(this);
        patchReplacement.setSingleLine(true);
        patchReplacement.setTextColor(TEXT);
        patchReplacement.setHintTextColor(MUTED);
        patchReplacement.setHint("Replacement text");
        patchReplacement.setContentDescription("Replacement string for eligible text-resource assets");
        patchReplacement.setBackground(surface(Color.rgb(14,26,43),10));
        patchReplacement.setPadding(dp(12),dp(10),dp(12),dp(10));
        margin(patchReplacement,patchCard,0,7);
        patchBatch=button("▶ Auto-stage exact replacements");
        margin(patchBatch,patchCard,0,8);
        patchBatch.setOnClickListener(v->runBatchPatch());
        patchUndo=button("↶ Undo last staged operation");
        margin(patchUndo,patchCard,0,7);
        patchUndo.setOnClickListener(v->{
            if(patchWorkspace==null||busy.get())return;
            if(patchWorkspace.undo()){
                String warning=savePatchCheckpoint();
                refreshPatchStatus();
                status.setText("Last staged operation undone."+warning);
            }else status.setText("No earlier patch queue state available.");
        });
        patchReset=button("↶ Discard all staged patches");
        margin(patchReset,patchCard,0,7);
        patchReset.setOnClickListener(v->{
            if(patchWorkspace==null || busy.get())return;
            patchWorkspace.clear();
            String warning=savePatchCheckpoint();
            refreshPatchStatus();
            status.setText("Staged changes discarded. Original APK unchanged."+warning);
        });
        Button validatePatch=button("✓ Preflight staged patches (read-only)");
        validatePatch.setContentDescription("Verify staged resource hashes and APK ZIP safety before export");
        margin(validatePatch,patchCard,0,8);
        validatePatch.setOnClickListener(v->{
            if(patchWorkspace==null||sourceApk==null||!busy.compareAndSet(false,true))return;
            final ApkPatchWorkspace plan=patchWorkspace;
            final File file=sourceApk;
            validatePatch.setEnabled(false);
            status.setText("Checking staged hashes and ZIP limits...");
            executor.execute(()->{
                String message;
                try{
                    ApkPatchWorkspace.Validation verified=plan.validateStaged(file);
                    message="Preflight PASS: "+verified.stagedFiles+
                        " text changes, "+verified.zipEntries+" ZIP entries; "+
                        verified.strippedSignatureEntries+" existing signature records will be stripped."+
                        " Export remains UNSIGNED.";
                }catch(IOException invalid){
                    message="Preflight REJECTED: "+invalid.getMessage();
                }catch(RuntimeException invalid){
                    message="Preflight FAILED on malformed input: "+invalid.getClass().getSimpleName();
                }
                final String result=message;
                busy.set(false);
                runOnUiThread(()->{
                    if(!isFinishing()&&!isDestroyed()){
                        validatePatch.setEnabled(true);
                        if(patchWorkspace==plan&&sourceApk==file)
                            status.setText(result);
                    }
                });
            });
        });
        patchExport=button("Export modified APK (UNSIGNED; signing required)");
        patchExport.setEnabled(false);
        margin(patchExport,patchCard,0,9);
        patchExport.setOnClickListener(v->chooseUnsignedExport());

        LinearLayout stringCard = card("Indexed analysis & search");
        margin(text("Browse verified DEX and Hermes records by category. Printable candidates are unverified.",
                12, MUTED, false), stringCard, 0, 8);
        modePicker = new Spinner(this);
        ArrayAdapter<String> modes = new ArrayAdapter<>(this,
             android.R.layout.simple_spinner_dropdown_item, MODES);
        modePicker.setAdapter(modes);
        modePicker.setContentDescription("Choose indexed analysis category");
        margin(modePicker, stringCard, 0, 12);
        modePicker.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent,View view,int position,long id) {
                page=0;updateResults();
            }
            @Override public void onNothingSelected(AdapterView<?> parent) {}
        });
        search = new EditText(this);
        search.setSingleLine(true);
        search.setTextColor(TEXT);
        search.setHintTextColor(MUTED);
        search.setTextSize(16);
        search.setHint("Search indexed records");
        search.setContentDescription("Filter indexed DEX and Hermes analysis records");
        search.setBackground(surface(Color.rgb(14, 26, 43), 10));
        search.setPadding(dp(14), dp(11), dp(14), dp(11));
        margin(search, stringCard, 0, 10);
        search.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                page = 0;
                updateResults();
            }
            @Override public void afterTextChanged(Editable s) {}
        });
        searchCaption = text("0 matching records", 13, MUTED, false);
        margin(searchCaption, stringCard, 0, 8);

        LinearLayout nav = new LinearLayout(this);
        nav.setGravity(Gravity.CENTER_VERTICAL);
        nav.setOrientation(LinearLayout.HORIZONTAL);
        previous = button("Previous");
        next = button("Next");
        pageLabel = text("Page 1 / 1", 12, TEXT, true);
        pageLabel.setGravity(Gravity.CENTER);
        pageLabel.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        previous.setContentDescription("Previous results page");
        next.setContentDescription("Next results page");
        nav.addView(previous, new LinearLayout.LayoutParams(0, dp(48), 1));
        nav.addView(pageLabel, new LinearLayout.LayoutParams(0, dp(48), 1));
        nav.addView(next, new LinearLayout.LayoutParams(0, dp(48), 1));
        margin(nav, stringCard, 0, 10);
        previous.setOnClickListener(v -> {
            if (page > 0) {
                page--;
                showPage();
            }
        });
        next.setOnClickListener(v -> {
            int count = SearchPager.pageCount(filtered.size());
            if (page + 1 < count) {
                page++;
                showPage();
            }
        });

        resultList = vertical();
        stringCard.addView(resultList);
        warnings = text("Full disassembly is not embedded in this build.", 13, MUTED, false);
        LinearLayout limits = card("Validation & limitations");
        margin(warnings, limits, 0, 0);
        updateResults();
    }

    private void chooseApk() {
        if (busy.get()) return;
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        try {
            startActivityForResult(intent, PICK_APK);
        } catch (android.content.ActivityNotFoundException missingPicker) {
            status.setText("No Android document picker is available.");
        }
    }

    @Override
    protected void onActivityResult(int requestCode,int resultCode,Intent data) {
        super.onActivityResult(requestCode,resultCode,data);
        if(resultCode!=RESULT_OK || data==null || data.getData()==null)return;
        Uri uri=data.getData();
        if(requestCode==PICK_APK) {
            boolean persisted=libraryStore.grant(uri);
            startAnalysis(uri,displayName(uri),persisted);
        }else if(requestCode==EXPORT_REPORT) {
            writeExport(uri);
        }else if(requestCode==IMPORT_REPORT) {
            importReport(uri);
        }else if(requestCode==EXPORT_SOURCE){
            exportSource(uri);
        }else if(requestCode==EXPORT_PAGE){
            exportPage(uri);
        }else if(requestCode==EXPORT_UNSIGNED_APK){
            exportUnsigned(uri);
        }
    }

    private void startAnalysis(Uri uri,String name,boolean persisted) {
        if(!busy.compareAndSet(false,true))return;
        choose.setEnabled(false);
        spinner.setVisibility(View.VISIBLE);
        status.setText("Analyzing "+name+" locally…");
        executor.execute(()->{
            File scratch=null;
            try{
                scratch=File.createTempFile("vibe-inspection-",".apk",getCacheDir());
                copyBounded(uri,scratch);
                ApkInspector.Report result=ApkInspector.inspect(scratch,
                    version->getAssets().open("opcodes/hbc"+version+".json"));
                ApkSourceExplorer.Result sources=null;
                try{sources=ApkSourceExplorer.index(scratch);}
                catch(IOException rejected){result.warnings.add("Source browser unavailable: "+rejected.getMessage());}
                ApkFeatureAudit.Result audit=null;
                try{audit=ApkFeatureAudit.analyze(scratch);}
                catch(IOException rejected){result.warnings.add("Feature evidence scan failed: "+rejected.getMessage());}
                final ApkFeatureAudit.Result featureResults=audit;
                final ApkSourceExplorer.Result ready=sources;
                ApkPatchWorkspace recovered=null;
                String recoveryNote=null;
                try{
                    recovered=patchStore==null?new ApkPatchWorkspace(scratch):patchStore.load(scratch);
                }catch(IOException badCheckpoint){
                    recoveryNote="Saved patch plan could not be restored: "+badCheckpoint.getMessage();
                    try{recovered=new ApkPatchWorkspace(scratch);}
                    catch(IOException badSource){
                        recoveryNote="Patch workspace unavailable: "+badSource.getMessage();
                    }
                }
                final ApkPatchWorkspace readyPatch=recovered;
                if(recoveryNote!=null)result.warnings.add(recoveryNote);
                final File captured=scratch;
                scratch=null;
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed())return;
                    if(sourceApk!=null && !sourceApk.equals(captured))sourceApk.delete();
                    sourceApk=captured;
                    sourceIndex=ready;
                    patchWorkspace=readyPatch;
                    patchCard.setVisibility(readyPatch==null?View.GONE:View.VISIBLE);
                    refreshPatchStatus();
                    featureAudit=featureResults;
                    updateAuditSummary();
                    selectedSourceText=null;
                    selectedSourceName=null;
                    selectedSourceEntry=null;
                    localDraft=null;
                    draftActions.setVisibility(View.GONE);
                    diffPreview.setVisibility(View.GONE);
                    pendingSourceExports.clear();
                    if(sourceLinks!=null)sourceLinks.removeAllViews();
                    sourceExport.setEnabled(false);
                    editCopy.setEnabled(false);
                    assetEditor.setVisibility(View.GONE);
                    applyCopy.setVisibility(View.GONE);
                    sourceText.setText("Select a file or class to read its bytecode.");
                    sourceCard.setVisibility(ready==null?View.GONE:View.VISIBLE);
                    sourcePage=0;
                    sourceSearch.setText("");
                    refreshSourceResults();
                    report=result;
                    lastFilename=name;
                    status.setText("Completed: "+name);
                    summary.setText(
                        "SHA-256: "+result.sha256+"\n"+
                        "Size: "+result.byteSize+" bytes\n"+
                        "ZIP entries: "+result.entries+"\n"+
                        "Technologies: "+String.join(", ",result.technologies)+"\n"+
                        "DEX files indexed: "+result.dexParsed+"\n"+
                        "DEX classes declared: "+result.dexDeclaredClasses+"\n"+
                        "DEX method references declared: "+result.dexDeclaredMethods+"\n"+
                        "DEX strings declared: "+result.dexDeclaredStrings+"\n"+
                        "Confirmed Hermes bundles: "+result.hermesBundles+"\n"+
                        "Hermes functions declared: "+result.functionCount+"\n"+
                        "Hermes instructions decoded: "+result.hermesDecodedInstructions);
                    bundles.setText(result.bundleDetails.isEmpty()?
                        "No Hermes bundles. Choose DEX strings/classes/methods below.":
                        String.join("\n\n",result.bundleDetails));
                    warnings.setText(String.join("\n\n",result.warnings));
                    copyHash.setEnabled(true);
                    exportReport.setEnabled(true);
                    modePicker.setSelection(result.dexParsed>0 ? 0 :
                        result.hermesBundles>0 ? 3 : 7);
                    page=0;updateResults();
                    if(persisted){
                        libraryStore.save(uri,name,result.sha256);
                        refreshLibrary();
                    }
                });
            }catch(Exception failure){
                final String message=failure.getMessage()==null?
                    "Malformed or unsupported APK":failure.getMessage();
                runOnUiThread(()->{
                    if(!isFinishing()&&!isDestroyed())
                        status.setText("Inspection failed: "+message);
                });
            }finally{
                if(scratch!=null && scratch.exists())scratch.delete();
                busy.set(false);
                runOnUiThread(()->{
                    if(!isFinishing()&&!isDestroyed()){
                        choose.setEnabled(true);
                        spinner.setVisibility(View.GONE);
                    }
                });
            }
        });
    }

    private void refreshLibrary() {
        if(libraryList==null)return;
        libraryList.removeAllViews();
        List<LibraryStore.Item> items=libraryStore.list();
        if(items.isEmpty()){
            margin(text("No saved APK references yet",13,MUTED,false),libraryList,2,4);
            return;
        }
        for(LibraryStore.Item item:items){
            LinearLayout row=vertical();
            margin(text(item.name,14,TEXT,true),row,4,2);
            TextView digest=text(item.sha.substring(0,16)+"…",11,MUTED,false);
            margin(digest,row,0,5);
            LinearLayout buttons=new LinearLayout(this);
            buttons.setOrientation(LinearLayout.HORIZONTAL);
            Button open=button("Open");
            Button forget=button("Remove");
            buttons.addView(open,new LinearLayout.LayoutParams(0,dp(44),2));
            buttons.addView(forget,new LinearLayout.LayoutParams(0,dp(44),1));
            margin(buttons,row,0,4);
            open.setOnClickListener(v->
                startAnalysis(Uri.parse(item.uri),item.name,false));
            forget.setOnClickListener(v->{
                libraryStore.remove(item.uri);
                refreshLibrary();
            });
            margin(row,libraryList,3,6);
        }
    }

    private void chooseReport() {
        if(busy.get())return;
        Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/json");
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try{startActivityForResult(intent,IMPORT_REPORT);}
        catch(android.content.ActivityNotFoundException error){
            status.setText("No document provider is available for report import");
        }
    }

    private void importReport(Uri uri) {
        if(!busy.compareAndSet(false,true))return;
        choose.setEnabled(false);
        spinner.setVisibility(View.VISIBLE);
        status.setText("Validating offline JSON report…");
        executor.execute(()->{
            try(InputStream input=getContentResolver().openInputStream(uri)){
                if(input==null)throw new IOException("Document provider returned no report");
                java.io.ByteArrayOutputStream buf=new java.io.ByteArrayOutputStream();
                byte[] chunk=new byte[32768];
                int n;
                while((n=input.read(chunk))!=-1){
                    if(Thread.currentThread().isInterrupted())throw new IOException("Import cancelled");
                    if(buf.size()+n>ReportImporter.MAX_JSON_BYTES)
                        throw new IOException("JSON report exceeds 4 MiB");
                    buf.write(chunk,0,n);
                }
                java.nio.charset.CharsetDecoder decoder=StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT);
                String content=decoder.decode(
                    java.nio.ByteBuffer.wrap(buf.toByteArray())).toString();
                final ApkInspector.Report restored=ReportImporter.parse(content);
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed())return;
                    if(sourceApk!=null){sourceApk.delete();sourceApk=null;}
                    sourceIndex=null;
                    patchWorkspace=null;
                    patchCard.setVisibility(View.GONE);
                    sourceCard.setVisibility(View.GONE);
                    featureAudit=null;
                    updateAuditSummary();
                    localDraft=null;
                    draftActions.setVisibility(View.GONE);
                    diffPreview.setVisibility(View.GONE);
                    report=restored;
                    lastFilename="Imported report";
                    status.setText("Saved report loaded. Original APK NOT re-verified.");
                    summary.setText("IMPORTED ANALYSIS — UNVERIFIED\n"+
                        "Recorded SHA-256: "+restored.sha256+"\n"+
                        "Recorded APK bytes: "+restored.byteSize+"\n"+
                        "Recorded DEX class IDs: "+restored.dexDeclaredClasses+"\n"+
                        "Recorded Hermes functions: "+restored.functionCount);
                    bundles.setText(restored.bundleDetails.isEmpty()?
                        "No HBC bundle records in imported report":
                        String.join("\n\n",restored.bundleDetails));
                    warnings.setText(String.join("\n\n",restored.warnings));
                    copyHash.setEnabled(true);
                    exportReport.setEnabled(true);
                    modePicker.setSelection(!restored.dexStrings.isEmpty()?0:
                        !restored.hermesStrings.isEmpty()?3:7);
                    page=0;updateResults();
                });
            }catch(Exception error){
                final String message=error.getMessage()==null?
                    "Malformed JSON report":error.getMessage();
                runOnUiThread(()->{
                    if(!isFinishing()&&!isDestroyed())
                        status.setText("Report import refused: "+message);
                });
            }finally{
                busy.set(false);
                runOnUiThread(()->{
                    if(!isFinishing()&&!isDestroyed()){
                        choose.setEnabled(true);
                        spinner.setVisibility(View.GONE);
                    }
                });
            }
        });
    }

    private void updateAuditSummary(){
        if(auditSummary==null)return;
        if(featureAudit==null){
            auditSummary.setText("No full DEX evidence scan available.");
        }else{
            StringBuilder out=new StringBuilder();
            out.append("DEX scanned: ").append(featureAudit.dexIndexed)
               .append(" · strings ").append(featureAudit.stringsScanned)
               .append(" · methods ").append(featureAudit.methodsScanned)
               .append(" · string-use sites ").append(featureAudit.stringUseSites).append("\n");
            for(ApkFeatureAudit.Topic topic:ApkFeatureAudit.Topic.values())
                out.append(topic.title).append(": ")
                   .append(featureAudit.count(topic)).append(" static matches\n");
            if(featureAudit.limitReached)out.append("Some results truncated by safety limits.\n");
            out.append("Matches do NOT verify any active premium entitlement or ad delivery.");
            auditSummary.setText(out.toString());
        }
        String[] titles={"VIP / Pro","Subscription","Billing","Ads","Analytics"};
        for(int i=0;i<quickAuditButtons.length;i++){
            if(quickAuditButtons[i]!=null)
                quickAuditButtons[i].setText(titles[i]+" · "+
                    (featureAudit==null?0:featureAudit.count(ApkFeatureAudit.Topic.values()[i])));
        }
        showAuditMatches();
    }

    private void showAuditMatches(){
        if(auditList==null||auditTopic==null)return;
        auditMatches.clear();
        if(featureAudit!=null){
            ApkFeatureAudit.Topic[] values=ApkFeatureAudit.Topic.values();
            int topic=Math.max(0,Math.min(auditTopic.getSelectedItemPosition(),values.length-1));
            String filter=auditFilter==null?"":auditFilter.getText().toString().toLowerCase(Locale.ROOT).trim();
            for(ApkFeatureAudit.Hit hit:featureAudit.hits.get(values[topic])){
                if(filter.isEmpty()||hit.display().toLowerCase(Locale.ROOT).contains(filter))
                    auditMatches.add(hit);
            }
        }
        showAuditPage();
    }

    private void showAuditPage(){
        if(auditList==null||auditPage==null)return;
        auditList.removeAllViews();
        int pages=Math.max(1,(auditMatches.size()+AUDIT_PAGE_SIZE-1)/AUDIT_PAGE_SIZE);
        auditPageNumber=Math.min(Math.max(0,auditPageNumber),pages-1);
        int from=auditPageNumber*AUDIT_PAGE_SIZE;
        int to=Math.min(auditMatches.size(),from+AUDIT_PAGE_SIZE);
        for(int i=from;i<to;i++){
            ApkFeatureAudit.Hit hit=auditMatches.get(i);
            Button item=button(hit.display());
            item.setTextSize(12);
            item.setContentDescription("Inspect static evidence "+hit.display());
            margin(item,auditList,0,3);
            item.setOnClickListener(v->{
                if(hit.classDescriptor!=null&&sourceIndex!=null){
                    for(ApkSourceExplorer.Entry candidate:sourceIndex.entries){
                        if("class".equals(candidate.kind)&&
                           hit.classDescriptor.equals(candidate.classDescriptor)&&
                           hit.dexPath.equals(candidate.archivePath)){
                            sourceSearch.setText(hit.classDescriptor);
                            if("Method string use".equals(hit.kind)){
                                int arrow=hit.evidence.indexOf("->");
                                int space=hit.evidence.indexOf(" uses ",arrow);
                                if(arrow>=0&&space>arrow+2)
                                    previewFind.setText(hit.evidence.substring(arrow+2,space));
                            }
                            openSourceEntry(candidate);
                            return;
                        }
                    }
                }
                ClipboardManager clipboard=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);
                if(clipboard!=null)
                    clipboard.setPrimaryClip(ClipData.newPlainText("Static APK audit evidence",hit.display()));
                status.setText("Static evidence copied. Does not prove entitlement/ad status.");
            });
        }
        if(auditMatches.isEmpty())
            margin(text("No matching static references in this category.",13,MUTED,false),
                auditList,0,5);
        auditPage.setText("Page "+(auditPageNumber+1)+" / "+pages);
        auditPrevious.setEnabled(auditPageNumber>0);
        auditNext.setEnabled(auditPageNumber+1<pages);
    }

    private void startEditCopy(){
        if(selectedSourceEntry==null||selectedSourceText==null||
           !"file".equals(selectedSourceEntry.kind)||
           !ApkSourceExplorer.isText(selectedSourceEntry.archivePath))return;
        String source=selectedSourceText;
        int newline=source.indexOf("\n\n");
        if(source.startsWith("# Packaged text asset:") && newline>=0)
            source=source.substring(newline+2);
        if(source.getBytes(StandardCharsets.UTF_8).length>65536){
            status.setText("Text resource too large for safe editing");return;
        }
        try{
            localDraft=new TextDraft(source);
        }catch(IllegalArgumentException invalid){
            status.setText("Cannot edit local copy: "+invalid.getMessage());return;
        }
        assetEditor.setText(source);
        assetEditor.setVisibility(View.VISIBLE);
        applyCopy.setVisibility(View.VISIBLE);
        draftActions.setVisibility(View.VISIBLE);
        diffPreview.setVisibility(View.VISIBLE);
        diffPreview.setText("No changes.");
        status.setText("Editing an exported copy; the imported APK is unchanged.");
    }

    private void refreshPatchStatus(){
        if(patchStatus==null||patchExport==null)return;
        if(patchWorkspace==null){
            patchStatus.setText("Load an authorized APK to stage text patches.");
            patchExport.setEnabled(false);
            return;
        }
        StringBuilder info=new StringBuilder();
        info.append(patchWorkspace.size()).append(" / ").append(ApkPatchWorkspace.MAX_STAGE)
            .append(" text assets staged\nOriginal SHA-256: ")
            .append(patchWorkspace.sourceSha256()).append("\n");
        for(ApkPatchWorkspace.Change entry:patchWorkspace.staged())
            info.append("• ").append(entry.describe()).append("\n");
        if(patchWorkspace.size()==0)info.append("No pending modifications.");
        info.append("\nOutput is UNSIGNED; Android install requires private-key signing.");
        patchStatus.setText(info.toString());
        patchExport.setEnabled(patchWorkspace.size()>0);
        if(patchUndo!=null)patchUndo.setEnabled(patchWorkspace.canUndo());
    }

    private String savePatchCheckpoint(){
        if(patchWorkspace==null)return "";
        if(patchStore==null)return " Checkpoint persistence unavailable on this device.";
        try{
            patchStore.save(patchWorkspace);
            return " Patch queue saved privately.";
        }catch(IOException error){
            return " WARNING: patch queue not saved: "+error.getMessage();
        }
    }
    private void stageSelectedPatch(){
        if(patchWorkspace==null||sourceApk==null||selectedSourceEntry==null||
           !"file".equals(selectedSourceEntry.kind)||localDraft==null){
            status.setText("Select and edit a supported text asset first.");return;
        }
        if(!busy.compareAndSet(false,true))return;
        final ApkPatchWorkspace plan=patchWorkspace;
        final File original=sourceApk;
        final String path=selectedSourceEntry.archivePath;
        final String replacement=assetEditor.getText().toString();
        patchStage.setEnabled(false);
        status.setText("Validating staged text edit against source APK...");
        executor.execute(()->{
            String message;
            try{
                plan.stage(original,path,replacement);
                message="Text resource staged. Original APK unchanged.";
                if(patchStore!=null)patchStore.save(plan);
                else message+=" Checkpoint persistence unavailable.";
            }catch(IOException error){
                message="Patch rejected or not saved: "+error.getMessage();
            }
            final String outcome=message;
            busy.set(false);
            runOnUiThread(()->{
                if(isFinishing()||isDestroyed())return;
                patchStage.setEnabled(true);
                if(patchWorkspace==plan){
                    refreshPatchStatus();
                    status.setText(outcome);
                }
            });
        });
    }
    private void runBatchPatch(){
        if(patchWorkspace==null||sourceApk==null||!busy.compareAndSet(false,true))return;
        final ApkPatchWorkspace pending=patchWorkspace;
        final File input=sourceApk;
        final String find=patchFind.getText().toString();
        final String replace=patchReplacement.getText().toString();
        patchBatch.setEnabled(false);
        status.setText("Scanning eligible text assets for exact replacements…");
        executor.execute(()->{
            try{
                int updated=pending.replaceLiteral(input,find,replace);
                final String checkpointNotice=patchStore==null?
                    " Checkpoint persistence unavailable." : persistBatchCheckpoint(pending);
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed()||patchWorkspace!=pending)return;
                    refreshPatchStatus();
                    status.setText("Auto-staged "+updated+" eligible text assets."+checkpointNotice);
                });
            }catch(IOException error){
                runOnUiThread(()->{
                    if(!isFinishing()&&!isDestroyed())status.setText("Automation rejected: "+error.getMessage());
                });
            }finally{
                busy.set(false);
                runOnUiThread(()->{
                    if(!isFinishing()&&!isDestroyed())patchBatch.setEnabled(true);
                });
            }
        });
    }
    private String persistBatchCheckpoint(ApkPatchWorkspace plan){
        try{patchStore.save(plan);return " Patch queue saved privately.";}
        catch(IOException bad){return " WARNING: checkpoint failed: "+bad.getMessage();}
    }

    private void chooseUnsignedExport(){
        if(patchWorkspace==null||patchWorkspace.size()==0||busy.get())return;
        Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/vnd.android.package-archive");
        intent.putExtra(Intent.EXTRA_TITLE,"Vibe_Repacked_UNSIGNED_NOT_INSTALLABLE.apk");
        try{startActivityForResult(intent,EXPORT_UNSIGNED_APK);}
        catch(android.content.ActivityNotFoundException none){
            status.setText("No system document provider for unsigned APK export.");
        }
    }
    private void exportUnsigned(Uri destination){
        if(patchWorkspace==null||patchWorkspace.size()==0||sourceApk==null||
           !busy.compareAndSet(false,true))return;
        final File original=sourceApk;
        final ApkPatchWorkspace pending=patchWorkspace;
        patchExport.setEnabled(false);
        status.setText("Repacking unsigned APK with integrity checks…");
        executor.execute(()->{
            File scratch=null;
            try{
                scratch=new File(getCacheDir(),"vibe-unsigned-"+System.nanoTime()+".apk");
                ApkPatchWorkspace.Result built=pending.buildUnsigned(original,scratch);
                try(InputStream in=new java.io.FileInputStream(scratch);
                    OutputStream output=getContentResolver().openOutputStream(destination,"w")){
                    if(output==null)throw new IOException("Document provider refused output");
                    byte[] buf=new byte[32768];int n;
                    while((n=in.read(buf))!=-1){
                        if(Thread.currentThread().isInterrupted())throw new IOException("APK export cancelled");
                        output.write(buf,0,n);
                    }
                    output.flush();
                }
                String verification;
                try(InputStream check=getContentResolver().openInputStream(destination)){
                    if(check==null)throw new IOException("Document provider returned no readable output");
                    java.security.MessageDigest digest=java.security.MessageDigest.getInstance("SHA-256");
                    byte[] part=new byte[32768];
                    long count=0;
                    int n;
                    while((n=check.read(part))!=-1){
                        if(Thread.currentThread().isInterrupted())throw new IOException("Export verification cancelled");
                        count+=n;
                        if(count>256L*1024*1024)throw new IOException("Provider output exceeds size limit");
                        digest.update(part,0,n);
                    }
                    StringBuilder actual=new StringBuilder();
                    for(byte b:digest.digest())
                        actual.append(String.format(Locale.ROOT,"%02x",b&255));
                    if(count!=built.outputBytes ||
                       !actual.toString().equals(built.outputSha256))
                        throw new IOException("Exported APK checksum mismatch. Delete the damaged file.");
                    verification="Provider read-back SHA-256 VERIFIED.";
                }catch(java.io.FileNotFoundException|SecurityException unavailable){
                    verification="WARNING: Provider read-back unavailable; verify exported file independently.";
                }
                final String result="UNSIGNED APK exported. SHA-256: "+
                    built.outputSha256+" · changed assets: "+built.changedFiles+
                    ". "+verification+" Alignment and private-key signing required.";
                runOnUiThread(()->{
                    if(!isFinishing()&&!isDestroyed())status.setText(result);
                });
            }catch(Exception error){
                runOnUiThread(()->{
                    if(!isFinishing()&&!isDestroyed())
                        status.setText("Unsigned export failed: "+error.getMessage());
                });
            }finally{
                if(scratch!=null&&scratch.exists())scratch.delete();
                busy.set(false);
                runOnUiThread(()->{
                    if(!isFinishing()&&!isDestroyed())refreshPatchStatus();
                });
            }
        });
    }

    private void refreshSourceResults() {
        if(sourceSearch==null||sourceCounter==null||sourceList==null)return;
        sourceMatches.clear();
        if(sourceIndex!=null) {
            String query=sourceSearch.getText().toString().trim().toLowerCase(Locale.ROOT);
            for(ApkSourceExplorer.Entry e:sourceIndex.entries)
                if(e.title.toLowerCase(Locale.ROOT).contains(query))
                    sourceMatches.add(e);
            sourceCounter.setText(sourceMatches.size()+" matching source entries · "+
                sourceIndex.totalDexClasses+" DEX classes · "+
                sourceIndex.dexFiles+" DEX files"+
                (sourceIndex.truncated?" · INDEX LIMITED":""));
        }else sourceCounter.setText("No APK source index available");
        showSourceResults();
    }

    private void showSourceResults() {
        if(sourceList==null||sourcePrevious==null||sourceNext==null)return;
        sourceList.removeAllViews();
        int total=sourceMatches.size();
        int pages=Math.max(1,(total+SOURCE_PAGE_SIZE-1)/SOURCE_PAGE_SIZE);
        sourcePage=Math.min(Math.max(0,sourcePage),pages-1);
        int from=sourcePage*SOURCE_PAGE_SIZE;
        int end=Math.min(total,from+SOURCE_PAGE_SIZE);
        for(int i=from;i<end;i++){
            ApkSourceExplorer.Entry entry=sourceMatches.get(i);
            Button view=button(entry.title);
            view.setTextSize(12);
            view.setContentDescription("Open APK "+entry.kind+" "+entry.title);
            margin(view,sourceList,0,3);
            view.setOnClickListener(v->openSourceEntry(entry));
        }
        if(total==0)margin(text("No matching files or classes",13,MUTED,false),sourceList,4,8);
        sourcePageLabel.setText("Page "+(sourcePage+1)+" / "+pages);
        sourcePrevious.setEnabled(sourcePage>0);
        sourceNext.setEnabled(sourcePage+1<pages);
        if(sourceExportPage!=null)sourceExportPage.setEnabled(total>0 && sourceApk!=null);
    }

    private void openSourceEntry(ApkSourceExplorer.Entry entry){
        if(sourceApk==null || entry==null)return;
        final File file=sourceApk;
        selectedSourceEntry=entry;
        sourceText.setText("Reading "+entry.title+"…");
        localDraft=null;
        draftActions.setVisibility(View.GONE);
        diffPreview.setVisibility(View.GONE);
        editCopy.setEnabled(false);
        assetEditor.setVisibility(View.GONE);
        applyCopy.setVisibility(View.GONE);
        sourceExport.setEnabled(false);
        sourceLinks.removeAllViews();
        final int viewMode=sourceModePicker.getSelectedItemPosition();
        executor.execute(()->{
            try{
                String output=ApkSourceExplorer.open(file,entry,viewMode);
                List<String> targets="class".equals(entry.kind)?
                    ApkSourceExplorer.callTargets(file,entry):java.util.Collections.emptyList();
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed()||sourceApk!=file)return;
                    selectedSourceText=output;
                    selectedSourceName=entry.classDescriptor!=null?
                        entry.classDescriptor.substring(1,entry.classDescriptor.length()-1).replace('/','_')+".smali":
                        entry.archivePath.replace('/','_')+".txt";
                    renderSourcePreview(output);
                    sourceExport.setEnabled(true);
                    boolean textAsset="file".equals(entry.kind) &&
                        ApkSourceExplorer.isText(entry.archivePath) &&
                        output.length()<=65536 && !output.contains("Binary or unsupported asset");
                    editCopy.setEnabled(textAsset);
                    showSourceLinks(targets);
                    status.setText("Viewing source: "+entry.title);
                });
            }catch(Exception error){
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed()||sourceApk!=file)return;
                    sourceText.setText("Unable to display source: "+error.getMessage());
                });
            }
        });
    }

    private void renderSourcePreview(String value) {
        if(sourceText==null)return;
        if(value.length()>ApkSourceExplorer.MAX_TEXT+4096){
            sourceText.setText(value.substring(0,ApkSourceExplorer.MAX_TEXT));
            return;
        }
        SpannableString colored=new SpannableString(value);
        Matcher lines=Pattern.compile("(?m)^(?:\\.class|\\.super|\\.method|\\.end|\\.field|\\.registers|METHOD|method |#).*?$")
            .matcher(value);
        int count=0;
        while(lines.find()&&count++<1200)
            colored.setSpan(new ForegroundColorSpan(ACCENT),lines.start(),lines.end(),
                            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        String query=previewFind==null?"":previewFind.getText().toString().trim();
        if(!query.isEmpty()&&query.length()<=120){
            String lower=value.toLowerCase(Locale.ROOT);
            String needle=query.toLowerCase(Locale.ROOT);
            int pos=0,highlighted=0;
            while((pos=lower.indexOf(needle,pos))>=0&&highlighted++<300){
                colored.setSpan(new ForegroundColorSpan(Color.rgb(255,196,83)),
                    pos,pos+needle.length(),Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                pos+=Math.max(1,needle.length());
            }
        }
        sourceText.setText(colored);
    }

    private void showSourceLinks(List<String> targetMethods) {
        sourceLinks.removeAllViews();
        if(targetMethods==null||targetMethods.isEmpty()||sourceIndex==null)return;
        margin(text("Referenced classes (explicit invoke sites)",14,ACCENT,true),
               sourceLinks,10,5);
        java.util.HashSet<String> owners=new java.util.HashSet<>();
        int shown=0;
        for(String target:targetMethods){
            int arrow=target.indexOf("->");
            if(arrow<1)continue;
            String owner=target.substring(0,arrow);
            if(!owners.add(owner))continue;
            ApkSourceExplorer.Entry match=null;
            for(ApkSourceExplorer.Entry candidate:sourceIndex.entries){
                if("class".equals(candidate.kind)&&owner.equals(candidate.classDescriptor)){
                    match=candidate;break;
                }
            }
            if(match==null)continue;
            final ApkSourceExplorer.Entry go=match;
            Button ref=button("Open "+target);
            ref.setTextSize(12);
            ref.setContentDescription("Navigate to referenced class "+owner);
            margin(ref,sourceLinks,0,4);
            ref.setOnClickListener(v->{
                sourceSearch.setText(owner);
                openSourceEntry(go);
            });
            if(++shown>=16)break;
        }
    }

    private void startPageExport(){
        if(sourceApk==null||sourceMatches.isEmpty()||busy.get())return;
        int start=sourcePage*SOURCE_PAGE_SIZE;
        int end=Math.min(sourceMatches.size(),start+SOURCE_PAGE_SIZE);
        pendingSourceExports=new ArrayList<>(sourceMatches.subList(start,end));
        Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/zip");
        intent.putExtra(Intent.EXTRA_TITLE,"Vibe_Source_Page_"+(sourcePage+1)+".zip");
        try{startActivityForResult(intent,EXPORT_PAGE);}
        catch(android.content.ActivityNotFoundException unavailable){
            status.setText("No Android document provider for ZIP export");
        }
    }

    private void exportPage(Uri destination){
        if(sourceApk==null||pendingSourceExports.isEmpty())return;
        if(!busy.compareAndSet(false,true))return;
        final File file=sourceApk;
        final List<ApkSourceExplorer.Entry> chosen=new ArrayList<>(pendingSourceExports);
        final int mode=sourceModePicker.getSelectedItemPosition();
        executor.execute(()->{
            try{
                byte[] contents=SourceBundleExporter.create(file,chosen,mode);
                try(OutputStream stream=getContentResolver().openOutputStream(destination,"w")){
                    if(stream==null)throw new IOException("Document provider denied ZIP export");
                    stream.write(contents);
                    stream.flush();
                }
                runOnUiThread(()->{
                    if(!isFinishing()&&!isDestroyed())
                        status.setText("Exported "+chosen.size()+" source previews as ZIP.");
                });
            }catch(Exception error){
                runOnUiThread(()->{
                    if(!isFinishing()&&!isDestroyed())
                        status.setText("ZIP export rejected: "+error.getMessage());
                });
            }finally{busy.set(false);}
        });
    }

    private void startSourceExport(){
        if(selectedSourceText==null)return;
        Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_TITLE,selectedSourceName);
        try{startActivityForResult(intent,EXPORT_SOURCE);}
        catch(android.content.ActivityNotFoundException error){
            status.setText("No document provider available for source export");
        }
    }
    private void exportSource(Uri uri){
        if(selectedSourceText==null)return;
        final String text=selectedSourceText;
        executor.execute(()->{
            try(OutputStream stream=getContentResolver().openOutputStream(uri,"w")){
                if(stream==null)throw new IOException("Document provider rejected source export");
                byte[] bytes=text.getBytes(StandardCharsets.UTF_8);
                if(bytes.length>ApkSourceExplorer.MAX_TEXT+4096)
                    throw new IOException("Source preview exceeds export limit");
                stream.write(bytes);
                stream.flush();
                runOnUiThread(()->{
                    if(!isFinishing()&&!isDestroyed())status.setText("Selected source exported");
                });
            }catch(Exception error){
                runOnUiThread(()->{
                    if(!isFinishing()&&!isDestroyed())
                        status.setText("Source export refused: "+error.getMessage());
                });
            }
        });
    }

    private void exportReport() {
        if(report==null)return;
        Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/json");
        intent.putExtra(Intent.EXTRA_TITLE,"Vibe_Hermes_Report_"+
            report.sha256.substring(0,10)+".json");
        try{
            startActivityForResult(intent,EXPORT_REPORT);
        }catch(android.content.ActivityNotFoundException missing){
            status.setText("No document export provider installed.");
        }
    }

    private void writeExport(Uri destination) {
        if(report==null)return;
        final ApkInspector.Report selected=report;
        final String name=lastFilename;
        executor.execute(()->{
            try(OutputStream out=getContentResolver().openOutputStream(destination,"w")){
                if(out==null)throw new IOException("Document provider refused export");
                byte[] encoded=ReportExporter.toJson(selected,name).getBytes(StandardCharsets.UTF_8);
                if(encoded.length>4*1024*1024)
                    throw new IOException("Export exceeds 4 MiB");
                out.write(encoded);
                out.flush();
                runOnUiThread(()->{
                    if(!isFinishing()&&!isDestroyed())status.setText("Report saved as JSON");
                });
            }catch(Exception failure){
                runOnUiThread(()->{
                    if(!isFinishing()&&!isDestroyed())
                        status.setText("Export failed: "+failure.getMessage());
                });
            }
        });
    }

    private String displayName(Uri uri) {
        String name = "selected APK";
        try (Cursor cursor = getContentResolver().query(uri,
                new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                String item = cursor.getString(0);
                if (item != null && !item.isEmpty()) name = item;
            }
        } catch (Exception ignored) {
            // Use a neutral label if the provider cannot supply metadata.
        }
        return name.length() > 90 ? name.substring(0, 90) : name;
    }

    private void copyBounded(Uri uri, File scratch) throws IOException {
        try (InputStream from = getContentResolver().openInputStream(uri);
             FileOutputStream to = new FileOutputStream(scratch)) {
            if (from == null) throw new IOException("Document provider returned no data");
            byte[] buffer = new byte[65536];
            long total = 0L;
            int n;
            while ((n = from.read(buffer)) >= 0) {
                if (Thread.currentThread().isInterrupted()) throw new IOException("Copy cancelled");
                if (n == 0) continue;
                total += n;
                if (total > ApkInspector.MAX_APK_BYTES)
                    throw new IOException("APK exceeds 96 MiB mobile limit");
                to.write(buffer, 0, n);
            }
            if (total < 22) throw new IOException("APK is empty or truncated");
        }
    }

    private void updateResults() {
        if(search==null||searchCaption==null||modePicker==null)return;
        filtered.clear();
        if(report!=null){
            List<String> source;
            switch(modePicker.getSelectedItemPosition()){
                case 0:source=report.dexStrings;break;
                case 1:source=report.dexClasses;break;
                case 2:source=report.dexMethods;break;
                case 3:source=report.hermesStrings;break;
                case 4:source=report.hermesFunctions;break;
                case 5:source=report.hermesInstructions;break;
                case 6:source=report.hermesReferences;break;
                default:source=report.candidates;
            }
            String query=search.getText().toString().trim().toLowerCase(Locale.ROOT);
            for(String value:source)
                if(value.toLowerCase(Locale.ROOT).contains(query))
                    filtered.add(value);
        }
        searchCaption.setText(filtered.size()+" matching records");
        showPage();
    }

    private void showPage() {
        if (resultList == null || pageLabel == null) return;
        resultList.removeAllViews();
        int pages = SearchPager.pageCount(filtered.size());
        page = SearchPager.clamp(page, filtered.size());
        int end = SearchPager.end(page, filtered.size());
        for (int index = SearchPager.start(page, filtered.size()); index < end; index++) {
            TextView row = text((index + 1) + ".  " + filtered.get(index), 14, TEXT, false);
            row.setPadding(dp(5), dp(10), dp(5), dp(10));
            margin(row, resultList, 0, 1);
        }
        if (filtered.isEmpty())
            margin(text("No matching candidates", 13, MUTED, false), resultList, 0, 5);
        pageLabel.setText("Page " + (page + 1) + " / " + pages);
        previous.setEnabled(page > 0);
        next.setEnabled(page + 1 < pages);
    }

    @Override
    public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        View rootView = getWindow().getDecorView();
        rootView.requestApplyInsets();
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        if(sourceApk!=null){sourceApk.delete();sourceApk=null;}
        super.onDestroy();
    }
}
