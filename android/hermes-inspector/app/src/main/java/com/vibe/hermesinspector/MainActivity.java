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
    private static final String[] MODES = {"DEX strings", "DEX classes", "DEX method references", "Hermes strings", "Hermes functions", "Hermes opcodes", "Hermes string references", "Printable candidates"};
    private static final int BACKGROUND = Color.rgb(13, 20, 32);
    private static final int SURFACE = Color.rgb(28, 40, 59);
    private static final int TEXT = Color.rgb(237, 246, 255);
    private static final int MUTED = Color.rgb(177, 195, 217);
    private static final int ACCENT = Color.rgb(89, 172, 246);
    private static final int PAGE_SIZE = 50;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final AtomicBoolean busy = new AtomicBoolean(false);
    private final List<String> filtered = new ArrayList<>();
    private ApkInspector.Report report;
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
        createView();
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
        margin(text("Read-only APK analysis", 26, TEXT, true), root, 0, 5);
        margin(text("Offline • On-device • No network permission • Android 9+", 13, MUTED, false),
                root, 0, 10);

        LinearLayout importCard = card("Import APK");
        choose = button("＋  Choose APK file");
        choose.setContentDescription("Choose an APK through the Android document picker");
        margin(choose, importCard, 0, 9);
        choose.setOnClickListener(v -> chooseApk());

        spinner = new ProgressBar(this);
        spinner.setIndeterminate(true);
        spinner.setVisibility(View.GONE);
        margin(spinner, importCard, 4, 4);
        status = text("Select a local APK to inspect.", 14, MUTED, false);
        status.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        margin(status, importCard, 0, 0);

        LinearLayout recentCard=card("Local APK library");
        margin(text("Saved document references only. No APK copies retained after analysis.",
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
            int count = Math.max(1, (filtered.size() + PAGE_SIZE - 1) / PAGE_SIZE);
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
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed())return;
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
        int pages = Math.max(1, (filtered.size() + PAGE_SIZE - 1) / PAGE_SIZE);
        page = Math.min(Math.max(page, 0), pages - 1);
        int end = Math.min(filtered.size(), (page + 1) * PAGE_SIZE);
        for (int index = page * PAGE_SIZE; index < end; index++) {
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
        super.onDestroy();
    }
}
