package com.vibe.hermesinspector;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** Deterministic, bounded JSON export of analysis evidence (never APK bytes). */
public final class ReportExporter {
    private ReportExporter() {}

    private static JSONArray entries(java.util.List<String> list,int limit) {
        JSONArray array=new JSONArray();
        for(int i=0;i<list.size()&&i<limit;i++)array.put(list.get(i));
        return array;
    }
    public static String toJson(ApkInspector.Report report,String filename)throws JSONException{
        if(report==null)throw new IllegalArgumentException("No inspection report");
        JSONObject root=new JSONObject();
        root.put("format","vibe-hermes-offline-report-v2");
        root.put("file_name",filename==null?"Unknown":filename);
        root.put("sha256",report.sha256);
        root.put("bytes",report.byteSize);
        root.put("zip_members",report.entries);
        root.put("technologies",entries(report.technologies,12));
        root.put("hermes_bundle_count",report.hermesBundles);
        root.put("hermes_declared_functions",report.functionCount);
        root.put("dex_files_indexed",report.dexParsed);
        root.put("dex_declared_classes",report.dexDeclaredClasses);
        root.put("dex_declared_methods",report.dexDeclaredMethods);
        root.put("dex_declared_strings",report.dexDeclaredStrings);
        root.put("hermes_decoded_instructions",report.hermesDecodedInstructions);
        root.put("hbc_bundle_details",entries(report.bundleDetails,50));
        root.put("dex_classes",entries(report.dexClasses,3000));
        root.put("dex_method_references",entries(report.dexMethods,4000));
        root.put("dex_strings",entries(report.dexStrings,6000));
        root.put("hermes_strings",entries(report.hermesStrings,6000));
        root.put("hermes_functions",entries(report.hermesFunctions,3000));
        root.put("hermes_instructions",entries(report.hermesInstructions,6000));
        root.put("hermes_string_references",entries(report.hermesReferences,3000));
        root.put("printable_candidates",entries(report.candidates,2000));
        root.put("warnings",entries(report.warnings,100));
        root.put("classification_note","DEX methods are method-id references, not proven executable functions. HBC opcodes are bytecode, not JavaScript source.");
        root.put("provenance", "offline bytecode metadata only; imported APK never executed");
        root.put("analysis_limits", "bounded DEX/HBC indexing; omitted records are not verified");
        String encoded=root.toString(2);
        if(encoded.length()>4*1024*1024)
            throw new IllegalArgumentException("Export exceeds 4 MiB safe limit");
        return encoded;
    }
}
