package com.apk.analyzer.soot;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import soot.FastHierarchy;
import soot.G;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.Stmt;
import soot.options.Options;
import soot.toolkits.graph.ExceptionalUnitGraph;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

public class SootExtractorMain {
    public static void main(String[] args) throws Exception {
        Map<String, String> params = parseArgs(args);
        String apkPath = require(params, "--apk");
        String androidPlatforms = require(params, "--android-platforms");
        String outDir = require(params, "--out");
        String cgAlgo = params.getOrDefault("--cg-algo", "SPARK");
        String targetSdkRaw = params.get("--target-sdk");
        String explicitJar = params.get("--android-jar");

        AndroidJarSelection jarSelection = configureSoot(apkPath, androidPlatforms, cgAlgo, targetSdkRaw, explicitJar);

        Scene.v().loadNecessaryClasses();
        List<SootMethod> entryPoints = buildEntryPoints();
        Scene.v().setEntryPoints(entryPoints);
        PackManager.v().runPacks();

        File out = new File(outDir);
        if (!out.exists()) {
            out.mkdirs();
        }

        writeCallGraph(
                new File(out, "callgraph.json"),
                entryPoints,
                apkPath,
                androidPlatforms,
                cgAlgo,
                jarSelection
        );
        writeEntrypoints(new File(out, "entrypoints.json"), entryPoints);
        writeClassHierarchy(new File(out, "class_hierarchy.json"));
        writeCfgs(new File(out, "cfg"), new File(out, "method_index.json"));
    }

    private static AndroidJarSelection configureSoot(
            String apkPath,
            String androidPlatforms,
            String cgAlgo,
            String targetSdkRaw,
            String explicitJar
    ) {
        G.reset();
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_android_jars(androidPlatforms);
        Options.v().set_process_dir(Collections.singletonList(apkPath));
        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_process_multiple_dex(true);
        Options.v().set_output_format(Options.output_format_none);
        Options.v().set_prepend_classpath(true);

        if ("CHA".equalsIgnoreCase(cgAlgo)) {
            Options.v().setPhaseOption("cg.cha", "on");
        } else {
            Options.v().setPhaseOption("cg.spark", "on");
        }
        Integer targetSdk = parseSdk(targetSdkRaw);
        AndroidJarSelection selection = selectAndroidJar(androidPlatforms, targetSdk, explicitJar);
        if (selection.jarPath != null) {
            Options.v().set_force_android_jar(selection.jarPath);
        }
        return selection;
    }

    private static void writeCallGraph(
            File outputFile,
            List<SootMethod> entryPoints,
            String apkPath,
            String androidPlatforms,
            String cgAlgo,
            AndroidJarSelection jarSelection
    ) throws Exception {
        CallGraph cg = Scene.v().getCallGraph();
        Set<String> methodSet = new HashSet<>();
        List<Map<String, Object>> edges = new ArrayList<>();
        Set<String> edgeKeys = new HashSet<>();
        int cgEdges = 0;
        int jimpleEdges = 0;

        for (Iterator<Edge> it = cg.iterator(); it.hasNext(); ) {
            Edge edge = it.next();
            if (edge.getSrc() == null || edge.getTgt() == null) {
                continue;
            }
            if (edge.getSrc().method() == null || edge.getTgt().method() == null) {
                continue;
            }
            SootMethod src = edge.getSrc().method();
            SootMethod tgt = edge.getTgt().method();
            methodSet.add(src.getSignature());
            methodSet.add(tgt.getSignature());

            Map<String, Object> edgeObj = new HashMap<>();
            edgeObj.put("caller", src.getSignature());
            edgeObj.put("callee", tgt.getSignature());
            if (edge.srcUnit() != null) {
                edgeObj.put("callsite", Collections.singletonMap("unit", edge.srcUnit().toString()));
            }
            edgeObj.put("edge_source", "soot_cg");
            String key = edgeKey(edgeObj);
            if (edgeKeys.add(key)) {
                edges.add(edgeObj);
                cgEdges += 1;
            }
        }

        jimpleEdges = appendInvokeEdges(edges, edgeKeys, methodSet);

        List<Map<String, Object>> nodes = new ArrayList<>();
        for (String sig : methodSet) {
            SootMethod method = Scene.v().grabMethod(sig);
            String className = method != null ? method.getDeclaringClass().getName() : classFromSignature(sig);
            boolean isFramework = false;
            if (method != null) {
                isFramework = method.getDeclaringClass().isLibraryClass();
            }
            Map<String, Object> node = new HashMap<>();
            node.put("method", sig);
            node.put("class", className);
            node.put("is_android_framework", isFramework);
            nodes.add(node);
        }

        Map<String, Object> payload = new HashMap<>();
        payload.put("nodes", nodes);
        payload.put("edges", edges);
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("generated_at", Instant.now().toString());
        metadata.put("apk_path", apkPath);
        metadata.put("android_platforms", androidPlatforms);
        metadata.put("cg_algo", cgAlgo);
        metadata.put("forced_android_jar", jarSelection.jarPath);
        metadata.put("android_jar_reason", jarSelection.reason);
        metadata.put("android_jar_api", jarSelection.apiLevel);
        metadata.put("application_class_count", Scene.v().getApplicationClasses().size());
        metadata.put("entrypoint_count", entryPoints.size());
        metadata.put("cg_edge_count", cgEdges);
        metadata.put("jimple_edge_count", jimpleEdges);
        metadata.put("edge_total", edges.size());
        List<String> entrypointSamples = new ArrayList<>();
        for (int i = 0; i < Math.min(entryPoints.size(), 50); i++) {
            entrypointSamples.add(entryPoints.get(i).getSignature());
        }
        metadata.put("entrypoints", entrypointSamples);
        payload.put("metadata", metadata);

        writeJson(outputFile, payload);
    }

    private static List<SootMethod> buildEntryPoints() {
        Set<SootMethod> entryPoints = new LinkedHashSet<>();
        FastHierarchy hierarchy = Scene.v().getOrMakeFastHierarchy();
        Map<String, Set<String>> entrypointMethods = entrypointMethodMap();
        Map<String, SootClass> baseClasses = new HashMap<>();
        for (String base : entrypointMethods.keySet()) {
            if (Scene.v().containsClass(base)) {
                baseClasses.put(base, Scene.v().getSootClass(base));
            }
        }
        for (SootClass cls : Scene.v().getApplicationClasses()) {
            if (cls.isPhantom()) {
                continue;
            }
            for (Map.Entry<String, SootClass> baseEntry : baseClasses.entrySet()) {
                if (!hierarchy.canStoreClass(cls, baseEntry.getValue())) {
                    continue;
                }
                for (String methodName : entrypointMethods.get(baseEntry.getKey())) {
                    if (!cls.declaresMethodByName(methodName)) {
                        continue;
                    }
                    for (SootMethod method : cls.getMethods()) {
                        if (method == null || !method.isConcrete()) {
                            continue;
                        }
                        if (methodName.equals(method.getName())) {
                            entryPoints.add(method);
                        }
                    }
                }
            }
        }
        return new ArrayList<>(entryPoints);
    }

    private static Map<String, Set<String>> entrypointMethodMap() {
        Map<String, Set<String>> map = new LinkedHashMap<>();
        map.put("android.app.Activity", new LinkedHashSet<>(Arrays.asList(
                "onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy",
                "onNewIntent", "onActivityResult"
        )));
        map.put("android.app.Service", new LinkedHashSet<>(Arrays.asList(
                "onCreate", "onStartCommand", "onBind", "onHandleIntent", "onDestroy"
        )));
        map.put("android.app.IntentService", new LinkedHashSet<>(Collections.singletonList("onHandleIntent")));
        map.put("android.content.BroadcastReceiver", new LinkedHashSet<>(Collections.singletonList("onReceive")));
        map.put("android.content.ContentProvider", new LinkedHashSet<>(Arrays.asList(
                "onCreate", "query", "insert", "update", "delete", "call"
        )));
        map.put("android.app.Application", new LinkedHashSet<>(Collections.singletonList("onCreate")));
        map.put("android.accessibilityservice.AccessibilityService", new LinkedHashSet<>(Arrays.asList(
                "onAccessibilityEvent", "onInterrupt", "onServiceConnected"
        )));
        map.put("android.app.Fragment", new LinkedHashSet<>(Arrays.asList(
                "onAttach", "onCreate", "onCreateView", "onViewCreated", "onActivityCreated",
                "onStart", "onResume", "onPause", "onStop", "onDestroyView", "onDestroy", "onDetach"
        )));
        map.put("androidx.fragment.app.Fragment", new LinkedHashSet<>(Arrays.asList(
                "onAttach", "onCreate", "onCreateView", "onViewCreated", "onActivityCreated",
                "onStart", "onResume", "onPause", "onStop", "onDestroyView", "onDestroy", "onDetach"
        )));
        return map;
    }

    private static String classFromSignature(String signature) {
        if (signature.startsWith("<") && signature.contains(":")) {
            return signature.substring(1, signature.indexOf(":")).trim();
        }
        return signature;
    }

    private static Integer parseSdk(String raw) {
        if (raw == null || raw.isEmpty()) {
            return null;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static AndroidJarSelection selectAndroidJar(
            String androidPlatforms,
            Integer targetSdk,
            String explicitJar
    ) {
        if (explicitJar != null && !explicitJar.isEmpty()) {
            File jarFile = new File(explicitJar);
            if (jarFile.exists()) {
                return new AndroidJarSelection(jarFile.getAbsolutePath(), apiFromPath(jarFile), "explicit");
            }
        }
        File platformsDir = new File(androidPlatforms);
        if (!platformsDir.isDirectory()) {
            return new AndroidJarSelection(null, null, "missing_platforms_dir");
        }
        File[] dirs = platformsDir.listFiles(File::isDirectory);
        if (dirs == null || dirs.length == 0) {
            return new AndroidJarSelection(null, null, "no_platforms");
        }
        Map<Integer, File> apiToJar = new HashMap<>();
        for (File dir : dirs) {
            String name = dir.getName();
            if (!name.startsWith("android-")) {
                continue;
            }
            try {
                int api = Integer.parseInt(name.substring("android-".length()));
                File jar = new File(dir, "android.jar");
                if (jar.exists()) {
                    apiToJar.put(api, jar);
                }
            } catch (NumberFormatException ignored) {
                // skip
            }
        }
        if (apiToJar.isEmpty()) {
            return new AndroidJarSelection(null, null, "no_android_jars");
        }
        List<Integer> apis = new ArrayList<>(apiToJar.keySet());
        Collections.sort(apis);
        if (targetSdk != null) {
            for (Integer api : apis) {
                if (api >= targetSdk) {
                    String reason = api.equals(targetSdk) ? "target_exact" : "target_nearest_higher";
                    return new AndroidJarSelection(apiToJar.get(api).getAbsolutePath(), api, reason);
                }
            }
            Integer fallback = apis.get(apis.size() - 1);
            return new AndroidJarSelection(apiToJar.get(fallback).getAbsolutePath(), fallback, "fallback_latest");
        }
        Integer latest = apis.get(apis.size() - 1);
        return new AndroidJarSelection(apiToJar.get(latest).getAbsolutePath(), latest, "latest_available");
    }

    private static Integer apiFromPath(File jarFile) {
        if (jarFile == null) {
            return null;
        }
        File parent = jarFile.getParentFile();
        if (parent == null) {
            return null;
        }
        String name = parent.getName();
        if (!name.startsWith("android-")) {
            return null;
        }
        try {
            return Integer.parseInt(name.substring("android-".length()));
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static void writeClassHierarchy(File outputFile) throws Exception {
        Map<String, Object> classes = new LinkedHashMap<>();
        for (SootClass cls : Scene.v().getClasses()) {
            Map<String, Object> info = new HashMap<>();
            info.put("is_library", cls.isLibraryClass());
            info.put("is_phantom", cls.isPhantom());
            String superclass = null;
            try {
                if (cls.hasSuperclass()) {
                    superclass = cls.getSuperclass().getName();
                }
            } catch (Exception ignored) {
                // best effort
            }
            info.put("superclass", superclass);
            List<String> interfaces = new ArrayList<>();
            try {
                for (SootClass iface : cls.getInterfaces()) {
                    if (iface != null) {
                        interfaces.add(iface.getName());
                    }
                }
            } catch (Exception ignored) {
                // best effort
            }
            info.put("interfaces", interfaces);
            info.put("supertypes", new ArrayList<>(collectSupertypes(cls)));
            classes.put(cls.getName(), info);
        }
        Map<String, Object> payload = new HashMap<>();
        payload.put("classes", classes);
        writeJson(outputFile, payload);
    }

    private static Set<String> collectSupertypes(SootClass cls) {
        Set<String> supers = new LinkedHashSet<>();
        Deque<SootClass> stack = new ArrayDeque<>();
        stack.add(cls);
        while (!stack.isEmpty()) {
            SootClass current = stack.pop();
            try {
                if (current.hasSuperclass()) {
                    SootClass sup = current.getSuperclass();
                    if (sup != null && supers.add(sup.getName())) {
                        stack.add(sup);
                    }
                }
            } catch (Exception ignored) {
                // best effort
            }
            try {
                for (SootClass iface : current.getInterfaces()) {
                    if (iface != null && supers.add(iface.getName())) {
                        stack.add(iface);
                    }
                }
            } catch (Exception ignored) {
                // best effort
            }
        }
        return supers;
    }

    private static class AndroidJarSelection {
        private final String jarPath;
        private final Integer apiLevel;
        private final String reason;

        private AndroidJarSelection(String jarPath, Integer apiLevel, String reason) {
            this.jarPath = jarPath;
            this.apiLevel = apiLevel;
            this.reason = reason;
        }
    }

    private static void writeCfgs(File cfgDir, File methodIndexFile) throws Exception {
        if (!cfgDir.exists()) {
            cfgDir.mkdirs();
        }
        Map<String, String> methodIndex = new HashMap<>();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        for (SootClass cls : Scene.v().getApplicationClasses()) {
            for (SootMethod method : cls.getMethods()) {
                if (!method.isConcrete()) {
                    continue;
                }
                try {
                    ExceptionalUnitGraph graph = new ExceptionalUnitGraph(method.retrieveActiveBody());
                    Map<Unit, String> unitIds = new LinkedHashMap<>();
                    int idx = 0;
                    for (Unit unit : graph) {
                        unitIds.put(unit, "u" + idx++);
                    }
                    List<Map<String, Object>> units = new ArrayList<>();
                    List<Map<String, Object>> edges = new ArrayList<>();
                    for (Unit unit : graph) {
                        String id = unitIds.get(unit);
                        List<String> succs = new ArrayList<>();
                        for (Unit succ : graph.getSuccsOf(unit)) {
                            succs.add(unitIds.get(succ));
                            Map<String, Object> edge = new HashMap<>();
                            edge.put("from", id);
                            edge.put("to", unitIds.get(succ));
                            edges.add(edge);
                        }
                        Map<String, Object> unitObj = new HashMap<>();
                        unitObj.put("id", id);
                        unitObj.put("stmt", unit.toString());
                        unitObj.put("succs", succs);
                        units.add(unitObj);
                    }
                    Map<String, Object> cfg = new HashMap<>();
                    cfg.put("method", method.getSignature());
                    cfg.put("units", units);
                    cfg.put("edges", edges);

                    String hash = sha1(method.getSignature());
                    methodIndex.put(method.getSignature(), hash);
                    File cfgFile = new File(cfgDir, hash + ".json");
                    try (FileWriter writer = new FileWriter(cfgFile, StandardCharsets.UTF_8)) {
                        writer.write(gson.toJson(cfg));
                    }
                } catch (Exception ignored) {
                    // Skip methods without bodies
                }
            }
        }

        writeJson(methodIndexFile, methodIndex);
    }

    private static String sha1(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        byte[] bytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static void writeJson(File file, Object payload) throws Exception {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (FileWriter writer = new FileWriter(file, StandardCharsets.UTF_8)) {
            writer.write(gson.toJson(payload));
        }
    }

    private static void writeEntrypoints(File outputFile, List<SootMethod> entryPoints) throws Exception {
        List<String> entries = new ArrayList<>();
        for (SootMethod method : entryPoints) {
            entries.add(method.getSignature());
        }
        Map<String, Object> payload = new HashMap<>();
        payload.put("entrypoints", entries);
        payload.put("count", entries.size());
        writeJson(outputFile, payload);
    }

    private static String edgeKey(Map<String, Object> edgeObj) {
        String caller = String.valueOf(edgeObj.get("caller"));
        String callee = String.valueOf(edgeObj.get("callee"));
        String callsite = "";
        Object callsiteObj = edgeObj.get("callsite");
        if (callsiteObj instanceof Map) {
            Object unit = ((Map<?, ?>) callsiteObj).get("unit");
            if (unit != null) {
                callsite = unit.toString();
            }
        }
        return caller + "->" + callee + "|" + callsite;
    }

    private static int appendInvokeEdges(
            List<Map<String, Object>> edges,
            Set<String> edgeKeys,
            Set<String> methodSet
    ) {
        int added = 0;
        for (SootClass cls : Scene.v().getApplicationClasses()) {
            for (SootMethod method : cls.getMethods()) {
                if (!method.isConcrete()) {
                    continue;
                }
                try {
                    for (Unit unit : method.retrieveActiveBody().getUnits()) {
                        if (!(unit instanceof Stmt)) {
                            continue;
                        }
                        Stmt stmt = (Stmt) unit;
                        if (!stmt.containsInvokeExpr()) {
                            continue;
                        }
                        SootMethod target = stmt.getInvokeExpr().getMethod();
                        if (target == null) {
                            continue;
                        }
                        Map<String, Object> edgeObj = new HashMap<>();
                        edgeObj.put("caller", method.getSignature());
                        edgeObj.put("callee", target.getSignature());
                        edgeObj.put("callsite", Collections.singletonMap("unit", stmt.toString()));
                        edgeObj.put("edge_source", "jimple_invoke");
                        String key = edgeKey(edgeObj);
                        if (edgeKeys.add(key)) {
                            edges.add(edgeObj);
                            methodSet.add(method.getSignature());
                            methodSet.add(target.getSignature());
                            added += 1;
                        }
                    }
                } catch (Exception ignored) {
                    // Skip methods without bodies
                }
            }
        }
        return added;
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> params = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.startsWith("--")) {
                if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                    params.put(arg, args[i + 1]);
                    i++;
                } else {
                    params.put(arg, "true");
                }
            }
        }
        return params;
    }

    private static String require(Map<String, String> params, String key) {
        String value = params.get(key);
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("Missing required argument: " + key);
        }
        return value;
    }
}
