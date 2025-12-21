package com.apk.analyzer.soot;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import soot.G;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
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

        configureSoot(apkPath, androidPlatforms, cgAlgo);

        Scene.v().loadNecessaryClasses();
        PackManager.v().runPacks();

        File out = new File(outDir);
        if (!out.exists()) {
            out.mkdirs();
        }

        writeCallGraph(new File(out, "callgraph.json"));
        writeCfgs(new File(out, "cfg"), new File(out, "method_index.json"));
    }

    private static void configureSoot(String apkPath, String androidPlatforms, String cgAlgo) {
        G.reset();
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_android_jars(androidPlatforms);
        Options.v().set_process_dir(Collections.singletonList(apkPath));
        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_process_multiple_dex(true);
        Options.v().set_output_format(Options.output_format_none);

        if ("CHA".equalsIgnoreCase(cgAlgo)) {
            Options.v().setPhaseOption("cg.cha", "on");
        } else {
            Options.v().setPhaseOption("cg.spark", "on");
        }
    }

    private static void writeCallGraph(File outputFile) throws Exception {
        CallGraph cg = Scene.v().getCallGraph();
        Set<String> methodSet = new HashSet<>();
        List<Map<String, Object>> edges = new ArrayList<>();

        for (Iterator<Edge> it = cg.iterator(); it.hasNext(); ) {
            Edge edge = it.next();
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
            edges.add(edgeObj);
        }

        List<Map<String, Object>> nodes = new ArrayList<>();
        for (String sig : methodSet) {
            SootMethod method = Scene.v().getMethod(sig);
            SootClass declaring = method.getDeclaringClass();
            Map<String, Object> node = new HashMap<>();
            node.put("method", sig);
            node.put("class", declaring.getName());
            node.put("is_android_framework", declaring.isLibraryClass());
            nodes.add(node);
        }

        Map<String, Object> payload = new HashMap<>();
        payload.put("nodes", nodes);
        payload.put("edges", edges);
        payload.put("metadata", Collections.singletonMap("generated_at", Instant.now().toString()));

        writeJson(outputFile, payload);
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
