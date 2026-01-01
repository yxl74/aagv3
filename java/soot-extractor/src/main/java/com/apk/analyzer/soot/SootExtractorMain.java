package com.apk.analyzer.soot;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import soot.FastHierarchy;
import soot.G;
import soot.Local;
import soot.PackManager;
import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.CastExpr;
import soot.jimple.DefinitionStmt;
import soot.jimple.FieldRef;
import soot.jimple.InstanceFieldRef;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.NewExpr;
import soot.jimple.SpecialInvokeExpr;
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
        boolean flowdroidCallbacksEnabled = parseBool(params.get("--flowdroid-callbacks"), true);
        if (parseBool(params.get("--no-flowdroid-callbacks"), false)) {
            flowdroidCallbacksEnabled = false;
        }
        int callbacksMaxPerComponent = parseInt(params.get("--flowdroid-callbacks-max-per-component"), 500);
        int callbacksTimeoutSec = parseInt(params.get("--flowdroid-callbacks-timeout"), 120);
        String callbacksMode = params.getOrDefault("--flowdroid-callbacks-mode", "default");

        AndroidJarSelection jarSelection = configureSoot(apkPath, androidPlatforms, cgAlgo, targetSdkRaw, explicitJar);

        Scene.v().loadNecessaryClasses();
        // Entrypoints are strict: manifest-startable component lifecycle methods only.
        // Callbacks (FlowDroid) are connected via synthetic edges, not treated as roots.
        List<SootMethod> entryPoints = buildEntryPoints();
        FlowDroidCallbackExtractor.Prepared callbackPrepared = null;
        if (flowdroidCallbacksEnabled) {
            try {
                callbackPrepared = FlowDroidCallbackExtractor.prepareCallbackAnalyzer(
                        apkPath,
                        callbacksMaxPerComponent,
                        callbacksTimeoutSec,
                        callbacksMode
                );
            } catch (Exception e) {
                System.err.println("FlowDroid callback preparation failed, using lifecycle entrypoints only: " + e);
            }
        }
        Scene.v().setEntryPoints(entryPoints);
        PackManager.v().runPacks();

        FlowDroidCallbackExtractor.Result callbackResult = null;
        if (flowdroidCallbacksEnabled && callbackPrepared != null) {
            try {
                callbackResult = FlowDroidCallbackExtractor.readCallbacks(callbackPrepared);
            } catch (Exception e) {
                System.err.println("FlowDroid callback read failed, using lifecycle entrypoints only: " + e);
            }
        }

        File out = new File(outDir);
        if (!out.exists()) {
            out.mkdirs();
        }

        writeCallGraph(
                new File(out, "callgraph.json"),
                entryPoints,
                callbackResult != null ? callbackResult.callbacks : Collections.emptyList(),
                flowdroidCallbacksEnabled,
                apkPath,
                androidPlatforms,
                cgAlgo,
                jarSelection
        );
        writeEntrypoints(new File(out, "entrypoints.json"), entryPoints);
        if (flowdroidCallbacksEnabled) {
            writeCallbacks(new File(out, "callbacks.json"),
                    callbackResult != null ? callbackResult.callbacks : Collections.emptyList());
        }
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
            List<FlowDroidCallbackExtractor.CallbackInfo> callbacks,
            boolean flowdroidCallbacksEnabled,
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
        int callbackEdges = appendCallbackEdges(edges, edgeKeys, methodSet, callbacks, entryPoints);
        int threadingEdges = appendThreadingEdges(edges, edgeKeys, methodSet);
        int listenerEdges = appendListenerRegistrationEdges(edges, edgeKeys, methodSet);

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
        metadata.put("callback_count", callbacks.size());
        metadata.put("flowdroid_callbacks_enabled", flowdroidCallbacksEnabled);
        metadata.put("cg_edge_count", cgEdges);
        metadata.put("jimple_edge_count", jimpleEdges);
        metadata.put("callback_edge_count", callbackEdges);
        metadata.put("threading_edge_count", threadingEdges);
        metadata.put("listener_edge_count", listenerEdges);
        metadata.put("synthetic_edge_count", callbackEdges + threadingEdges + listenerEdges);
        metadata.put("edge_total", edges.size());
        List<String> entrypointSources = new ArrayList<>();
        entrypointSources.add("lifecycle");
        if (flowdroidCallbacksEnabled) {
            entrypointSources.add("flowdroid_callbacks");
        }
        metadata.put("entrypoint_sources", entrypointSources);
        List<String> entrypointSamples = new ArrayList<>();
        for (int i = 0; i < Math.min(entryPoints.size(), 50); i++) {
            entrypointSamples.add(entryPoints.get(i).getSignature());
        }
        metadata.put("entrypoints", entrypointSamples);
        payload.put("metadata", metadata);
        payload.put("callbacks", callbacks);

        writeJson(outputFile, payload);
    }

    private static int appendCallbackEdges(
            List<Map<String, Object>> edges,
            Set<String> edgeKeys,
            Set<String> methodSet,
            List<FlowDroidCallbackExtractor.CallbackInfo> callbacks,
            List<SootMethod> entryPoints
    ) {
        if (callbacks == null || callbacks.isEmpty()) {
            return 0;
        }
        Map<String, List<String>> entrypointsByComponent = new HashMap<>();
        if (entryPoints != null) {
            for (SootMethod ep : entryPoints) {
                if (ep == null) {
                    continue;
                }
                String cls = ep.getDeclaringClass() != null ? ep.getDeclaringClass().getName() : null;
                if (cls == null || cls.isEmpty()) {
                    continue;
                }
                entrypointsByComponent.computeIfAbsent(cls, k -> new ArrayList<>()).add(ep.getSignature());
            }
        }

        int added = 0;
        for (FlowDroidCallbackExtractor.CallbackInfo cb : callbacks) {
            if (cb == null || cb.method == null || cb.method.isEmpty()) {
                continue;
            }
            String callee = cb.method;
            String registration = cb.registrationSite;
            if (registration != null && !registration.isEmpty()) {
                added += addSyntheticEdge(
                        edges,
                        edgeKeys,
                        methodSet,
                        registration,
                        callee,
                        "flowdroid_callback",
                        "callback_registration",
                        "medium",
                        "FLOWDROID_CALLBACK registrationSite=" + registration
                );
                continue;
            }
            String component = cb.component;
            if (component == null || component.isEmpty()) {
                continue;
            }
            List<String> componentEntrypoints = entrypointsByComponent.get(component);
            if (componentEntrypoints == null || componentEntrypoints.isEmpty()) {
                continue;
            }
            for (String ep : componentEntrypoints) {
                added += addSyntheticEdge(
                        edges,
                        edgeKeys,
                        methodSet,
                        ep,
                        callee,
                        "flowdroid_callback",
                        "callback_orphan",
                        "low",
                        "FLOWDROID_CALLBACK orphan component=" + component
                );
            }
        }
        return added;
    }

    private static int appendListenerRegistrationEdges(
            List<Map<String, Object>> edges,
            Set<String> edgeKeys,
            Set<String> methodSet
    ) {
        FastHierarchy hierarchy = Scene.v().getOrMakeFastHierarchy();

        SootClass onClickListener = Scene.v().getSootClassUnsafe("android.view.View$OnClickListener");
        SootClass primaryClipListener = Scene.v().getSootClassUnsafe("android.content.ClipboardManager$OnPrimaryClipChangedListener");
        SootClass imageAvailableListener = Scene.v().getSootClassUnsafe("android.media.ImageReader$OnImageAvailableListener");
        SootClass broadcastReceiver = Scene.v().getSootClassUnsafe("android.content.BroadcastReceiver");

        if (onClickListener == null && primaryClipListener == null && imageAvailableListener == null && broadcastReceiver == null) {
            return 0;
        }

        int added = 0;
        List<SootClass> classes = new ArrayList<>(Scene.v().getApplicationClasses());
        for (SootClass cls : classes) {
            for (SootMethod method : new ArrayList<>(cls.getMethods())) {
                if (method == null || !method.isConcrete()) {
                    continue;
                }
                try {
                    Map<Local, Value> localDefs = new HashMap<>();
                    for (Unit unit : method.retrieveActiveBody().getUnits()) {
                        if (unit instanceof DefinitionStmt) {
                            DefinitionStmt def = (DefinitionStmt) unit;
                            if (def.getLeftOp() instanceof Local) {
                                localDefs.put((Local) def.getLeftOp(), def.getRightOp());
                            }
                        }
                        if (!(unit instanceof Stmt)) {
                            continue;
                        }
                        Stmt stmt = (Stmt) unit;
                        if (!stmt.containsInvokeExpr()) {
                            continue;
                        }
                        InvokeExpr invoke = stmt.getInvokeExpr();
                        ListenerRegistration reg = matchListenerRegistration(invoke, onClickListener, primaryClipListener, imageAvailableListener, broadcastReceiver);
                        if (reg == null) {
                            continue;
                        }
                        if (invoke.getArgCount() <= reg.listenerArgIndex) {
                            continue;
                        }
                        Value listenerArg = invoke.getArg(reg.listenerArgIndex);
                        if (listenerArg == null) {
                            continue;
                        }
                        ListenerTargets targets = resolveListenerTargets(
                                listenerArg,
                                localDefs,
                                hierarchy,
                                reg.listenerBaseClass,
                                reg.callbackSubSignatures,
                                method.getDeclaringClass().getName(),
                                packageName(method.getDeclaringClass().getName()),
                                MAX_FALLBACK_RUNNABLE_TARGETS
                        );
                        if (targets.targets.isEmpty()) {
                            continue;
                        }
                        String caller = method.getSignature();
                        String callsite = stmt.toString();
                        for (SootMethod cb : targets.targets) {
                            added += addSyntheticEdge(
                                    edges,
                                    edgeKeys,
                                    methodSet,
                                    caller,
                                    cb.getSignature(),
                                    "listener_registration_synthetic",
                                    reg.pattern,
                                    targets.confidence,
                                    callsite
                            );
                        }
                    }
                } catch (Exception ignored) {
                    // best effort
                }
            }
        }
        return added;
    }

    private static final class ListenerRegistration {
        private final String pattern;
        private final SootClass listenerBaseClass;
        private final List<String> callbackSubSignatures;
        private final int listenerArgIndex;

        private ListenerRegistration(String pattern, SootClass listenerBaseClass, List<String> callbackSubSignatures, int listenerArgIndex) {
            this.pattern = pattern;
            this.listenerBaseClass = listenerBaseClass;
            this.callbackSubSignatures = callbackSubSignatures;
            this.listenerArgIndex = listenerArgIndex;
        }
    }

    private static final class ListenerTargets {
        private final List<SootMethod> targets;
        private final String confidence;

        private ListenerTargets(List<SootMethod> targets, String confidence) {
            this.targets = targets;
            this.confidence = confidence;
        }
    }

    private static ListenerRegistration matchListenerRegistration(
            InvokeExpr invoke,
            SootClass onClickListener,
            SootClass primaryClipListener,
            SootClass imageAvailableListener,
            SootClass broadcastReceiver
    ) {
        if (invoke == null || invoke.getMethod() == null) {
            return null;
        }
        SootMethod invoked = invoke.getMethod();
        String name = invoked.getName();

        // android.view.View.setOnClickListener(View$OnClickListener)
        if ("setOnClickListener".equals(name)
                && onClickListener != null
                && invoked.getParameterCount() == 1
                && invoked.getParameterType(0) instanceof RefType
                && onClickListener.getName().equals(((RefType) invoked.getParameterType(0)).getClassName())) {
            return new ListenerRegistration(
                    "setOnClickListener",
                    onClickListener,
                    Collections.singletonList("void onClick(android.view.View)"),
                    0
            );
        }

        // android.content.ClipboardManager.addPrimaryClipChangedListener(OnPrimaryClipChangedListener)
        if ("addPrimaryClipChangedListener".equals(name)
                && primaryClipListener != null
                && invoked.getParameterCount() == 1
                && invoked.getParameterType(0) instanceof RefType
                && primaryClipListener.getName().equals(((RefType) invoked.getParameterType(0)).getClassName())) {
            return new ListenerRegistration(
                    "addPrimaryClipChangedListener",
                    primaryClipListener,
                    Collections.singletonList("void onPrimaryClipChanged()"),
                    0
            );
        }

        // android.media.ImageReader.setOnImageAvailableListener(OnImageAvailableListener, Handler)
        if ("setOnImageAvailableListener".equals(name)
                && imageAvailableListener != null
                && invoked.getParameterCount() >= 1
                && invoked.getParameterType(0) instanceof RefType
                && imageAvailableListener.getName().equals(((RefType) invoked.getParameterType(0)).getClassName())) {
            return new ListenerRegistration(
                    "setOnImageAvailableListener",
                    imageAvailableListener,
                    Collections.singletonList("void onImageAvailable(android.media.ImageReader)"),
                    0
            );
        }

        // android.content.Context.registerReceiver(BroadcastReceiver, ...)
        if ("registerReceiver".equals(name)
                && broadcastReceiver != null
                && invoked.getParameterCount() >= 1
                && invoked.getParameterType(0) instanceof RefType
                && broadcastReceiver.getName().equals(((RefType) invoked.getParameterType(0)).getClassName())) {
            return new ListenerRegistration(
                    "registerReceiver",
                    broadcastReceiver,
                    Collections.singletonList("void onReceive(android.content.Context,android.content.Intent)"),
                    0
            );
        }

        return null;
    }

    private static ListenerTargets resolveListenerTargets(
            Value listenerValue,
            Map<Local, Value> localDefs,
            FastHierarchy hierarchy,
            SootClass listenerBaseClass,
            List<String> callbackSubSignatures,
            String callerClassName,
            String callerPackage,
            int maxFallbackTargets
    ) {
        if (listenerValue == null || listenerBaseClass == null || callbackSubSignatures == null || callbackSubSignatures.isEmpty()) {
            return new ListenerTargets(Collections.emptyList(), "low");
        }
        List<SootMethod> targets = new ArrayList<>();

        Value resolved = resolveValue(listenerValue, localDefs, 6);
        if (resolved instanceof NewExpr) {
            SootClass cls = sootClassFromType(((NewExpr) resolved).getType());
            if (cls != null && hierarchy.canStoreClass(cls, listenerBaseClass)) {
                for (String subSig : callbackSubSignatures) {
                    SootMethod m = lookupMethodInHierarchy(cls, subSig);
                    if (m != null && m.isConcrete() && m.getDeclaringClass().isApplicationClass()) {
                        targets.add(m);
                    }
                }
                if (!targets.isEmpty()) {
                    return new ListenerTargets(targets, "high");
                }
            }
        }

        Type t = resolved != null ? resolved.getType() : null;
        if (t instanceof RefType) {
            SootClass cls = sootClassFromType(t);
            if (cls != null && cls.isApplicationClass() && hierarchy.canStoreClass(cls, listenerBaseClass)) {
                for (String subSig : callbackSubSignatures) {
                    SootMethod m = lookupMethodInHierarchy(cls, subSig);
                    if (m != null && m.isConcrete() && m.getDeclaringClass().isApplicationClass()) {
                        targets.add(m);
                    }
                }
                if (!targets.isEmpty()) {
                    return new ListenerTargets(targets, "medium");
                }
            }
        }

        // Fuzzy fallback (bounded): prefer inner classes of the caller class, then same-package implementors.
        if (maxFallbackTargets <= 0) {
            return new ListenerTargets(Collections.emptyList(), "low");
        }

        String callerPrefix = callerClassName != null ? (callerClassName + "$") : null;
        List<SootClass> appClasses = new ArrayList<>(Scene.v().getApplicationClasses());

        for (SootClass cls : appClasses) {
            if (targets.size() >= maxFallbackTargets) {
                break;
            }
            if (cls == null || cls.isPhantom() || !cls.isApplicationClass()) {
                continue;
            }
            if (callerPrefix != null && !callerPrefix.isEmpty() && !cls.getName().startsWith(callerPrefix)) {
                continue;
            }
            if (!hierarchy.canStoreClass(cls, listenerBaseClass)) {
                continue;
            }
            for (String subSig : callbackSubSignatures) {
                SootMethod m = lookupMethodInHierarchy(cls, subSig);
                if (m != null && m.isConcrete() && m.getDeclaringClass().isApplicationClass()) {
                    targets.add(m);
                }
            }
        }

        if (targets.isEmpty() && callerPackage != null && !callerPackage.isEmpty()) {
            for (SootClass cls : appClasses) {
                if (targets.size() >= maxFallbackTargets) {
                    break;
                }
                if (cls == null || cls.isPhantom() || !cls.isApplicationClass()) {
                    continue;
                }
                if (!callerPackage.equals(packageName(cls.getName()))) {
                    continue;
                }
                if (!hierarchy.canStoreClass(cls, listenerBaseClass)) {
                    continue;
                }
                for (String subSig : callbackSubSignatures) {
                    SootMethod m = lookupMethodInHierarchy(cls, subSig);
                    if (m != null && m.isConcrete() && m.getDeclaringClass().isApplicationClass()) {
                        targets.add(m);
                    }
                }
            }
        }

        if (targets.isEmpty()) {
            return new ListenerTargets(Collections.emptyList(), "low");
        }
        return new ListenerTargets(targets, "low");
    }

    private static int addSyntheticEdge(
            List<Map<String, Object>> edges,
            Set<String> edgeKeys,
            Set<String> methodSet,
            String caller,
            String callee,
            String edgeSource,
            String pattern,
            String confidence,
            String callsiteUnit
    ) {
        if (caller == null || caller.isEmpty() || callee == null || callee.isEmpty()) {
            return 0;
        }
        Map<String, Object> edgeObj = new HashMap<>();
        edgeObj.put("caller", caller);
        edgeObj.put("callee", callee);
        edgeObj.put("callsite", Collections.singletonMap("unit", callsiteUnit));
        edgeObj.put("edge_source", edgeSource);
        edgeObj.put("edge_layer", "synthetic");
        edgeObj.put("pattern", pattern);
        edgeObj.put("confidence", confidence);
        String key = edgeKey(edgeObj);
        if (edgeKeys.add(key)) {
            edges.add(edgeObj);
            methodSet.add(caller);
            methodSet.add(callee);
            return 1;
        }
        return 0;
    }

    private static final int MAX_FALLBACK_RUNNABLE_TARGETS = 20;

    private static int appendThreadingEdges(
            List<Map<String, Object>> edges,
            Set<String> edgeKeys,
            Set<String> methodSet
    ) {
        FastHierarchy hierarchy = Scene.v().getOrMakeFastHierarchy();
        SootClass threadClass = Scene.v().getSootClassUnsafe("java.lang.Thread");
        SootClass runnableClass = Scene.v().getSootClassUnsafe("java.lang.Runnable");
        if (threadClass == null || runnableClass == null) {
            return 0;
        }

        int added = 0;
        List<SootClass> classes = new ArrayList<>(Scene.v().getApplicationClasses());
        for (SootClass cls : classes) {
            List<SootMethod> methods = new ArrayList<>(cls.getMethods());
            for (SootMethod method : methods) {
                if (method == null || !method.isConcrete()) {
                    continue;
                }
                try {
                    Map<Local, Value> localDefs = new HashMap<>();
                    Map<Local, Value> threadRunnableArgs = new HashMap<>();

                    for (Unit unit : method.retrieveActiveBody().getUnits()) {
                        if (unit instanceof DefinitionStmt) {
                            DefinitionStmt def = (DefinitionStmt) unit;
                            if (def.getLeftOp() instanceof Local) {
                                localDefs.put((Local) def.getLeftOp(), def.getRightOp());
                            }
                        }
                        if (!(unit instanceof Stmt)) {
                            continue;
                        }
                        Stmt stmt = (Stmt) unit;
                        if (!stmt.containsInvokeExpr()) {
                            continue;
                        }
                        InvokeExpr invoke = stmt.getInvokeExpr();

                        // Capture "new Thread(runnable)" and "new ThreadSubclass(runnable)" constructor args
                        captureThreadConstructorRunnableArg(invoke, threadRunnableArgs, hierarchy, threadClass, runnableClass);

                        if (isThreadStartInvoke(invoke, hierarchy, threadClass)) {
                            InstanceInvokeExpr iie = (InstanceInvokeExpr) invoke;
                            Value base = iie.getBase();
                            if (!(base instanceof Local)) {
                                continue;
                            }
                            Local threadLocal = (Local) base;
                            Value resolvedThreadValue = resolveValue(threadLocal, localDefs, 6);
                            ThreadResolution resolution = resolveThreadInstance(
                                    resolvedThreadValue,
                                    threadLocal,
                                    localDefs,
                                    hierarchy,
                                    threadClass
                            );

                            String caller = method.getSignature();
                            String callsite = stmt.toString();

                            boolean hasAppRun = false;
                            if (resolution.threadClass != null) {
                                SootMethod runMethod = lookupMethodInHierarchy(resolution.threadClass, "void run()");
                                if (runMethod != null
                                        && runMethod.isConcrete()
                                        && runMethod.getDeclaringClass() != null
                                        && runMethod.getDeclaringClass().isApplicationClass()) {
                                    hasAppRun = true;
                                    added += addSyntheticEdge(
                                            edges,
                                            edgeKeys,
                                            methodSet,
                                            caller,
                                            runMethod.getSignature(),
                                            "threading_synthetic",
                                            "thread_start",
                                            resolution.confidence,
                                            callsite
                                    );
                                }
                            }

                            Value runnableArg = findThreadRunnableArg(threadLocal, localDefs, threadRunnableArgs);
                            // Only synthesize a direct caller -> runnable.run edge when the Thread does not have an
                            // app-defined run() implementation. For Thread subclasses, prefer the (caller -> run())
                            // edge and let the call graph connect run() -> runnable.run().
                            boolean wantsRunnableEdge = runnableArg != null && !hasAppRun;
                            if (wantsRunnableEdge) {
                                RunnableTargets targets = resolveRunnableTargets(
                                        runnableArg,
                                        localDefs,
                                        hierarchy,
                                        runnableClass,
                                        method.getDeclaringClass().getName(),
                                        packageName(method.getDeclaringClass().getName()),
                                        MAX_FALLBACK_RUNNABLE_TARGETS
                                );
                                String pattern = "thread_runnable";
                                for (SootMethod targetRun : targets.targets) {
                                    added += addSyntheticEdge(
                                            edges,
                                            edgeKeys,
                                            methodSet,
                                            caller,
                                            targetRun.getSignature(),
                                            "threading_synthetic",
                                            pattern,
                                            targets.confidence,
                                            callsite
                                    );
                                }
                            }
                        }

                        if (isHandlerPostInvoke(invoke)) {
                            String caller = method.getSignature();
                            String callsite = stmt.toString();
                            Value runnableArg = invoke.getArgCount() > 0 ? invoke.getArg(0) : null;
                            if (runnableArg == null) {
                                continue;
                            }
                            RunnableTargets targets = resolveRunnableTargets(
                                    runnableArg,
                                    localDefs,
                                    hierarchy,
                                    runnableClass,
                                    method.getDeclaringClass().getName(),
                                    packageName(method.getDeclaringClass().getName()),
                                    MAX_FALLBACK_RUNNABLE_TARGETS
                            );
                            for (SootMethod targetRun : targets.targets) {
                                added += addSyntheticEdge(
                                        edges,
                                        edgeKeys,
                                        methodSet,
                                        caller,
                                        targetRun.getSignature(),
                                        "threading_synthetic",
                                        "handler_post",
                                        targets.confidence,
                                        callsite
                                );
                            }
                        }

                        if (isHandlerSendMessageInvoke(invoke)) {
                            String caller = method.getSignature();
                            String callsite = stmt.toString();
                            Value msgArg = invoke.getArgCount() > 0 ? invoke.getArg(0) : null;
                            if (msgArg == null) {
                                continue;
                            }
                            Value resolvedMsg = resolveValue(msgArg, localDefs, 6);
                            Value callbackRunnable = extractRunnableFromMessageObtain(resolvedMsg);
                            if (callbackRunnable == null) {
                                continue;
                            }
                            RunnableTargets targets = resolveRunnableTargets(
                                    callbackRunnable,
                                    localDefs,
                                    hierarchy,
                                    runnableClass,
                                    method.getDeclaringClass().getName(),
                                    packageName(method.getDeclaringClass().getName()),
                                    MAX_FALLBACK_RUNNABLE_TARGETS
                            );
                            for (SootMethod targetRun : targets.targets) {
                                added += addSyntheticEdge(
                                        edges,
                                        edgeKeys,
                                        methodSet,
                                        caller,
                                        targetRun.getSignature(),
                                        "threading_synthetic",
                                        "handler_message",
                                        targets.confidence,
                                        callsite
                                );
                            }
                        }

                        if (isExecutorExecuteInvoke(invoke)) {
                            String caller = method.getSignature();
                            String callsite = stmt.toString();
                            Value runnableArg = invoke.getArgCount() > 0 ? invoke.getArg(0) : null;
                            if (runnableArg == null) {
                                continue;
                            }
                            RunnableTargets targets = resolveRunnableTargets(
                                    runnableArg,
                                    localDefs,
                                    hierarchy,
                                    runnableClass,
                                    method.getDeclaringClass().getName(),
                                    packageName(method.getDeclaringClass().getName()),
                                    MAX_FALLBACK_RUNNABLE_TARGETS
                            );
                            for (SootMethod targetRun : targets.targets) {
                                added += addSyntheticEdge(
                                        edges,
                                        edgeKeys,
                                        methodSet,
                                        caller,
                                        targetRun.getSignature(),
                                        "threading_synthetic",
                                        "executor_execute",
                                        targets.confidence,
                                        callsite
                                );
                            }
                        }
                    }
                } catch (Exception ignored) {
                    // best effort; skip methods without bodies or with soot failures
                }
            }
        }
        return added;
    }

    private static boolean isThreadStartInvoke(InvokeExpr invoke, FastHierarchy hierarchy, SootClass threadClass) {
        if (!(invoke instanceof InstanceInvokeExpr)) {
            return false;
        }
        SootMethod invoked = invoke.getMethod();
        if (invoked == null) {
            return false;
        }
        if (!"start".equals(invoked.getName())) {
            return false;
        }
        if (invoked.getParameterCount() != 0) {
            return false;
        }
        if (!"void start()".equals(invoked.getSubSignature())) {
            return false;
        }
        SootClass declaring = invoked.getDeclaringClass();
        if (declaring != null && "java.lang.Thread".equals(declaring.getName())) {
            return true;
        }
        Value base = ((InstanceInvokeExpr) invoke).getBase();
        if (base == null) {
            return false;
        }
        Type type = base.getType();
        if (!(type instanceof RefType)) {
            return false;
        }
        SootClass baseClass;
        try {
            baseClass = ((RefType) type).getSootClass();
        } catch (Exception e) {
            baseClass = Scene.v().getSootClassUnsafe(((RefType) type).getClassName());
        }
        return baseClass != null && hierarchy.canStoreClass(baseClass, threadClass);
    }

    private static boolean isHandlerPostInvoke(InvokeExpr invoke) {
        SootMethod invoked = invoke.getMethod();
        if (invoked == null) {
            return false;
        }
        if (!"android.os.Handler".equals(invoked.getDeclaringClass().getName())) {
            return false;
        }
        String name = invoked.getName();
        if (!name.startsWith("post")) {
            return false;
        }
        return invoked.getParameterCount() >= 1
                && invoked.getParameterType(0) instanceof RefType
                && "java.lang.Runnable".equals(((RefType) invoked.getParameterType(0)).getClassName());
    }

    private static boolean isHandlerSendMessageInvoke(InvokeExpr invoke) {
        SootMethod invoked = invoke.getMethod();
        if (invoked == null) {
            return false;
        }
        if (!"android.os.Handler".equals(invoked.getDeclaringClass().getName())) {
            return false;
        }
        String name = invoked.getName();
        if (name == null || !name.startsWith("sendMessage")) {
            return false;
        }
        if (invoked.getParameterCount() < 1) {
            return false;
        }
        Type first = invoked.getParameterType(0);
        return first instanceof RefType
                && "android.os.Message".equals(((RefType) first).getClassName());
    }

    private static Value extractRunnableFromMessageObtain(Value messageValue) {
        if (!(messageValue instanceof InvokeExpr)) {
            return null;
        }
        InvokeExpr invoke = (InvokeExpr) messageValue;
        SootMethod invoked = invoke.getMethod();
        if (invoked == null) {
            return null;
        }
        if (!"obtain".equals(invoked.getName())) {
            return null;
        }
        if (!"android.os.Message".equals(invoked.getDeclaringClass().getName())) {
            return null;
        }
        int argCount = Math.min(invoke.getArgCount(), invoked.getParameterCount());
        for (int i = 0; i < argCount; i++) {
            Type paramType = invoked.getParameterType(i);
            if (!(paramType instanceof RefType)) {
                continue;
            }
            if (!"java.lang.Runnable".equals(((RefType) paramType).getClassName())) {
                continue;
            }
            return invoke.getArg(i);
        }
        return null;
    }

    private static boolean isExecutorExecuteInvoke(InvokeExpr invoke) {
        SootMethod invoked = invoke.getMethod();
        if (invoked == null) {
            return false;
        }
        String name = invoked.getName();
        if (!"execute".equals(name) && !"submit".equals(name)) {
            return false;
        }
        return invoked.getParameterCount() >= 1
                && invoked.getParameterType(0) instanceof RefType
                && "java.lang.Runnable".equals(((RefType) invoked.getParameterType(0)).getClassName());
    }

    private static void captureThreadConstructorRunnableArg(
            InvokeExpr invoke,
            Map<Local, Value> threadRunnableArgs,
            FastHierarchy hierarchy,
            SootClass threadClass,
            SootClass runnableClass
    ) {
        if (!(invoke instanceof SpecialInvokeExpr)) {
            return;
        }
        SpecialInvokeExpr sie = (SpecialInvokeExpr) invoke;
        SootMethod invoked = sie.getMethod();
        if (invoked == null || !"<init>".equals(invoked.getName())) {
            return;
        }
        Value base = sie.getBase();
        if (!(base instanceof Local)) {
            return;
        }
        Local threadLocal = (Local) base;

        // Only record for Thread instances (or subclasses).
        Type threadType = threadLocal.getType();
        if (!(threadType instanceof RefType)) {
            return;
        }
        SootClass threadLocalClass;
        try {
            threadLocalClass = ((RefType) threadType).getSootClass();
        } catch (Exception e) {
            threadLocalClass = Scene.v().getSootClassUnsafe(((RefType) threadType).getClassName());
        }
        if (threadLocalClass == null || !hierarchy.canStoreClass(threadLocalClass, threadClass)) {
            return;
        }

        for (int i = 0; i < sie.getArgCount(); i++) {
            Value arg = sie.getArg(i);
            if (arg == null) {
                continue;
            }
            Type argType = arg.getType();
            if (!(argType instanceof RefType)) {
                continue;
            }
            SootClass argClass;
            try {
                argClass = ((RefType) argType).getSootClass();
            } catch (Exception e) {
                argClass = Scene.v().getSootClassUnsafe(((RefType) argType).getClassName());
            }
            if (argClass != null && hierarchy.canStoreClass(argClass, runnableClass)) {
                threadRunnableArgs.put(threadLocal, arg);
                return;
            }
        }
    }

    private static Value findThreadRunnableArg(
            Local threadLocal,
            Map<Local, Value> localDefs,
            Map<Local, Value> threadRunnableArgs
    ) {
        if (threadRunnableArgs.containsKey(threadLocal)) {
            return threadRunnableArgs.get(threadLocal);
        }
        // Follow simple aliases: t2 = t1; t2.start()
        Value def = localDefs.get(threadLocal);
        if (def instanceof Local) {
            return threadRunnableArgs.get(def);
        }
        return null;
    }

    private static Value resolveValue(Value value, Map<Local, Value> localDefs, int maxDepth) {
        Value current = value;
        int depth = 0;
        while (depth < maxDepth) {
            depth += 1;
            if (current instanceof CastExpr) {
                current = ((CastExpr) current).getOp();
                continue;
            }
            if (current instanceof Local) {
                Value next = localDefs.get(current);
                if (next == null || next == current) {
                    return current;
                }
                current = next;
                continue;
            }
            return current;
        }
        return current;
    }

    private static ThreadResolution resolveThreadInstance(
            Value resolvedThreadValue,
            Local threadLocal,
            Map<Local, Value> localDefs,
            FastHierarchy hierarchy,
            SootClass threadClass
    ) {
        // Default: use declared type.
        SootClass typeClass = null;
        Type t = threadLocal.getType();
        if (t instanceof RefType) {
            try {
                typeClass = ((RefType) t).getSootClass();
            } catch (Exception e) {
                typeClass = Scene.v().getSootClassUnsafe(((RefType) t).getClassName());
            }
        }
        ThreadResolution out = new ThreadResolution(typeClass, "low");

        if (resolvedThreadValue instanceof NewExpr) {
            Type newType = ((NewExpr) resolvedThreadValue).getType();
            if (newType instanceof RefType) {
                SootClass allocated = ((RefType) newType).getSootClass();
                if (allocated != null && hierarchy.canStoreClass(allocated, threadClass)) {
                    return new ThreadResolution(allocated, "high");
                }
            }
            return out;
        }

        if (resolvedThreadValue instanceof FieldRef) {
            FieldRef fr = (FieldRef) resolvedThreadValue;
            SootField field = fr.getField();
            if (field != null) {
                ThreadResolution fieldRes = resolveThreadFromField(field, hierarchy, threadClass);
                if (fieldRes != null) {
                    return fieldRes;
                }
            }
        }
        return out;
    }

    private static ThreadResolution resolveThreadFromField(
            SootField field,
            FastHierarchy hierarchy,
            SootClass threadClass
    ) {
        if (field == null) {
            return null;
        }
        SootClass declaring = field.getDeclaringClass();
        if (declaring == null) {
            return null;
        }
        List<String> initializerNames = Arrays.asList("<init>", "onCreate", "onStartCommand", "onReceive");
        for (SootMethod m : declaring.getMethods()) {
            if (m == null || !m.isConcrete()) {
                continue;
            }
            if (!initializerNames.contains(m.getName())) {
                continue;
            }
            try {
                Map<Local, Value> localDefs = new HashMap<>();
                for (Unit u : m.retrieveActiveBody().getUnits()) {
                    if (u instanceof DefinitionStmt) {
                        DefinitionStmt def = (DefinitionStmt) u;
                        if (def.getLeftOp() instanceof Local) {
                            localDefs.put((Local) def.getLeftOp(), def.getRightOp());
                        }
                    }
                    if (u instanceof AssignStmt) {
                        AssignStmt as = (AssignStmt) u;
                        Value left = as.getLeftOp();
                        if (!(left instanceof InstanceFieldRef)) {
                            continue;
                        }
                        InstanceFieldRef ifr = (InstanceFieldRef) left;
                        if (ifr.getField() == null || !ifr.getField().equals(field)) {
                            continue;
                        }
                        Value rhs = as.getRightOp();
                        Value resolved = resolveValue(rhs, localDefs, 6);
                        if (resolved instanceof NewExpr) {
                            Type newType = ((NewExpr) resolved).getType();
                            if (newType instanceof RefType) {
                                SootClass allocated = ((RefType) newType).getSootClass();
                                if (allocated != null && hierarchy.canStoreClass(allocated, threadClass)) {
                                    return new ThreadResolution(allocated, "medium");
                                }
                            }
                        }
                    }
                }
            } catch (Exception ignored) {
                // best effort
            }
        }
        return null;
    }

    private static SootMethod lookupMethodInHierarchy(SootClass cls, String subSignature) {
        if (cls == null || subSignature == null) {
            return null;
        }
        SootClass current = cls;
        int depth = 0;
        while (current != null && depth < 25) {
            depth += 1;
            SootMethod m = current.getMethodUnsafe(subSignature);
            if (m != null) {
                return m;
            }
            try {
                if (!current.hasSuperclass()) {
                    break;
                }
                current = current.getSuperclass();
            } catch (Exception e) {
                break;
            }
        }
        return null;
    }

    private static RunnableTargets resolveRunnableTargets(
            Value runnableValue,
            Map<Local, Value> localDefs,
            FastHierarchy hierarchy,
            SootClass runnableClass,
            String callerClassName,
            String callerPackage,
            int maxFallbackTargets
    ) {
        List<SootMethod> targets = new ArrayList<>();

        Value resolved = resolveValue(runnableValue, localDefs, 6);
        if (resolved instanceof NewExpr) {
            SootClass cls = sootClassFromType(((NewExpr) resolved).getType());
            SootMethod run = (cls != null) ? lookupMethodInHierarchy(cls, "void run()") : null;
            if (run != null && run.isConcrete() && run.getDeclaringClass().isApplicationClass()) {
                targets.add(run);
                return new RunnableTargets(targets, "high");
            }
        }

        Type t = resolved != null ? resolved.getType() : null;
        if (t instanceof RefType) {
            SootClass cls;
            try {
                cls = ((RefType) t).getSootClass();
            } catch (Exception e) {
                cls = Scene.v().getSootClassUnsafe(((RefType) t).getClassName());
            }
            if (cls != null && cls.isApplicationClass()) {
                SootMethod run = lookupMethodInHierarchy(cls, "void run()");
                if (run != null && run.isConcrete() && run.getDeclaringClass().isApplicationClass()) {
                    targets.add(run);
                    return new RunnableTargets(targets, "medium");
                }
            }
        }

        // Fuzzy fallback (bounded): prefer inner classes of the caller, then same-package implementors.
        if (maxFallbackTargets > 0) {
            String callerPrefix = callerClassName != null ? (callerClassName + "$") : null;
            List<SootClass> appClasses = new ArrayList<>(Scene.v().getApplicationClasses());

            if (callerPrefix != null && !callerPrefix.isEmpty()) {
                for (SootClass cls : appClasses) {
                    if (targets.size() >= maxFallbackTargets) {
                        break;
                    }
                    if (cls == null || cls.isPhantom()) {
                        continue;
                    }
                    if (!cls.getName().startsWith(callerPrefix)) {
                        continue;
                    }
                    if (!hierarchy.canStoreClass(cls, runnableClass)) {
                        continue;
                    }
                    SootMethod run = lookupMethodInHierarchy(cls, "void run()");
                    if (run != null && run.isConcrete() && run.getDeclaringClass().isApplicationClass()) {
                        targets.add(run);
                    }
                }
            }

            if (targets.isEmpty() && callerPackage != null && !callerPackage.isEmpty()) {
                for (SootClass cls : appClasses) {
                    if (targets.size() >= maxFallbackTargets) {
                        break;
                    }
                    if (cls == null || cls.isPhantom()) {
                        continue;
                    }
                    if (!callerPackage.equals(packageName(cls.getName()))) {
                        continue;
                    }
                    if (!hierarchy.canStoreClass(cls, runnableClass)) {
                        continue;
                    }
                    SootMethod run = lookupMethodInHierarchy(cls, "void run()");
                    if (run != null && run.isConcrete() && run.getDeclaringClass().isApplicationClass()) {
                        targets.add(run);
                    }
                }
            }
        }
        return new RunnableTargets(targets, targets.isEmpty() ? "low" : "low");
    }

    private static SootClass sootClassFromType(Type type) {
        if (!(type instanceof RefType)) {
            return null;
        }
        try {
            return ((RefType) type).getSootClass();
        } catch (Exception e) {
            return Scene.v().getSootClassUnsafe(((RefType) type).getClassName());
        }
    }

    private static String packageName(String className) {
        if (className == null) {
            return "";
        }
        int idx = className.lastIndexOf('.');
        return idx >= 0 ? className.substring(0, idx) : "";
    }

    private static final class ThreadResolution {
        private final SootClass threadClass;
        private final String confidence;

        private ThreadResolution(SootClass threadClass, String confidence) {
            this.threadClass = threadClass;
            this.confidence = confidence;
        }
    }

    private static final class RunnableTargets {
        private final List<SootMethod> targets;
        private final String confidence;

        private RunnableTargets(List<SootMethod> targets, String confidence) {
            this.targets = targets;
            this.confidence = confidence;
        }
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

    private static void writeCallbacks(File outputFile, List<FlowDroidCallbackExtractor.CallbackInfo> callbacks)
            throws Exception {
        Map<String, Object> payload = new HashMap<>();
        payload.put("callbacks", callbacks);
        payload.put("count", callbacks.size());
        writeJson(outputFile, payload);
    }

    private static List<SootMethod> mergeEntryPoints(List<SootMethod> base, List<SootMethod> extra) {
        LinkedHashSet<SootMethod> merged = new LinkedHashSet<>(base);
        if (extra != null) {
            merged.addAll(extra);
        }
        return new ArrayList<>(merged);
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
        List<SootClass> classes = new ArrayList<>(Scene.v().getApplicationClasses());
        for (SootClass cls : classes) {
            List<SootMethod> methods = new ArrayList<>(cls.getMethods());
            for (SootMethod method : methods) {
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

    private static boolean parseBool(String raw, boolean defaultValue) {
        if (raw == null) {
            return defaultValue;
        }
        return "true".equalsIgnoreCase(raw) || "1".equals(raw);
    }

    private static int parseInt(String raw, int defaultValue) {
        if (raw == null || raw.isEmpty()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException ignored) {
            return defaultValue;
        }
    }

    private static String require(Map<String, String> params, String key) {
        String value = params.get(key);
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("Missing required argument: " + key);
        }
        return value;
    }
}
