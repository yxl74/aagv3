package com.apk.analyzer.soot;

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.callbacks.AbstractCallbackAnalyzer;
import soot.jimple.infoflow.android.callbacks.AndroidCallbackDefinition;
import soot.jimple.infoflow.android.callbacks.DefaultCallbackAnalyzer;
import soot.jimple.infoflow.android.callbacks.FastCallbackAnalyzer;
import soot.jimple.infoflow.android.manifest.IAndroidComponent;
import soot.jimple.infoflow.android.manifest.IComponentContainer;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.util.MultiMap;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class FlowDroidCallbackExtractor {
    private FlowDroidCallbackExtractor() {
        // Utility class
    }

    public static final class CallbackInfo {
        public final String method;
        public final String type;
        public final String component;
        public final String registrationSite;

        public CallbackInfo(String method, String type, String component, String registrationSite) {
            this.method = method;
            this.type = type;
            this.component = component;
            this.registrationSite = registrationSite;
        }
    }

    public static final class Result {
        public final List<CallbackInfo> callbacks;
        public final List<SootMethod> callbackMethods;

        public Result(List<CallbackInfo> callbacks, List<SootMethod> callbackMethods) {
            this.callbacks = callbacks;
            this.callbackMethods = callbackMethods;
        }
    }

    public static final class Prepared {
        public final AbstractCallbackAnalyzer analyzer;

        public Prepared(AbstractCallbackAnalyzer analyzer) {
            this.analyzer = analyzer;
        }
    }

    public static Prepared prepareCallbackAnalyzer(
            String apkPath,
            int maxCallbacksPerComponent,
            int callbackTimeoutSec,
            String analyzerMode
    ) throws Exception {
        ProcessManifest manifest = new ProcessManifest(apkPath);
        Set<SootClass> entryPointClasses = collectEntryPointClasses(manifest);
        if (entryPointClasses.isEmpty()) {
            return null;
        }

        InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
        config.getCallbackConfig().setEnableCallbacks(true);
        config.getCallbackConfig().setMaxCallbacksPerComponent(maxCallbacksPerComponent);
        config.getCallbackConfig().setCallbackAnalysisTimeout(callbackTimeoutSec);
        InfoflowAndroidConfiguration.CallbackAnalyzer analyzerType = parseAnalyzerMode(analyzerMode);
        config.getCallbackConfig().setCallbackAnalyzer(analyzerType);

        AbstractCallbackAnalyzer analyzer;
        if (analyzerType == InfoflowAndroidConfiguration.CallbackAnalyzer.Fast) {
            analyzer = new FastCallbackAnalyzer(config, entryPointClasses);
        } else {
            analyzer = new DefaultCallbackAnalyzer(config, entryPointClasses);
        }

        // Registers FlowDroid's callback transform, executed during PackManager.v().runPacks().
        analyzer.collectCallbackMethods();
        return new Prepared(analyzer);
    }

    public static Result readCallbacks(Prepared prepared) {
        if (prepared == null || prepared.analyzer == null) {
            return new Result(Collections.emptyList(), Collections.emptyList());
        }
        MultiMap<SootClass, AndroidCallbackDefinition> cbMap = prepared.analyzer.getCallbackMethods();
        List<CallbackInfo> callbacks = new ArrayList<>();
        Set<SootMethod> callbackMethods = new LinkedHashSet<>();

        for (SootClass component : cbMap.keySet()) {
            for (AndroidCallbackDefinition def : cbMap.get(component)) {
                if (def == null || def.getTargetMethod() == null) {
                    continue;
                }
                SootMethod target = def.getTargetMethod();
                callbackMethods.add(target);
                String parentSig = def.getParentMethod() != null ? def.getParentMethod().getSignature() : null;
                callbacks.add(new CallbackInfo(
                        target.getSignature(),
                        def.getCallbackType() != null ? def.getCallbackType().name() : "UNKNOWN",
                        component != null ? component.getName() : null,
                        parentSig
                ));
            }
        }

        callbacks.sort((a, b) -> {
            int cmp = safe(a.component).compareTo(safe(b.component));
            if (cmp != 0) {
                return cmp;
            }
            cmp = safe(a.method).compareTo(safe(b.method));
            if (cmp != 0) {
                return cmp;
            }
            return safe(a.type).compareTo(safe(b.type));
        });

        return new Result(callbacks, new ArrayList<>(callbackMethods));
    }

    private static Set<SootClass> collectEntryPointClasses(ProcessManifest manifest) {
        Set<SootClass> entryPointClasses = new LinkedHashSet<>();
        addComponents(entryPointClasses, manifest, manifest.getActivities());
        addComponents(entryPointClasses, manifest, manifest.getServices());
        addComponents(entryPointClasses, manifest, manifest.getBroadcastReceivers());
        addComponents(entryPointClasses, manifest, manifest.getContentProviders());
        return entryPointClasses;
    }

    private static void addComponents(
            Set<SootClass> out,
            ProcessManifest manifest,
            IComponentContainer<? extends IAndroidComponent> components
    ) {
        if (components == null || components.isEmpty()) {
            return;
        }
        for (IAndroidComponent component : components.asList()) {
            if (component == null) {
                continue;
            }
            String rawName = component.getNameString();
            if (rawName == null || rawName.isEmpty()) {
                continue;
            }
            String normalized = manifest.expandClassName(rawName);
            SootClass cls = Scene.v().getSootClassUnsafe(normalized);
            if (cls != null) {
                out.add(cls);
            }
        }
    }

    private static InfoflowAndroidConfiguration.CallbackAnalyzer parseAnalyzerMode(String mode) {
        if (mode == null) {
            return InfoflowAndroidConfiguration.CallbackAnalyzer.Default;
        }
        String normalized = mode.trim().toLowerCase(Locale.ROOT);
        if ("fast".equals(normalized)) {
            return InfoflowAndroidConfiguration.CallbackAnalyzer.Fast;
        }
        return InfoflowAndroidConfiguration.CallbackAnalyzer.Default;
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
