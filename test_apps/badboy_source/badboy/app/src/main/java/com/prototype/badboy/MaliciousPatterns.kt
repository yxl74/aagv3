package com.prototype.badboy

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.os.Debug
import dalvik.system.DexClassLoader
import dalvik.system.PathClassLoader
import java.io.File
import java.lang.reflect.Method

/**
 * This class contains patterns that trigger various threat detection indicators.
 * FOR SECURITY RESEARCH AND TESTING PURPOSES ONLY.
 */
@Suppress("unused", "UNUSED_VARIABLE", "UNUSED_PARAMETER")
object MaliciousPatterns {

    // =====================================================
    // EXECUTION - Multiple Runtime.exec and ProcessBuilder
    // =====================================================

    fun execCommand1(cmd: String): String {
        val process = Runtime.getRuntime().exec(cmd)
        return process.inputStream.bufferedReader().readText()
    }

    fun execCommand2(cmd: String): String {
        val runtime = Runtime.getRuntime()
        val p = runtime.exec(arrayOf("sh", "-c", cmd))
        return p.inputStream.bufferedReader().readText()
    }

    fun execCommand3(cmd: String): String {
        return Runtime.getRuntime().exec(cmd).inputStream.bufferedReader().readText()
    }

    fun execWithProcessBuilder(cmd: String): String {
        val pb = ProcessBuilder(cmd.split(" "))
        val process = pb.start()
        return process.inputStream.bufferedReader().readText()
    }

    fun execSu(): java.lang.Process = Runtime.getRuntime().exec("su")
    fun execId(): java.lang.Process = Runtime.getRuntime().exec("id")
    fun execPs(): java.lang.Process = Runtime.getRuntime().exec("ps")
    fun execLs(): java.lang.Process = Runtime.getRuntime().exec("ls")
    fun execCat(): java.lang.Process = Runtime.getRuntime().exec("cat /etc/passwd")
    fun execMount(): java.lang.Process = Runtime.getRuntime().exec("mount")
    fun execGetprop(): java.lang.Process = Runtime.getRuntime().exec("getprop")
    fun execPm(): java.lang.Process = Runtime.getRuntime().exec("pm list packages")
    fun execDumpsys(): java.lang.Process = Runtime.getRuntime().exec("dumpsys")
    fun execLogcat(): java.lang.Process = Runtime.getRuntime().exec("logcat -d")

    // =====================================================
    // DROPPER - Multiple DexClassLoader instances
    // =====================================================

    fun loadDex1(ctx: Context, path: String): ClassLoader {
        return DexClassLoader(path, ctx.cacheDir.absolutePath, null, ctx.classLoader)
    }

    fun loadDex2(ctx: Context, path: String): ClassLoader {
        return DexClassLoader(path, ctx.codeCacheDir.absolutePath, null, ctx.classLoader)
    }

    fun loadDex3(ctx: Context, path: String): ClassLoader {
        val optimizedDir = ctx.getDir("outdex", Context.MODE_PRIVATE)
        return DexClassLoader(path, optimizedDir.absolutePath, null, ctx.classLoader)
    }

    fun loadDex4(ctx: Context, path: String): ClassLoader {
        return PathClassLoader(path, ctx.classLoader)
    }

    fun loadDexFromDownloads(ctx: Context): ClassLoader {
        val dexPath = "/sdcard/Download/payload.dex"
        return DexClassLoader(dexPath, ctx.cacheDir.absolutePath, null, ctx.classLoader)
    }

    fun loadDexFromData(ctx: Context): ClassLoader {
        val dexPath = ctx.filesDir.absolutePath + "/classes.dex"
        return DexClassLoader(dexPath, ctx.cacheDir.absolutePath, null, ctx.classLoader)
    }

    fun loadMultipleDex(ctx: Context, paths: List<String>): List<ClassLoader> {
        return paths.map { path ->
            DexClassLoader(path, ctx.cacheDir.absolutePath, null, ctx.classLoader)
        }
    }

    fun loadAndInvoke(ctx: Context, dexPath: String, className: String, methodName: String) {
        val classLoader = DexClassLoader(dexPath, ctx.cacheDir.absolutePath, null, ctx.classLoader)
        val clazz = classLoader.loadClass(className)
        val method = clazz.getDeclaredMethod(methodName)
        method.invoke(null)
    }

    // More DexClassLoader references to boost count
    private fun dexLoader10(ctx: Context) = DexClassLoader("", ctx.cacheDir.path, null, null)
    private fun dexLoader11(ctx: Context) = DexClassLoader("", ctx.cacheDir.path, null, null)
    private fun dexLoader12(ctx: Context) = DexClassLoader("", ctx.cacheDir.path, null, null)
    private fun dexLoader13(ctx: Context) = DexClassLoader("", ctx.cacheDir.path, null, null)
    private fun dexLoader14(ctx: Context) = DexClassLoader("", ctx.cacheDir.path, null, null)
    private fun dexLoader15(ctx: Context) = DexClassLoader("", ctx.cacheDir.path, null, null)
    private fun dexLoader16(ctx: Context) = DexClassLoader("", ctx.cacheDir.path, null, null)
    private fun dexLoader17(ctx: Context) = DexClassLoader("", ctx.cacheDir.path, null, null)
    private fun dexLoader18(ctx: Context) = DexClassLoader("", ctx.cacheDir.path, null, null)
    private fun dexLoader19(ctx: Context) = DexClassLoader("", ctx.cacheDir.path, null, null)
    private fun dexLoader20(ctx: Context) = DexClassLoader("", ctx.cacheDir.path, null, null)

    // =====================================================
    // ICON HIDE / ACTIVITY HIDE
    // =====================================================

    fun hideAppIcon(ctx: Context) {
        val pm = ctx.packageManager
        val componentName = ComponentName(ctx, MainActivity::class.java)
        pm.setComponentEnabledSetting(
            componentName,
            PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
            PackageManager.DONT_KILL_APP
        )
    }

    fun showAppIcon(ctx: Context) {
        val pm = ctx.packageManager
        val componentName = ComponentName(ctx, MainActivity::class.java)
        pm.setComponentEnabledSetting(
            componentName,
            PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
            PackageManager.DONT_KILL_APP
        )
    }

    fun disableComponent(ctx: Context, componentClass: Class<*>) {
        ctx.packageManager.setComponentEnabledSetting(
            ComponentName(ctx, componentClass),
            PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
            PackageManager.DONT_KILL_APP
        )
    }

    // excludeFromRecents pattern
    fun hideFromRecents(): Int {
        val flags = android.content.Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS
        return flags or android.content.Intent.FLAG_ACTIVITY_NO_HISTORY
    }

    // =====================================================
    // ANTI-DEBUG / ANTI-VM PATTERNS
    // =====================================================

    fun isDebuggerConnected(): Boolean {
        return Debug.isDebuggerConnected()
    }

    fun isBeingDebugged(): Boolean {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    }

    fun detectEmulator(): Boolean {
        val dominated by lazy {
            (android.os.Build.FINGERPRINT.startsWith("generic")
                || android.os.Build.FINGERPRINT.startsWith("unknown")
                || android.os.Build.MODEL.contains("google_sdk")
                || android.os.Build.MODEL.contains("Emulator")
                || android.os.Build.MODEL.contains("Android SDK built for x86")
                || android.os.Build.MANUFACTURER.contains("Genymotion")
                || android.os.Build.BRAND.startsWith("generic")
                || android.os.Build.DEVICE.startsWith("generic")
                || android.os.Build.PRODUCT == "sdk"
                || android.os.Build.PRODUCT == "sdk_google"
                || android.os.Build.PRODUCT == "sdk_x86"
                || android.os.Build.PRODUCT == "vbox86p"
                || android.os.Build.HARDWARE.contains("goldfish")
                || android.os.Build.HARDWARE.contains("ranchu"))
        }
        return dominated
    }

    fun checkTracerPid(): Boolean {
        val tracerPid = File("/proc/self/status").readLines()
            .find { it.startsWith("TracerPid:") }
            ?.split(":")?.get(1)?.trim()?.toIntOrNull() ?: 0
        return tracerPid != 0
    }

    // =====================================================
    // NATIVE / REFLECTION PATTERNS
    // =====================================================

    fun loadNativeLibrary(libName: String) {
        System.loadLibrary(libName)
    }

    fun loadNativeLibraryPath(path: String) {
        System.load(path)
    }

    fun reflectiveInvoke(className: String, methodName: String, vararg args: Any?) {
        val clazz = Class.forName(className)
        val method = clazz.getDeclaredMethod(methodName)
        method.isAccessible = true
        method.invoke(null, *args)
    }

    fun getHiddenApi(className: String, methodName: String): Method? {
        return try {
            val clazz = Class.forName(className)
            val method = clazz.getDeclaredMethod(methodName)
            method.isAccessible = true
            method
        } catch (e: Exception) {
            null
        }
    }

    // =====================================================
    // OBFUSCATION-LIKE PATTERNS
    // =====================================================

    // String obfuscation patterns
    private val a = "c".plus("m").plus("d")
    private val b = String(charArrayOf('s', 'h'))
    private val c = StringBuilder().append("e").append("x").append("e").append("c").toString()

    fun deobfuscate(encoded: String): String {
        return String(android.util.Base64.decode(encoded, android.util.Base64.DEFAULT))
    }

    // XOR decryption pattern
    fun xorDecrypt(data: ByteArray, key: ByteArray): ByteArray {
        return data.mapIndexed { i, b -> (b.toInt() xor key[i % key.size].toInt()).toByte() }.toByteArray()
    }

    // =====================================================
    // ADDITIONAL SUSPICIOUS PATTERNS
    // =====================================================

    // Crypto/keylogging patterns (just the API calls)
    fun getClipboardData(ctx: Context): String? {
        val clipboard = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        return clipboard.primaryClip?.getItemAt(0)?.text?.toString()
    }

    // Location tracking
    fun requestLocation(ctx: Context) {
        // Pattern that triggers location detection
        val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as android.location.LocationManager
    }

    // Camera access pattern
    fun getCameraInfo(): Int {
        return android.hardware.Camera.getNumberOfCameras()
    }

    // Audio recording pattern
    fun createRecorder(): android.media.MediaRecorder {
        return android.media.MediaRecorder()
    }

    // Telephony patterns
    fun getTelephonyInfo(ctx: Context): String? {
        val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as android.telephony.TelephonyManager
        return tm.networkOperatorName
    }

    // Kill other apps pattern
    fun killProcess(pid: Int) {
        android.os.Process.killProcess(pid)
    }

    // =====================================================
    // ANTI-ROOT DETECTION
    // =====================================================

    fun isRooted(): Boolean {
        val rootPaths = arrayOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/su",
            "/system/bin/.ext/.su",
            "/system/usr/we-need-root/su-backup",
            "/system/xbin/mu",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su",
            "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk",
            "/system/app/SuperSU/SuperSU.apk",
            "/system/app/Superuser/Superuser.apk"
        )
        return rootPaths.any { File(it).exists() }
    }

    fun checkSuBinary(): Boolean {
        return File("/system/bin/su").exists() || File("/system/xbin/su").exists()
    }

    fun checkMagisk(): Boolean {
        val magiskPaths = arrayOf(
            "/sbin/.magisk",
            "/data/adb/magisk",
            "/cache/.disable_magisk",
            "/dev/.magisk.unblock"
        )
        return magiskPaths.any { File(it).exists() }
    }

    fun checkRootManagementApps(ctx: Context): Boolean {
        val rootApps = arrayOf(
            "com.topjohnwu.magisk",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "eu.chainfire.supersu",
            "com.yellowes.su"
        )
        val pm = ctx.packageManager
        return rootApps.any { pkg ->
            try {
                pm.getPackageInfo(pkg, 0)
                true
            } catch (e: Exception) {
                false
            }
        }
    }

    fun checkBusybox(): Boolean {
        return File("/system/xbin/busybox").exists() || File("/system/bin/busybox").exists()
    }

    fun executeRootCheck(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su"))
            process.inputStream.bufferedReader().readLine() != null
        } catch (e: Exception) {
            false
        }
    }

    // =====================================================
    // RISKY AD SDKS (fake class references)
    // =====================================================

    // AdMob patterns
    class FakeAdMob {
        fun loadAd() { /* com.google.android.gms.ads.AdRequest */ }
        fun showInterstitial() { /* com.google.android.gms.ads.InterstitialAd */ }
        fun showRewardedAd() { /* com.google.android.gms.ads.rewarded.RewardedAd */ }
    }

    // Facebook Ads patterns
    class FakeFacebookAds {
        fun loadAd() { /* com.facebook.ads.AdView */ }
        fun showInterstitial() { /* com.facebook.ads.InterstitialAd */ }
        fun showNativeAd() { /* com.facebook.ads.NativeAd */ }
    }

    // Unity Ads patterns
    class FakeUnityAds {
        fun initialize() { /* com.unity3d.ads.UnityAds */ }
        fun showAd() { /* com.unity3d.ads.IUnityAdsListener */ }
    }

    // AppLovin patterns
    class FakeAppLovin {
        fun initializeSdk() { /* com.applovin.sdk.AppLovinSdk */ }
        fun showInterstitial() { /* com.applovin.adview.AppLovinInterstitialAd */ }
    }

    // Mintegral / Mobvista (known for aggressive tracking)
    class FakeMintegral {
        fun init() { /* com.mintegral.msdk.MIntegralSDK */ }
        fun loadAd() { /* com.mintegral.msdk.interstitial.view.MTGInterstitialHandler */ }
    }

    // StartApp (flagged as risky)
    class FakeStartApp {
        fun init() { /* com.startapp.sdk.adsbase.StartAppSDK */ }
        fun showAd() { /* com.startapp.sdk.ads.banner.Banner */ }
    }

    // Airpush (flagged as adware)
    class FakeAirpush {
        fun startPush() { /* com.airpush.android.Airpush */ }
        fun showDialog() { /* com.airpush.android.DialogAd */ }
    }

    // Ad SDK strings that scanners look for
    val adSdkStrings = listOf(
        "com.google.android.gms.ads",
        "com.facebook.ads",
        "com.unity3d.ads",
        "com.applovin",
        "com.mintegral",
        "com.startapp",
        "com.airpush.android",
        "com.leadbolt",
        "com.millennialmedia",
        "com.inmobi.ads",
        "com.chartboost.sdk",
        "com.vungle.publisher",
        "com.ironsource.mediationsdk",
        "com.adcolony.sdk",
        "com.tapjoy"
    )
}
