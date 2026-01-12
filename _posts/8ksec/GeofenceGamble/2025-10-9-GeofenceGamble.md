---
title: GeofenceGamble - 8kSec
date: 2025-10-9 00:00:00 +/-TTTT
categories: [8kSec]
tags: [8kSec, writeup, mobile penetration testing, android]     # TAG names should always be lowercase
---

<br />**Description**

Embark on a thrilling adventure with **GeofenceGamble**! Explore your city to discover and collect virtual relics of varying rarities scattered across real-world locations. View collectibles on an interactive map, navigate to their locations, and press "Collect" when you're within range. 


Compete with friends on the leaderboard as you hunt for the rarest relics. GeofenceGamble uses precise geolocation to ensure fair play and encourage outdoor exploration.

<br />**Objective**

Bypass geofencing restrictions in location-based games like GeofenceGamble without requiring physical presence at target coordinates. Hackers are supposed to be lazy! Your goal is to identify and leverage weaknesses in the app's location verification system to collect virtual relics remotely.

These techniques should enable you to collect high-value relics from anywhere in the world, highlighting fundamental security issues in how mobile games implement location-based mechanics.

Successfully completing this challenge showcases vulnerabilities in GPS-dependent applications and emphasizes the need for implementing additional validation layers beyond simple coordinate checking.

<br />**Restrictions**

Your solution must work on Android devices running versions up to Android 15. At no point should your solution require statically patching the application to bypass any protections. The exploit should be able to modify location data seamlessly without triggering the game's anti-cheat mechanisms or showing suspicious movement patterns that could flag an account for review.

<br />

**Explore the application**

When the app launches, it runs several root detection checks before the game starts. so we should bypass those checks first

![](/assets/img/8ksec/GeofenceGamble/1.png)

<br />

**Analyzing the application using JADX**

From: AndroidManifest.xml

```xml
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
<uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION"/>
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
<uses-permission
    android:name="android.permission.WRITE_EXTERNAL_STORAGE"
    android:maxSdkVersion="28"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-feature
    android:glEsVersion="0x20000"
    android:required="true"/>
<queries>
    <package android:name="com.google.android.apps.maps"/>
</queries>
```

<br />

| Permission / Feature                   | Purpose                                 |
| -------------------------------------- | --------------------------------------- |
| ACCESS_FINE_LOCATION                   | GPS tracking for gameplay or geofencing |
| ACCESS_COARSE_LOCATION                 | Approximate location                    |
| INTERNET                               | API calls / map loading                 |
| ACCESS_NETWORK_STATE                   | Detect if user is online                |
| READ/WRITE_EXTERNAL_STORAGE            | Store or read game/map data             |
| glEsVersion 0x20000                    | Requires OpenGL ES 2.0 for graphics     |
| queries / com.google.android.apps.maps | Check if Google Maps app is installed   |

<br />

```xml
<uses-feature
    android:name="android.hardware.location.network"
    android:required="false"/>
<uses-feature
    android:name="android.hardware.location.gps"
    android:required="false"/>
<uses-feature
    android:name="android.hardware.telephony"
    android:required="false"/>
<uses-feature
    android:name="android.hardware.wifi"
    android:required="false"/>
```

- `android.hardware.location.network`: 
  - This declares that the app *can* use **network-based location** (Wi-Fi and cell tower triangulation), but doesn’t *require* it.
  - If `required="false"`, devices **without** that hardware (e.g., a tablet with no SIM or Wi-Fi-only location disabled) can still install the app.

- `android.hardware.location.gps`:
  - Declares that the app can use GPS sensors if they exist.
  - Marking it as `false` means the app won’t be filtered out from devices without a GPS chip, for example, an emulator or some low-end devices.

- `android.hardware.telephony`:
  - Indicates that the app can access phone-related hardware (SIM card, cellular network, etc.) but it’s not mandatory.
  - Without this flag, the Play Store might exclude Wi-Fi-only tablets or Android TVs from seeing the app.
  - Apps often include this to allow installation across a wider range of devices, especially if they only use telephony for optional identification or analytics.

- `android.hardware.wifi`:
  - Declares the app can use Wi-Fi (for internet or location services).
  - Not required, meaning the app can still function on devices that connect only via mobile data or Ethernet (e.g., some smart displays).

<br />From: com.eightksec.geofencegamble.security.NativeRootChecker

```java
public final class NativeRootChecker {
    public static final int $stable;
    public static final NativeRootChecker INSTANCE = new NativeRootChecker();
    private static final String TAG = "NativeRootChecker";
    private static boolean libraryLoaded;

    private final native boolean checkReadableProcMapsNative();

    private final native boolean checkSuExistsNative();

    private NativeRootChecker() {
    }

    static {
        try {
            System.loadLibrary("geofencegamble_native");
            libraryLoaded = true;
            Log.i(TAG, "Native library loaded successfully.");
        } catch (SecurityException e) {
            Log.e(TAG, "SecurityException loading native library", e);
        } catch (UnsatisfiedLinkError e2) {
            Log.e(TAG, "Failed to load native library: geofencegamble_native", e2);
        }
        $stable = 8;
    }

    public final boolean checkSuExists() {
        if (!libraryLoaded) {
            return false;
        }
        try {
            return checkSuExistsNative();
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Native method checkSuExistsNative not found", e);
            return false;
        }
    }

    public final boolean checkProcMaps() {
        if (!libraryLoaded) {
            return false;
        }
        try {
            return checkReadableProcMapsNative();
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Native method checkReadableProcMapsNative not found", e);
            return false;
        }
    }
}
```

`NativeRootChecker` is a singleton that loads `libgeofencegamble_native.so` and exposes two Java wrappers:

- `checkSuExists()` → calls native `checkSuExistsNative()`, detects `su` binaries.
- `checkProcMaps()` → calls native `checkReadableProcMapsNative()`, inspects `/proc/self/maps` for injected libs (Frida/Xposed/etc).

If the native lib fails to load, the Java wrappers return `false`. The `RootDetector` collects these native results along with many Java checks and uses them in `isDeviceRootedOrEmulator()`.

<br />From: com.eightksec.geofencegamble.security.RootDetector

```java
public final class RootDetector {
    public static final int $stable = 8;
    private final String TAG;
    private final Context context;

    public RootDetector(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
        this.TAG = "RootDetector";
    }

    public static final /* data */ class RootDetectionResult {
        public static final int $stable = 0;
        private final boolean isRooted;
        private final String methodName;

        public static /* synthetic */ RootDetectionResult copy$default(RootDetectionResult rootDetectionResult, String str, boolean z, int i, Object obj) {
            if ((i & 1) != 0) {
                str = rootDetectionResult.methodName;
            }
            if ((i & 2) != 0) {
                z = rootDetectionResult.isRooted;
            }
            return rootDetectionResult.copy(str, z);
        }

        /* renamed from: component1, reason: from getter */
        public final String getMethodName() {
            return this.methodName;
        }

        /* renamed from: component2, reason: from getter */
        public final boolean getIsRooted() {
            return this.isRooted;
        }

        public final RootDetectionResult copy(String methodName, boolean isRooted) {
            Intrinsics.checkNotNullParameter(methodName, "methodName");
            return new RootDetectionResult(methodName, isRooted);
        }

        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof RootDetectionResult)) {
                return false;
            }
            RootDetectionResult rootDetectionResult = (RootDetectionResult) other;
            return Intrinsics.areEqual(this.methodName, rootDetectionResult.methodName) && this.isRooted == rootDetectionResult.isRooted;
        }

        public int hashCode() {
            return (this.methodName.hashCode() * 31) + Boolean.hashCode(this.isRooted);
        }

        public String toString() {
            return "RootDetectionResult(methodName=" + this.methodName + ", isRooted=" + this.isRooted + ')';
        }

        public RootDetectionResult(String methodName, boolean z) {
            Intrinsics.checkNotNullParameter(methodName, "methodName");
            this.methodName = methodName;
            this.isRooted = z;
        }

        public final String getMethodName() {
            return this.methodName;
        }

        public final boolean isRooted() {
            return this.isRooted;
        }
    }

    public final boolean isDeviceRootedOrEmulator() {
        List<RootDetectionResult> performChecks = performChecks();
        logDetectionResults(performChecks);
        List<RootDetectionResult> list = performChecks;
        if ((list instanceof Collection) && list.isEmpty()) {
            return false;
        }
        Iterator<T> it = list.iterator();
        while (it.hasNext()) {
            if (((RootDetectionResult) it.next()).isRooted()) {
                return true;
            }
        }
        return false;
    }

    public final List<RootDetectionResult> getDetectionInfo() {
        return performChecks();
    }

    private final List<RootDetectionResult> performChecks() {
        ArrayList arrayList = new ArrayList();
        arrayList.add(new RootDetectionResult("SU Binary Paths (Java)", checkSuPaths()));
        arrayList.add(new RootDetectionResult("Build Tags (test-keys)", checkBuildTags()));
        arrayList.add(new RootDetectionResult("Dangerous Props", checkDangerousProps()));
        arrayList.add(new RootDetectionResult("RW System Paths", canWriteToSystemFolder()));
        arrayList.add(new RootDetectionResult("Hooking Frameworks (Java)", checkForHooks()));
        arrayList.add(new RootDetectionResult("Magisk Specific Files/Sockets", checkForMagisk()));
        arrayList.add(new RootDetectionResult("Root Management Apps", checkForRootManagementApps()));
        arrayList.add(new RootDetectionResult("Potentially Dangerous Apps", checkForDangerousApps()));
        arrayList.add(new RootDetectionResult("BusyBox Binary", checkForBusyBox()));
        arrayList.add(new RootDetectionResult("SELinux Status (Permissive)", checkSELinuxPermissive()));
        arrayList.add(new RootDetectionResult("SU Binary Paths (Native)", NativeRootChecker.INSTANCE.checkSuExists()));
        arrayList.add(new RootDetectionResult("Suspicious Libs in /proc/maps (Native)", NativeRootChecker.INSTANCE.checkProcMaps()));
        arrayList.add(new RootDetectionResult("Emulator Files", checkForEmulatorFiles()));
        arrayList.add(new RootDetectionResult("Emulator Props (Generic)", checkEmulatorProps()));
        arrayList.add(new RootDetectionResult("Emulator Hardware/Device Name", checkEmulatorHardwareName()));
        arrayList.add(new RootDetectionResult("Emulator QEMU Props", checkQemuProps()));
        return arrayList;
    }

    private final boolean checkSuPaths() {
        String[] strArr = {"/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su"};
        for (int i = 0; i < 10; i++) {
            if (new File(strArr[i]).exists()) {
                return true;
            }
        }
        return false;
    }

    private final boolean checkBuildTags() {
        String str = Build.TAGS;
        return str != null && StringsKt.contains$default((CharSequence) str, (CharSequence) "test-keys", false, 2, (Object) null);
    }

    private final boolean checkDangerousProps() {
        for (Map.Entry entry : MapsKt.mapOf(TuplesKt.to("ro.debuggable", "1"), TuplesKt.to("ro.secure", "0")).entrySet()) {
            if (Intrinsics.areEqual(getSystemProperty((String) entry.getKey()), (String) entry.getValue())) {
                return true;
            }
        }
        return false;
    }

    private final boolean canWriteToSystemFolder() {
        File file;
        String[] strArr = {"/system", "/system/bin", "/system/sbin", "/system/xbin", "/vendor/bin", "/sbin", "/etc"};
        for (int i = 0; i < 7; i++) {
            try {
                file = new File(strArr[i], "test_write_" + System.currentTimeMillis());
                if (file.exists()) {
                    file.delete();
                }
            } catch (Exception unused) {
            }
            if (file.createNewFile()) {
                file.delete();
                return true;
            }
            continue;
        }
        return false;
    }

    private final boolean checkNativeRootIndicators() {
        String[] strArr = new String[1];
        try {
            Process exec = Runtime.getRuntime().exec("which su");
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(exec.getInputStream()));
            String readLine = bufferedReader.readLine();
            bufferedReader.close();
            int waitFor = exec.waitFor();
            exec.destroy();
            if (waitFor != 0 || readLine == null) {
                return false;
            }
            return readLine.length() > 0;
        } catch (Exception e) {
            Log.w(this.TAG, "Error executing command: which su", e);
            return false;
        }
    }

    private final boolean checkForHooks() {
        ApplicationInfo applicationInfo;
        try {
            throw new Exception("Hook Check");
        } catch (Exception e) {
            StackTraceElement[] stackTrace = e.getStackTrace();
            Intrinsics.checkNotNullExpressionValue(stackTrace, "getStackTrace(...)");
            for (StackTraceElement stackTraceElement : stackTrace) {
                String className = stackTraceElement.getClassName();
                Intrinsics.checkNotNull(className);
                String str = className;
                if (StringsKt.contains$default((CharSequence) str, (CharSequence) "de.robv.android.xposed", false, 2, (Object) null) || StringsKt.contains$default((CharSequence) str, (CharSequence) "com.saurik.substrate", false, 2, (Object) null) || StringsKt.contains$default((CharSequence) str, (CharSequence) "com.cigital.freak", false, 2, (Object) null) || StringsKt.contains$default((CharSequence) str, (CharSequence) "com.lody.virtual", false, 2, (Object) null)) {
                    return true;
                }
            }
            String[] strArr = {"de.robv.android.xposed.XposedHelpers", "de.robv.android.xposed.XposedBridge", "com.saurik.substrate.MS", "com.lody.virtual.client.core.VirtualCore"};
            for (int i = 0; i < 4; i++) {
                String str2 = strArr[i];
                try {
                    Class.forName(str2);
                    return true;
                } catch (ClassNotFoundException unused) {
                } catch (Exception e2) {
                    Log.w(this.TAG, "Error checking for hook class " + str2, e2);
                }
            }
            try {
                applicationInfo = this.context.getPackageManager().getApplicationInfo("de.robv.android.xposed.installer", 0);
                Intrinsics.checkNotNullExpressionValue(applicationInfo, "getApplicationInfo(...)");
            } catch (PackageManager.NameNotFoundException unused2) {
            } catch (Exception e3) {
                Log.w(this.TAG, "Error checking Xposed files", e3);
            }
            return new File(applicationInfo.dataDir, "bin/XposedBridge.jar").exists();
        }
    }

    private final boolean checkForMagisk() {
        String[] strArr = {"/sbin/.magisk", "/sbin/.core", "/sbin/.su", "/sbin/magisk", "/cache/.disable_magisk", "/cache/magisk.log", "/cache/magisk_mount", "/cache/magisk_merge", "/data/adb/magisk", "/data/adb/magisk.img", "/data/adb/magisk.db", "/data/adb/magisk_simple", "/data/adb/modules", "/data/adb/su", "/data/magisk.db"};
        for (int i = 0; i < 15; i++) {
            if (new File(strArr[i]).exists()) {
                return true;
            }
        }
        return detectMagiskUnixDomainSocket();
    }


    private final boolean checkForRootManagementApps() {
        PackageManager packageManager = this.context.getPackageManager();
        String[] strArr = {"com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu", "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.topjohnwu.magisk", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus", "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot", "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "com.koushikdutta.rommanager", "com.koushikdutta.rommanager.license", "com.cyanogenmod.filemanager", "com.jrummy.busybox.installer", "com.jrummyapps.busybox.installer", "stericson.busybox", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch", "com.freedom.assist", "com.cheatengine.ceapp", "com.networksignalinfo.pro", "com.google.android.apps.authenticator2.license", "com.android.vending.billing.InAppBillingService.LOCK", "com.android.vending.billing.InAppBillingService.LUCK", "com.blackmartalpha", "org.blackmart.market", "com.kingroot.kinguser", "com.kingo.root", "com.smedialink.oneclickroot", "com.zhiqupk.root.global", "com.alephzain.framaroot"};
        for (int i = 0; i < 37; i++) {
            String str = strArr[i];
            try {
                packageManager.getPackageInfo(str, 0);
                return true;
            } catch (PackageManager.NameNotFoundException unused) {
            } catch (Exception e) {
                Log.w(this.TAG, "Error checking package " + str, e);
            }
        }
        return false;
    }

    private final boolean checkForDangerousApps() {
        return checkForRootManagementApps();
    }

    private final boolean checkForBusyBox() {
        String[] strArr = {"/system/bin/busybox", "/system/xbin/busybox", "/sbin/busybox", "/data/local/bin/busybox", "/data/local/xbin/busybox", "/system/sd/xbin/busybox", "/data/busybox", "/data/adb/modules/busybox*"};
        for (int i = 0; i < 8; i++) {
            if (new File(strArr[i]).exists()) {
                return true;
            }
        }
        try {
            Process exec = Runtime.getRuntime().exec(new String[]{"which", "busybox"});
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(exec.getInputStream()));
            String readLine = bufferedReader.readLine();
            int waitFor = exec.waitFor();
            bufferedReader.close();
            exec.destroy();
            if (waitFor == 0 && readLine != null) {
                if (readLine.length() > 0) {
                    return true;
                }
            }
        } catch (Exception e) {
            Log.w(this.TAG, "Error executing 'which busybox'", e);
        }
        return false;
    }

    private final boolean checkSELinuxPermissive() {
        String str;
        String obj;
        try {
            Process exec = Runtime.getRuntime().exec("getenforce");
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(exec.getInputStream()));
            String readLine = bufferedReader.readLine();
            if (readLine == null || (obj = StringsKt.trim((CharSequence) readLine).toString()) == null) {
                str = null;
            } else {
                str = obj.toLowerCase(Locale.ROOT);
                Intrinsics.checkNotNullExpressionValue(str, "toLowerCase(...)");
            }
            bufferedReader.close();
            exec.destroy();
            if (str != null) {
                return !Intrinsics.areEqual(str, "enforcing");
            }
            return false;
        } catch (Exception e) {
            Log.w(this.TAG, "Error checking SELinux status via getenforce", e);
            return false;
        }
    }

    private final boolean checkForEmulatorFiles() {
        String[] strArr = {"/system/lib/libc_malloc_debug_qemu.so", "/sys/qemu_trace", "/system/bin/qemu-props", "/dev/socket/genymotion", "/dev/socket/genyd", "/dev/socket/genymotion_audio", "/dev/socket/andyd", "/dev/socket/andy-render", "/dev/socket/noxd", "/dev/socket/nox-bridge", "/dev/qemu_pipe", "/dev/goldfish_pipe", "/dev/alarm", "/system/lib/egl/libGLES_android.so", "/system/bin/androVM-prop", "/system/bin/microvirt-prop"};
        for (int i = 0; i < 16; i++) {
            if (new File(strArr[i]).exists()) {
                return true;
            }
        }
        return false;
    }

    private final boolean checkEmulatorProps() {
        String str;
        for (Map.Entry entry : MapsKt.mapOf(TuplesKt.to("ro.hardware", CollectionsKt.listOf((Object[]) new String[]{"goldfish", "ranchu", "qemu", "vbox86", "android_x86", "intel", "amd"})), TuplesKt.to("ro.kernel.qemu", CollectionsKt.listOf("1")), TuplesKt.to("ro.kernel.qemu.gles", CollectionsKt.listOf("1")), TuplesKt.to("ro.product.model", CollectionsKt.listOf((Object[]) new String[]{"sdk", "google_sdk", "android sdk built for x86", "emulator", "genymotion", "nox", "virtualbox"})), TuplesKt.to("ro.product.manufacturer", CollectionsKt.listOf((Object[]) new String[]{"genymotion", EnvironmentCompat.MEDIA_UNKNOWN, "corellium", "bluestacks", "virtualbox"})), TuplesKt.to("ro.product.brand", CollectionsKt.listOf((Object[]) new String[]{"generic", "generic_x86", "generic_arm"})), TuplesKt.to("ro.board.platform", CollectionsKt.listOf((Object[]) new String[]{"android", "goldfish", "vbox86p"})), TuplesKt.to("ro.build.fingerprint", CollectionsKt.listOf((Object[]) new String[]{"generic", "emulator", "vbox", "test-keys"})), TuplesKt.to("ro.build.tags", CollectionsKt.listOf("test-keys")), TuplesKt.to("ro.build.characteristics", CollectionsKt.listOf("emulator"))).entrySet()) {
            String str2 = (String) entry.getKey();
            List list = (List) entry.getValue();
            String systemProperty = getSystemProperty(str2);
            if (systemProperty != null) {
                str = systemProperty.toLowerCase(Locale.ROOT);
                Intrinsics.checkNotNullExpressionValue(str, "toLowerCase(...)");
            } else {
                str = null;
            }
            if (str != null) {
                Iterator it = list.iterator();
                while (it.hasNext()) {
                    if (StringsKt.contains$default((CharSequence) str, (CharSequence) it.next(), false, 2, (Object) null)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private final boolean checkEmulatorHardwareName() {
        String HARDWARE = Build.HARDWARE;
        Intrinsics.checkNotNullExpressionValue(HARDWARE, "HARDWARE");
        String lowerCase = HARDWARE.toLowerCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
        String DEVICE = Build.DEVICE;
        Intrinsics.checkNotNullExpressionValue(DEVICE, "DEVICE");
        String lowerCase2 = DEVICE.toLowerCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(lowerCase2, "toLowerCase(...)");
        String PRODUCT = Build.PRODUCT;
        Intrinsics.checkNotNullExpressionValue(PRODUCT, "PRODUCT");
        String lowerCase3 = PRODUCT.toLowerCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(lowerCase3, "toLowerCase(...)");
        String MODEL = Build.MODEL;
        Intrinsics.checkNotNullExpressionValue(MODEL, "MODEL");
        String lowerCase4 = MODEL.toLowerCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(lowerCase4, "toLowerCase(...)");
        String MANUFACTURER = Build.MANUFACTURER;
        Intrinsics.checkNotNullExpressionValue(MANUFACTURER, "MANUFACTURER");
        String lowerCase5 = MANUFACTURER.toLowerCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(lowerCase5, "toLowerCase(...)");
        List listOf = CollectionsKt.listOf((Object[]) new String[]{"goldfish", "ranchu", "qemu", "vbox", "nox", "andy", "genymotion", "ttvm", "android_x86", "emulator", "sdk", "google_sdk", "virtual"});
        boolean z = listOf instanceof Collection;
        if (!z || !listOf.isEmpty()) {
            Iterator it = listOf.iterator();
            while (it.hasNext()) {
                if (StringsKt.contains$default((CharSequence) lowerCase, (CharSequence) it.next(), false, 2, (Object) null)) {
                    return true;
                }
            }
        }
        if (!z || !listOf.isEmpty()) {
            Iterator it2 = listOf.iterator();
            while (it2.hasNext()) {
                if (StringsKt.contains$default((CharSequence) lowerCase2, (CharSequence) it2.next(), false, 2, (Object) null)) {
                    return true;
                }
            }
        }
        if (!z || !listOf.isEmpty()) {
            Iterator it3 = listOf.iterator();
            while (it3.hasNext()) {
                if (StringsKt.contains$default((CharSequence) lowerCase3, (CharSequence) it3.next(), false, 2, (Object) null)) {
                    return true;
                }
            }
        }
        if (!z || !listOf.isEmpty()) {
            Iterator it4 = listOf.iterator();
            while (it4.hasNext()) {
                if (StringsKt.contains$default((CharSequence) lowerCase4, (CharSequence) it4.next(), false, 2, (Object) null)) {
                    return true;
                }
            }
        }
        if (!z || !listOf.isEmpty()) {
            Iterator it5 = listOf.iterator();
            while (it5.hasNext()) {
                if (StringsKt.contains$default((CharSequence) lowerCase5, (CharSequence) it5.next(), false, 2, (Object) null) && !Intrinsics.areEqual(lowerCase5, "google")) {
                    return true;
                }
            }
        }
        return false;
    }

    private final boolean checkQemuProps() {
        String[] strArr = {"ro.kernel.qemu.avd_name", "ro.kernel.qemu.gles", "ro.kernel.qemu", "qemu.sf.lcd_density", "qemu.hw.mainkeys"};
        for (int i = 0; i < 5; i++) {
            if (getSystemProperty(strArr[i]) != null) {
                return true;
            }
        }
        return false;
    }

    private final String getSystemProperty(String propName) {
        try {
            Process exec = Runtime.getRuntime().exec("getprop " + propName);
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(exec.getInputStream()), 8192);
            String readLine = bufferedReader.readLine();
            String obj = readLine != null ? StringsKt.trim((CharSequence) readLine).toString() : null;
            bufferedReader.close();
            try {
                exec.destroy();
            } catch (Exception unused) {
            }
            String str = obj;
            if (str == null) {
                return null;
            }
            if (str.length() == 0) {
                return null;
            }
            return obj;
        } catch (Exception e) {
            Log.w(this.TAG, "Error getting system property: " + propName, e);
            return null;
        }
    }

    private final void logDetectionResults(List<RootDetectionResult> results) {
        Log.i(this.TAG, "--- Root/Emulator Detection Results ---");
        boolean z = false;
        for (RootDetectionResult rootDetectionResult : results) {
            rootDetectionResult.isRooted();
            if (rootDetectionResult.isRooted()) {
                z = true;
            }
        }
        Log.i(this.TAG, "Overall Status: ".concat(z ? "DEVICE FLAGGED (Rooted or Emulator)" : "Device Clear"));
        Log.i(this.TAG, "-------------------------------------");
    }
}
```

While reversing the `com.eightksec.geofencegamble` app, I found a rather comprehensive root detection system inside the `RootDetector` class. This component performs both Java-level and native-level integrity checks to identify rooted or emulated devices.

The `RootDetector` class initializes with a context and defines multiple methods, each testing for a specific root or emulator indicator. These are aggregated through `performChecks()`, which builds a list of `RootDetectionResult` objects, one for each detection technique.

<br />**Detection Techniques:**

Here’s a breakdown of the most interesting checks:

1. **SU Binary Paths**

Checks for the presence of `su` binaries in typical locations like `/system/xbin/su`, `/sbin/su`, or `/data/local/bin/su`.
 This is one of the most common ways to detect rooted devices.

2. **Build Tags**

Reads the system `Build.TAGS` property. If it contains `"test-keys"`, the build is likely non-production, common on emulators or custom ROMs.

3. **Dangerous Properties**

Queries system properties such as:

- `ro.debuggable=1`
- `ro.secure=0`
   These indicate the system was built for debugging.

4. **Write Access to System Folders**

Attempts to create a temporary file inside system directories like `/system/` or `/vendor/`. If successful, it means the partition is writable, a strong root indicator.

5. **Hook Detection**

Throws and inspects a fake exception to analyze the stack trace for the presence of hooking frameworks like:

- Xposed (`de.robv.android.xposed`)
- Substrate (`com.saurik.substrate`)
- Virtual frameworks like `VirtualCore`

It also tries loading these classes directly via reflection.

6. **Magisk Detection**

Looks for Magisk-related files and sockets under `/sbin`, `/cache`, and `/data/adb/`. Additionally, it reads `/proc/net/unix` to detect the Magisk UNIX socket (e.g. `/dev/socket/magisk`).

7. **Root Management Apps**

Scans installed packages for well-known root-related apps like `SuperSU`, `Magisk`, `RootCloak`, and `KingRoot`.

8. **BusyBox**

Checks for BusyBox binaries or resolves them with a `which busybox` command.

9. **SELinux Status**

Executes `getenforce` to detect if SELinux is in permissive mode instead of enforcing.

10. **Native Checks**

Uses JNI calls via `NativeRootChecker`:

```
checkSuExistsNative()
checkReadableProcMapsNative()
```

These functions are implemented in the `geofencegamble_native` library and likely perform similar root checks from the native layer (for example, reading `/proc/self/maps` or scanning for injected libraries).

11. **Emulator Detection**

A large set of checks target emulator artifacts:

- Common QEMU device files (`/dev/qemu_pipe`, `/dev/goldfish_pipe`)
- System properties like `ro.kernel.qemu=1`
- Build identifiers like `"generic_x86"`, `"vbox"`, `"nox"`, `"emulator"`, etc.
- Manufacturer and model strings typical of Genymotion, BlueStacks, etc.

<br />I hooked several of these functions using Frida to observe their return values

```javascript
Java.perform(function () {

    let NativeRootChecker = Java.use("com.eightksec.geofencegamble.security.NativeRootChecker");
    NativeRootChecker["checkReadableProcMapsNative"].implementation = function () {
    console.log(`NativeRootChecker.checkReadableProcMapsNative is called`);
    let result = this["checkReadableProcMapsNative"]();
    console.log(`NativeRootChecker.checkReadableProcMapsNative result=${result}`);
    return result;
    };

    NativeRootChecker["checkSuExistsNative"].implementation = function () {
    console.log(`NativeRootChecker.checkSuExistsNative is called`);
    let result = this["checkSuExistsNative"]();
    console.log(`NativeRootChecker.checkSuExistsNative result=${result}`);
    return result;
    };

    let RootDetectionResult = Java.use("com.eightksec.geofencegamble.security.RootDetector$RootDetectionResult");
    RootDetectionResult["$init"].implementation = function (methodName, z) {
    console.log(`RootDetectionResult.$init is called: methodName=${methodName}, z=${z}`);
    this["$init"](methodName, z);
    };

    RootDetectionResult["isRooted"].implementation = function () {
    console.log(`RootDetectionResult.isRooted is called`);
    let result = this["isRooted"]();
    console.log(`RootDetectionResult.isRooted result=${result}`);
    return result;
    };

});
```

<br />Multiple detection mechanisms identified the runtime as an emulator rather than a physical device, and indicated that the device had root access.

```
frida -U -f com.eightksec.geofencegamble -l hook.js
     ____
    / _  |   Frida 16.7.19 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Android Emulator 5554 (id=emulator-5554)
Spawned `com.eightksec.geofencegamble`. Resuming main thread!
[Android Emulator 5554::com.eightksec.geofencegamble ]-> RootDetectionResult.$init is called: methodName=SU Binary Paths (Java), z=false
RootDetectionResult.$init is called: methodName=Build Tags (test-keys), z=true
RootDetectionResult.$init is called: methodName=Dangerous Props, z=false
RootDetectionResult.$init is called: methodName=RW System Paths, z=false
RootDetectionResult.$init is called: methodName=Hooking Frameworks (Java), z=false
RootDetectionResult.$init is called: methodName=Magisk Specific Files/Sockets, z=false
RootDetectionResult.$init is called: methodName=Root Management Apps, z=false
RootDetectionResult.$init is called: methodName=Potentially Dangerous Apps, z=false
RootDetectionResult.$init is called: methodName=BusyBox Binary, z=false
RootDetectionResult.$init is called: methodName=SELinux Status (Permissive), z=false
NativeRootChecker.checkSuExistsNative is called
NativeRootChecker.checkSuExistsNative result=false
RootDetectionResult.$init is called: methodName=SU Binary Paths (Native), z=false
NativeRootChecker.checkReadableProcMapsNative is called
NativeRootChecker.checkReadableProcMapsNative result=false
RootDetectionResult.$init is called: methodName=Suspicious Libs in /proc/maps (Native), z=false
RootDetectionResult.$init is called: methodName=Emulator Files, z=false
RootDetectionResult.$init is called: methodName=Emulator Props (Generic), z=true
RootDetectionResult.$init is called: methodName=Emulator Hardware/Device Name, z=true
RootDetectionResult.$init is called: methodName=Emulator QEMU Props, z=true
RootDetectionResult.$init is called: methodName=SU Binary Paths (Java), z=false
RootDetectionResult.$init is called: methodName=Build Tags (test-keys), z=true
RootDetectionResult.$init is called: methodName=Dangerous Props, z=false
RootDetectionResult.$init is called: methodName=RW System Paths, z=false
RootDetectionResult.$init is called: methodName=Hooking Frameworks (Java), z=false
RootDetectionResult.$init is called: methodName=Magisk Specific Files/Sockets, z=false
RootDetectionResult.$init is called: methodName=Root Management Apps, z=false
RootDetectionResult.$init is called: methodName=Potentially Dangerous Apps, z=false
RootDetectionResult.$init is called: methodName=BusyBox Binary, z=false
RootDetectionResult.$init is called: methodName=SELinux Status (Permissive), z=false
NativeRootChecker.checkSuExistsNative is called
NativeRootChecker.checkSuExistsNative result=false
RootDetectionResult.$init is called: methodName=SU Binary Paths (Native), z=false
NativeRootChecker.checkReadableProcMapsNative is called
NativeRootChecker.checkReadableProcMapsNative result=false
RootDetectionResult.$init is called: methodName=Suspicious Libs in /proc/maps (Native), z=false
RootDetectionResult.$init is called: methodName=Emulator Files, z=false
RootDetectionResult.$init is called: methodName=Emulator Props (Generic), z=true
RootDetectionResult.$init is called: methodName=Emulator Hardware/Device Name, z=true
RootDetectionResult.$init is called: methodName=Emulator QEMU Props, z=true
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=false
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=false
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=true
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=true
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=true
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=true
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=true
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=true
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=true
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=true
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=false
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=true
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=false
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=false
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=false
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=false
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=false
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=false
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=false
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=false
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=false
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=false
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=false
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=true
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=true
RootDetectionResult.isRooted is called
RootDetectionResult.isRooted result=true
```

<br />**Disabling Root Detection Method 1**

To bypass the app’s root detection logic, I decided to target the `isRooted()` method inside the `RootDetectionResult` class. This method is responsible for returning whether a specific check has detected root access. By hooking it with Frida, I could override its behavior and make every check appear clean. My initial attempt called `this["isRooted"]()` inside the hook, which caused infinite recursion because the hook kept calling itself. After realizing that, I saved the original implementation and simply returned `false` instead. This way, every call to `isRooted()` reported that the device was not rooted, effectively disabling all root detection results at once.

```javascript
Java.perform(function () {
    let RootDetectionResult = Java.use("com.eightksec.geofencegamble.security.RootDetector$RootDetectionResult");
    RootDetectionResult["isRooted"].implementation = function () {
        this["isRooted"]();
        return false;
    };
});
```

<br />**Disabling Root Detection Method 2**

I targeted the `isDeviceRootedOrEmulator()` entry point to the app’s entire root/emulator logic, by hooking it with Frida I could force the method to always return `false`, making the app believe the device is clean.

```javascript
Java.perform(function () {
    let RootDetector = Java.use("com.eightksec.geofencegamble.security.RootDetector");
    RootDetector["isDeviceRootedOrEmulator"].implementation = function () {
        this["isDeviceRootedOrEmulator"]();
        return false;
    };
});
```

<br />**Disabling Root Detection Method 3**

I hooked `RootDetector.performChecks()` with Frida and returned a fabricated `java.util.ArrayList` of `RootDetectionResult(name, false)` entries so every check reports “not rooted.

```javascript
Java.perform(function() {
    
    let RootDetector = Java.use("com.eightksec.geofencegamble.security.RootDetector");
    let RootDetectionResult = Java.use("com.eightksec.geofencegamble.security.RootDetector$RootDetectionResult");    
    RootDetector.performChecks.implementation = function() {
        
        // Don't even call the original method to avoid detection
        let fakeResults = Java.use("java.util.ArrayList").$new();
        
        // Create fake clean results for all expected checks
        let expectedChecks = [
            "SU Binary Paths (Java)", "Build Tags (test-keys)", "Dangerous Props",
            "RW System Paths", "Hooking Frameworks (Java)", "Magisk Specific Files/Sockets",
            "Root Management Apps", "Potentially Dangerous Apps", "BusyBox Binary",
            "SELinux Status (Permissive)", "SU Binary Paths (Native)", 
            "Suspicious Libs in /proc/maps (Native)", "Emulator Files", 
            "Emulator Props (Generic)", "Emulator Hardware/Device Name", "Emulator QEMU Props"
        ];
        
        expectedChecks.forEach(checkName => {
            let cleanResult = RootDetectionResult.$new(checkName, false); // false = not detected
            fakeResults.add(cleanResult);
        });
        
        console.log(`[+] Generated ${fakeResults.size()} clean detection results`);
        return fakeResults;
    };
});
```

<br />**Disabling Root Detection Method 4**

I hooked `RootDetector.performChecks()` but still call the original function, capture its returned list, and build a new `java.util.ArrayList` of `RootDetectionResult(name, false)` entries (preserving each check’s name). This sanitizes the real results forcing every check to report “not rooted”

```javascript
Java.perform(function () {
    const ROOT_DETECTOR = "com.eightksec.geofencegamble.security.RootDetector";
    const RDR = "com.eightksec.geofencegamble.security.RootDetector$RootDetectionResult";
    const ArrayList = Java.use("java.util.ArrayList");

    try {
        const RootDetector = Java.use(ROOT_DETECTOR);
        const RootDetectionResult = Java.use(RDR);
        const orig = RootDetector.performChecks.overload();

        orig.implementation = function () {
            console.log("[*] performChecks() hooked");

            // call the original method
            const origList = orig.call(this);
            const newList = ArrayList.$new();

            try {
                const n = origList.size();
                console.log("    returned list size:", n);

                for (let i = 0; i < n; i++) {
                    const item = origList.get(i);
                    let name = "(unknown)";
                    try {
                        if (item.getMethodName) name = item.getMethodName();
                        else if (item.toString) name = item.toString();
                    } catch (e) {}

                    // create new result with isRooted = false
                    const newItem = RootDetectionResult.$new(name, false);
                    newList.add(newItem);

                    console.log(`    [${i}] ${name} -> forced false`);
                }
            } catch (e) {
                console.log("[-] iteration error:", e.message);
                return origList;
            }

            return newList; // return modified results
        };
    } catch (err) {
        console.log("[-] Failed to hook:", err.message);
    }
});
```

<br />After bypassing the root checks, the game starts. You must collect all virtual relics of scattered across real locations within 30 minutes to win

![](/assets/img/8ksec/GeofenceGamble/2.png)

<br />Clicking on a relic triggers a distance check between the player’s position and the relic’s location. If the distance is less than 50 meters, the relic becomes collectible otherwise, the app displays an alert indicating that the relic is too far away

![](/assets/img/8ksec/GeofenceGamble/3.png)

<br />

![](/assets/img/8ksec/GeofenceGamble/4.png)

<br />From: com.eightksec.geofencegamble.utils.LocationUtils

```java
public final class LocationUtils {
    public static final int $stable = 0;
    private static final float COLLECTION_RADIUS_METERS = 50.0f;
    private static final float EARTH_RADIUS_METERS = 6371000.0f;
    public static final LocationUtils INSTANCE = new LocationUtils();

    private LocationUtils() {
    }

    public final boolean isWithinCollectionRadius(GeoPoint userLocation, GeoPoint relicLocation) {
        Intrinsics.checkNotNullParameter(userLocation, "userLocation");
        Intrinsics.checkNotNullParameter(relicLocation, "relicLocation");
        return calculateDistance(userLocation.getLatitude(), userLocation.getLongitude(), relicLocation.getLatitude(), relicLocation.getLongitude()) <= 50.0d;
    }

    public final double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
        double radians = Math.toRadians(lat2 - lat1);
        double radians2 = Math.toRadians(lon2 - lon1);
        double d = 2;
        double d2 = radians / d;
        double d3 = radians2 / d;
        double sin = (Math.sin(d2) * Math.sin(d2)) + (Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2)) * Math.sin(d3) * Math.sin(d3));
        return EARTH_RADIUS_METERS * d * Math.atan2(Math.sqrt(sin), Math.sqrt(1 - sin));
    }

    public final double calculateBearing(double lat1, double lon1, double lat2, double lon2) {
        double radians = Math.toRadians(lon2 - lon1);
        double radians2 = Math.toRadians(lat1);
        double radians3 = Math.toRadians(lat2);
        double degrees = Math.toDegrees(Math.atan2(Math.sin(radians) * Math.cos(radians3), (Math.cos(radians2) * Math.sin(radians3)) - ((Math.sin(radians2) * Math.cos(radians3)) * Math.cos(radians))));
        return degrees < 0.0d ? degrees + 360 : degrees;
    }

    public final String getDirectionString(double bearing) {
        if (bearing >= 337.5d || bearing < 22.5d) {
            return "N";
        }
        if (bearing >= 22.5d && bearing < 67.5d) {
            return "NE";
        }
        if (bearing >= 67.5d && bearing < 112.5d) {
            return "E";
        }
        if (bearing >= 112.5d && bearing < 157.5d) {
            return "SE";
        }
        if (bearing >= 157.5d && bearing < 202.5d) {
            return "S";
        }
        if (bearing >= 202.5d && bearing < 247.5d) {
            return "SW";
        }
        if (bearing >= 247.5d && bearing < 292.5d) {
            return "W";
        }
        return "NW";
    }

    public final String formatDistance(double distance) {
        if (distance < 1000.0d) {
            return new StringBuilder().append((int) distance).append('m').toString();
        }
        String format = String.format("%.1fkm", Arrays.copyOf(new Object[]{Double.valueOf(distance / 1000)}, 1));
        Intrinsics.checkNotNullExpressionValue(format, "format(...)");
        return format;
    }

    public final GeoPoint calculateDestinationPoint(GeoPoint startPoint, double distanceMeters, double bearingDegrees) {
        Intrinsics.checkNotNullParameter(startPoint, "startPoint");
        double d = distanceMeters / EARTH_RADIUS_METERS;
        double radians = Math.toRadians(bearingDegrees);
        double radians2 = Math.toRadians(startPoint.getLatitude());
        double radians3 = Math.toRadians(startPoint.getLongitude());
        double asin = Math.asin((Math.sin(radians2) * Math.cos(d)) + (Math.cos(radians2) * Math.sin(d) * Math.cos(radians)));
        return new GeoPoint(Math.toDegrees(asin), Math.toDegrees((((radians3 + Math.atan2((Math.sin(radians) * Math.sin(d)) * Math.cos(radians2), Math.cos(d) - (Math.sin(radians2) * Math.sin(asin)))) + 9.42477796076938d) % 6.283185307179586d) - 3.141592653589793d));
    }
}
```

The `LocationUtils` class is a core utility responsible for all distance and navigation-related calculations used in the game’s geolocation mechanics. Its primary role is to determine whether the player is close enough to a relic to collect it and to provide direction and distance feedback on the map.

At its heart, the class defines two constants: `EARTH_RADIUS_METERS` (≈6,371 km) used for distance calculations based on the Haversine formula, and `COLLECTION_RADIUS_METERS`, set to 50 meters, the required proximity for a successful relic collection. The method `isWithinCollectionRadius()` uses these constants to check if the user’s current GPS position (`userLocation`) is within 50 meters of a relic’s location (`relicLocation`).

It also includes helper methods such as `calculateDistance()` (to compute the distance between two coordinates), `calculateBearing()` (to find the compass direction from the player to a relic), `getDirectionString()` (to convert the bearing angle into a readable compass direction like N, NE, or SW), and `formatDistance()` (to display distances neatly in meters or kilometers). Finally, `calculateDestinationPoint()` can project a new GPS coordinate based on a starting point, distance, and direction, useful for map navigation or spawning virtual objects.

<br />In this step, I hooked the `LocationUtils.calculateDistance()` method to observe how the game calculates the distance between the player’s current GPS coordinates and the relic’s location. The Frida script logs all input parameters (`lat1`, `lon1`, `lat2`, `lon2`) and the returned distance value. When executed, it printed the coordinates used in the distance check,  `lat1=37.421998333333335, lon1=-122.084, lat2=37.41883452522175, lon2=-122.0801532885869`, confirming that the function was actively determining whether the player was within the collection radius.

```javascript
Java.perform(function () {
	let LocationUtils = Java.use("com.eightksec.geofencegamble.utils.LocationUtils");
    LocationUtils["calculateDistance"].implementation = function (lat1, lon1, lat2, lon2) {
        console.log(`LocationUtils.calculateDistance is called: lat1=${lat1}, lon1=${lon1}, lat2=${lat2}, lon2=${lon2}`);
        let result = this["calculateDistance"](lat1, lon1, lat2, lon2);
        console.log(`LocationUtils.calculateDistance result=${result}`);
        return result;
    };
});
```

<br />

```
LocationUtils.calculateDistance is called: lat1=37.421998333333335, lon1=-122.084, lat2=37.41883452522175, lon2=-122.0801532885869
```

<br />From: com.eightksec.geofencegamble.model.GameState

```java
public final /* data */ class GameState {
    public static final int $stable = 8;
    private final int collectedRelics;
    private final boolean gameCompleted;
    private final boolean gameOver;
    private final boolean gameStarted;
    private final boolean gameWon;
    private final LatLng playerLocation;
    private final List<CityRelic> relics;
    private final long startTime;
    private final long timeRemaining;
    private final int totalRelics;

    public GameState() {
        this(null, null, false, false, false, false, 0L, 0L, 0, 0, 1023, null);
    }

    public static /* synthetic */ GameState copy$default(GameState gameState, List list, LatLng latLng, boolean z, boolean z2, boolean z3, boolean z4, long j, long j2, int i, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            list = gameState.relics;
        }
        if ((i3 & 2) != 0) {
            latLng = gameState.playerLocation;
        }
        if ((i3 & 4) != 0) {
            z = gameState.gameStarted;
        }
        if ((i3 & 8) != 0) {
            z2 = gameState.gameCompleted;
        }
        if ((i3 & 16) != 0) {
            z3 = gameState.gameOver;
        }
        if ((i3 & 32) != 0) {
            z4 = gameState.gameWon;
        }
        if ((i3 & 64) != 0) {
            j = gameState.startTime;
        }
        if ((i3 & 128) != 0) {
            j2 = gameState.timeRemaining;
        }
        if ((i3 & 256) != 0) {
            i = gameState.collectedRelics;
        }
        if ((i3 & 512) != 0) {
            i2 = gameState.totalRelics;
        }
        long j3 = j2;
        long j4 = j;
        boolean z5 = z3;
        boolean z6 = z4;
        boolean z7 = z;
        boolean z8 = z2;
        return gameState.copy(list, latLng, z7, z8, z5, z6, j4, j3, i, i2);
    }

    public final List<CityRelic> component1() {
        return this.relics;
    }

    /* renamed from: component10, reason: from getter */
    public final int getTotalRelics() {
        return this.totalRelics;
    }

    /* renamed from: component2, reason: from getter */
    public final LatLng getPlayerLocation() {
        return this.playerLocation;
    }

    /* renamed from: component3, reason: from getter */
    public final boolean getGameStarted() {
        return this.gameStarted;
    }

    /* renamed from: component4, reason: from getter */
    public final boolean getGameCompleted() {
        return this.gameCompleted;
    }

    /* renamed from: component5, reason: from getter */
    public final boolean getGameOver() {
        return this.gameOver;
    }

    /* renamed from: component6, reason: from getter */
    public final boolean getGameWon() {
        return this.gameWon;
    }

    /* renamed from: component7, reason: from getter */
    public final long getStartTime() {
        return this.startTime;
    }

    /* renamed from: component8, reason: from getter */
    public final long getTimeRemaining() {
        return this.timeRemaining;
    }

    /* renamed from: component9, reason: from getter */
    public final int getCollectedRelics() {
        return this.collectedRelics;
    }

    public final GameState copy(List<CityRelic> relics, LatLng playerLocation, boolean gameStarted, boolean gameCompleted, boolean gameOver, boolean gameWon, long startTime, long timeRemaining, int collectedRelics, int totalRelics) {
        Intrinsics.checkNotNullParameter(relics, "relics");
        return new GameState(relics, playerLocation, gameStarted, gameCompleted, gameOver, gameWon, startTime, timeRemaining, collectedRelics, totalRelics);
    }

    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof GameState)) {
            return false;
        }
        GameState gameState = (GameState) other;
        return Intrinsics.areEqual(this.relics, gameState.relics) && Intrinsics.areEqual(this.playerLocation, gameState.playerLocation) && this.gameStarted == gameState.gameStarted && this.gameCompleted == gameState.gameCompleted && this.gameOver == gameState.gameOver && this.gameWon == gameState.gameWon && this.startTime == gameState.startTime && this.timeRemaining == gameState.timeRemaining && this.collectedRelics == gameState.collectedRelics && this.totalRelics == gameState.totalRelics;
    }

    public int hashCode() {
        int hashCode = this.relics.hashCode() * 31;
        LatLng latLng = this.playerLocation;
        return ((((((((((((((((hashCode + (latLng == null ? 0 : latLng.hashCode())) * 31) + Boolean.hashCode(this.gameStarted)) * 31) + Boolean.hashCode(this.gameCompleted)) * 31) + Boolean.hashCode(this.gameOver)) * 31) + Boolean.hashCode(this.gameWon)) * 31) + Long.hashCode(this.startTime)) * 31) + Long.hashCode(this.timeRemaining)) * 31) + Integer.hashCode(this.collectedRelics)) * 31) + Integer.hashCode(this.totalRelics);
    }

    public String toString() {
        return "GameState(relics=" + this.relics + ", playerLocation=" + this.playerLocation + ", gameStarted=" + this.gameStarted + ", gameCompleted=" + this.gameCompleted + ", gameOver=" + this.gameOver + ", gameWon=" + this.gameWon + ", startTime=" + this.startTime + ", timeRemaining=" + this.timeRemaining + ", collectedRelics=" + this.collectedRelics + ", totalRelics=" + this.totalRelics + ')';
    }

    public GameState(List<CityRelic> relics, LatLng latLng, boolean z, boolean z2, boolean z3, boolean z4, long j, long j2, int i, int i2) {
        Intrinsics.checkNotNullParameter(relics, "relics");
        this.relics = relics;
        this.playerLocation = latLng;
        this.gameStarted = z;
        this.gameCompleted = z2;
        this.gameOver = z3;
        this.gameWon = z4;
        this.startTime = j;
        this.timeRemaining = j2;
        this.collectedRelics = i;
        this.totalRelics = i2;
    }

}
```

The `GameState` class represents the **current status of the game** in *GeofenceGamble*, tracking both the player’s progress and the overall game conditions. It holds essential data such as the list of available relics (`relics`), the player’s current location (`playerLocation`), and several boolean flags indicating whether the game has started, been completed, is over, or has been won. Additionally, it stores timing information (`startTime`, `timeRemaining`) and counters for how many relics have been collected (`collectedRelics`) versus the total number available (`totalRelics`).

This class is particularly interesting because it centralizes all the game’s logic about **player state and victory conditions**. By manipulating its fields or intercepting its initialization through Frida, an attacker could simulate any in-game scenario such as instantly winning, having all relics collected, or extending the timer indefinitely. Essentially, `GameState` serves as the game’s memory snapshot, and controlling it means controlling the entire game flow.

<br />

```javascript
Java.perform(function () {
    GameState["$init"].overload('java.util.List', 'com.google.android.gms.maps.model.LatLng', 'boolean', 'boolean', 'boolean', 'boolean', 'long', 'long', 'int', 'int').implementation = function (relics, latLng, z, z2, z3, z4, j, j2, i, i2) {
        console.log(`GameState.$init is called: relics=${relics}, latLng=${latLng}, z=${z}, z2=${z2}, z3=${z3}, z4=${z4}, j=${j}, j2=${j2}, i=${i}, i2=${i2}`);
        this["$init"](relics, latLng, z, z2, z3, z4, j, j2, i, i2);
    };
});
```

<br />

| Function Parameter | Data Type                                  | Corresponding Variable | Description                                                  |
| ------------------ | ------------------------------------------ | ---------------------- | ------------------------------------------------------------ |
| `relics`           | `java.util.List<CityRelic>`                | `relics`               | A list of collectible items (relics) available in the game.  |
| `latLng`           | `com.google.android.gms.maps.model.LatLng` | `playerLocation`       | The player’s current GPS location on the map.                |
| `z`                | `boolean`                                  | `gameStarted`          | Indicates whether the game session has started.              |
| `z2`               | `boolean`                                  | `gameCompleted`        | True when all objectives are finished.                       |
| `z3`               | `boolean`                                  | `gameOver`             | True when the game has ended (e.g., failed or expired).      |
| `z4`               | `boolean`                                  | `gameWon`              | True when the player successfully wins the game.             |
| `j`                | `long`                                     | `startTime`            | The timestamp when the game session started.                 |
| `j2`               | `long`                                     | `timeRemaining`        | The countdown timer showing how much time is left (in milliseconds). |
| `i`                | `int`                                      | `collectedRelics`      | The number of relics the player has already collected.       |
| `i2`               | `int`                                      | `totalRelics`          | The total number of relics available in the current game.    |

<br />

The `GameState` class represents the core state of the game, tracking progress, timing, and player status. The constructor of this class which was hooked using Frida initializes all these variables whenever a new game state instance is created. By observing the parameters passed to the constructor, we can understand how the game updates and maintains its internal logic.

Here’s how each parameter in the hooked function maps to the class fields:

| Function Parameter | Data Type                                  | Corresponding Variable | Description                                                  |
| ------------------ | ------------------------------------------ | ---------------------- | ------------------------------------------------------------ |
| `relics`           | `java.util.List<CityRelic>`                | `relics`               | A list of collectible items (relics) available in the game.  |
| `latLng`           | `com.google.android.gms.maps.model.LatLng` | `playerLocation`       | The player’s current GPS location on the map.                |
| `z`                | `boolean`                                  | `gameStarted`          | Indicates whether the game session has started.              |
| `z2`               | `boolean`                                  | `gameCompleted`        | True when all objectives are finished.                       |
| `z3`               | `boolean`                                  | `gameOver`             | True when the game has ended                                 |
| `z4`               | `boolean`                                  | `gameWon`              | True when the player successfully wins the game.             |
| `j`                | `long`                                     | `startTime`            | The timestamp when the game session started.                 |
| `j2`               | `long`                                     | `timeRemaining`        | The countdown timer showing how much time is left (in milliseconds). |
| `i`                | `int`                                      | `collectedRelics`      | The number of relics the player has already collected.       |
| `i2`               | `int`                                      | `totalRelics`          | The total number of relics available in the current game.    |

In the Frida output, the repeated calls to `GameState.$init` show that the app continuously re-instantiates the game state, likely to refresh timer values (`timeRemaining` drops by 1000 ms per call). This discovery is useful in a CTF context because it reveals a potential point for manipulation. For example, intercepting this constructor to modify parameters like `gameWon`, `collectedRelics`, or `timeRemaining` to achieve victory instantly or prevent the timer from expiring

```
GameState.$init is called: relics=[object Object], latLng=null, z=true, z2=false, z3=false, z4=false, j=0, j2=1800000, i=0, i2=33
GameState.$init is called: relics=[object Object], latLng=null, z=true, z2=false, z3=false, z4=false, j=0, j2=1799000, i=0, i2=33
GameState.$init is called: relics=[object Object], latLng=null, z=true, z2=false, z3=false, z4=false, j=0, j2=1798000, i=0, i2=33
GameState.$init is called: relics=[object Object], latLng=null, z=true, z2=false, z3=false, z4=false, j=0, j2=1797000, i=0, i2=33
```

<br />**Method 1: Forcing a Win by Hooking `GameState`**

I hooked `GameState`’s constructor with Frida and forced every new state to be a win. The hook keeps the original `relics` and `playerLocation` but sets `gameCompleted`, `gameOver`, and `gameWon` to `true`, `timeRemaining` to `0`, and `collectedRelics` to equal `totalRelics`. Calling the constructor with `this["$init"](relics, latLng, z, true, true, true, j, 0, i2, i2)` preserves any constructor side-effects while making the app think all relics were collected

```javascript
setTimeout(function() {
    Java.scheduleOnMainThread(function () {
        Java.perform(function() {
            let RootDetector = Java.use("com.eightksec.geofencegamble.security.RootDetector");
    		RootDetector["isDeviceRootedOrEmulator"].implementation = function () {
        		this["isDeviceRootedOrEmulator"]();
       			return false;
    };
            
            let GameState = Java.use("com.eightksec.geofencegamble.model.GameState");
            GameState["$init"].overload('java.util.List', 'com.google.android.gms.maps.model.LatLng', 'boolean', 'boolean', 'boolean', 'boolean', 'long', 'long', 'int', 'int').implementation = function (relics, latLng, z, z2, z3, z4, j, j2, i, i2) {
                console.log(`GameState.$init is called: relics=${relics}, latLng=${latLng}, z=${z}, z2=${z2}, z3=${z3}, z4=${z4}, j=${j}, j2=${j2}, i=${i}, i2=${i2}`);
                this["$init"](relics, latLng, z, true, true, true, j, 0, i2, i2);
            };
        })
    })
}, 20000);
```

<br />

![](/assets/img/8ksec/GeofenceGamble/5.png)

<br />

![](/assets/img/8ksec/GeofenceGamble/6.png)

<br />

**Method 2: Hooking `calculateDestinationPoint` to place all relics within 10 m of the player**

I hooked into the `calculateDestinationPoint()` function inside `LocationUtils`, which is responsible for determining a new geographic coordinate based on a starting point, a distance, and a bearing (direction). This function essentially calculates where a player would end up after moving a certain distance in a specific direction.

By attaching a Frida hook to this method I logged its inputs and outputs. From the traces I saw the app repeatedly calculate destination points near the real coordinates (`37.421998, -122.084`) with varying distances and bearings, confirming how it models player movement and evaluates proximity to relics.

```javascript
Java.perform(function() {
    let LocationUtils = Java.use("com.eightksec.geofencegamble.utils.LocationUtils");
	LocationUtils["calculateDestinationPoint"].implementation = function (startPoint, distanceMeters, bearingDegrees) {
        console.log(`LocationUtils.calculateDestinationPoint is called: startPoint=${startPoint}, distanceMeters=${distanceMeters}, bearingDegrees=${bearingDegrees}`);
        let result = this["calculateDestinationPoint"](startPoint, distanceMeters, bearingDegrees);
        console.log(`LocationUtils.calculateDestinationPoint result=${result}`);
        return result;
    };
});
```

<br />

```
LocationUtils.calculateDestinationPoint result=37.42201201779618,-122.08411192018855,0.0
LocationUtils.calculateDestinationPoint is called: startPoint=37.421998333333335,-122.084,0.0, distanceMeters=1356.506001232884, bearingDegrees=254.79427525687237
LocationUtils.calculateDestinationPoint result=37.42197474537257,-122.08410927432776,0.0
LocationUtils.calculateDestinationPoint is called: startPoint=37.421998333333335,-122.084,0.0, distanceMeters=2399.1182223347, bearingDegrees=29.841784787974696
LocationUtils.calculateDestinationPoint result=37.422076340726825,-122.08394365154857,0.0
```

<br />

I hooked the `calculateDestinationPoint` function and modified its logic to always use a fixed distance of **10 meters** instead of the real one. Since the game’s collection logic checks whether the player is within **50 meters** of a relic to collect it, forcing all destination points to just 10 meters away meant every relic appeared to be within range. As a result, I could collect all relics surrounding the player and easily win the game.

```javascript
Java.perform(function() {
    let RootDetector = Java.use("com.eightksec.geofencegamble.security.RootDetector");
    RootDetector["isDeviceRootedOrEmulator"].implementation = function () {
        this["isDeviceRootedOrEmulator"]();
        return false;
    };
    
    let LocationUtils = Java.use("com.eightksec.geofencegamble.utils.LocationUtils");
    LocationUtils["calculateDestinationPoint"].implementation = function (startPoint, distanceMeters, bearingDegrees) {
        console.log(`LocationUtils.calculateDestinationPoint is called: startPoint=${startPoint}, distanceMeters=${distanceMeters}, bearingDegrees=${bearingDegrees}`);
        let result = this["calculateDestinationPoint"](startPoint, 10.0, bearingDegrees);
        console.log(`LocationUtils.calculateDestinationPoint result=${result}`);
        return result;
    };
});
```

<br />

![](/assets/img/8ksec/GeofenceGamble/7.png)

