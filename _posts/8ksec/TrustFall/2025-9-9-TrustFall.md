---
title: TrustFall - 8kSec
date: 2025-9-9 00:00:00 +/-TTTT
categories: [8kSec]
tags: [8kSec, writeup, mobile penetration testing, ios]     # TAG names should always be lowercase
---

<br />

**Description:**

TrustFall is a secure iOS workspace app that uses deep linking to load trusted content inside an embedded browser. It claims to only open links from approved domains, but its defenses aren’t as strong as they seem. Direct access to untrusted domains is blocked unless you find a loophole.

<br />

**Objective:**

- Find a way to trick the app into loading an unintended URL and triggering the hidden flag.
- Use deep link manipulation to bypass the app’s domain filtering and get it to load a crafted URL. 

<br />

**Explore the application**

When the app launches, it displays a screen with three buttons, but none of them perform any actions.

![](/assets/img/8ksec/TrustFall/2.jpg)

<br />

From the **Info.plist** file, this entry registers the app to automatically launch whenever a URL beginning with `trustfall://` is opened.

```json
└─# ipsw plist Info.plist                
{
  "BuildMachineOSBuild": "24D70",
  "CFBundleDevelopmentRegion": "en",
  "CFBundleExecutable": "TrustFall",
  "CFBundleURLTypes": [
    {
      "CFBundleTypeRole": "Editor",
      "CFBundleURLName": "trustfall",
      "CFBundleURLSchemes": [
        "trustfall"
      ]
    }
  ],

```

<br />

**Reverse Engineering With Ghidra**

the function `_$s9TrustFall11ContentViewV17handleIncomingURLyy10Foundation0G0VF` When demangled, this becomes:

```
TrustFall.ContentView.handleIncomingURL(_ url: Foundation.URL)
```

<br />

This function handles URLs that the app receives (via a deep link)

![](/assets/img/8ksec/TrustFall/1.png)

<br />

It Checks if the URL’s **scheme** equals `"trustfall"`.

<br />

![](/assets/img/8ksec/TrustFall/5.png)

<br />

Then checks if the **host** equals `"open"`.

![](/assets/img/8ksec/TrustFall/2.png)

<br />

It parses the URL’s query parameters and verifies whether the resulting URL begins with **"[https://8ksec.io](https://8ksec.io/)"**.

<br />

![](/assets/img/8ksec/TrustFall/3.png)

<br />

If the domain matches `"8ksec.io"`, the app updates its SwiftUI states as expected. Otherwise, it changes its internal state to display the flag, indicating that an unsafe or modified URL was detected.

![](/assets/img/8ksec/TrustFall/4.png)

<br />

| Step | Action                                                | Description                                                  |
| ---- | ----------------------------------------------------- | ------------------------------------------------------------ |
| 1    | Extract URL scheme                                    | Only process URLs with the scheme `"trustfall"`.             |
| 2    | Extract host                                          | Only handle URLs where host is `"open"`.                     |
| 3    | Parse query parameters                                | Use `URLComponents` to parse key–value pairs from the query string. |
| 4    | Find a specific query item                            | Looks for a certain query (maybe `?url=` or similar).        |
| 5    | Create a new URL from that query value                | Attempt to sanitize or validate it.                          |
| 6    | Check if the new URL starts with `"https://8ksec.io"` | Trusted domain check.                                        |
| 7    | If trusted                                            | Load the URL into SwiftUI’s state.                           |
| 8    | If **not** trusted                                    | Set a SwiftUI state to display `"CTF{bad_url_sanitization}"`. |

<br />

If you open the deeplink `trustfall://open?url=https://8ksec.io`, the app will load the **[https://8ksec.io](https://8ksec.io/)** website within its embedded browser.

```
trustfall://open?url=https://8ksec.io
```

<br />

![](/assets/img/8ksec/TrustFall/5.jpg)

<br />

This Frida script watches whenever the app’s web view (`WKWebView`) loads a web page. Each time it happens, it logs the **exact URL** the app is trying to load.

```javascript
Interceptor.attach(ObjC.classes.WKWebView["- loadRequest:"].implementation, {
    onEnter(args) {
        const req = new ObjC.Object(args[2]);
        const url = req.URL().absoluteString();
        console.log("[WKWebView] Loading URL:", url.toString());
    }
});
```

Run the app with this Frida script, open the deeplink, and you’ll see the script log that it’s opening the URL:

```
[iOS Device::com.8ksec.TrustFall.W46SY5ZJ6Z ]-> [WKWebView] Loading URL: https://8ksec.io
```

<br />

Because the app only tests whether the URL string **starts with** `"https://8ksec.io"`, that check is too weak and can be bypassed by URLs where `8ksec.io` is merely part of a larger hostname or a subdomain of another domain. For example:

```
trustfall://open?url=https://8ksec.io.google.com
trustfall://open?url=https://8ksec.iogoogle.com
trustfall://open?url=https://8ksec.io.com
```

<br />

If you open the deeplink `trustfall://open?url=https://8ksec.io.google.com`, the app will attempt to load `https://8ksec.io.google.com`. And because that site does not exist, the embedded browser will display a blank page.

```
trustfall://open?url=https://8ksec.io.google.com
```

<br />

```
[iOS Device::com.8ksec.TrustFall.W46SY5ZJ6Z ]-> [WKWebView] Loading URL: https://8ksec.io.google.com
```

<br />

![](/assets/img/8ksec/TrustFall/4.jpg)

<br />

If the URL isn't trusted (doesn't start with `https://8ksec.io`), the app displays an alert **"Suspicious Activity Detected"** and shows the challenge flag.

<br />

![](/assets/img/8ksec/TrustFall/6.png)

<br />

![](/assets/img/8ksec/TrustFall/7.png)

<br />

To retrieve the flag, open a URL that **is not trusted** (it does **not** start with `https://8ksec.io`) but whose host **contains** `8ksec.io`. Examples:

```
trustfall://open?url=http://8ksec.io
trustfall://open?url=http://8ksec.io.com
trustfall://open?url=any://8ksec.iogoogle.com
```

<br />

![](/assets/img/8ksec/TrustFall/1.jpg)

<br />

**Flag:** CTF{bad_url_sanitization}

<br />

**Note:** On smaller iPhones (e.g., iPhone 7, 8, X), the flag might not be visible because it appears at the bottom of the screen and can be hidden due to the limited display size. To see the flag, use a larger iPhone model (e.g., iPhone 7 Plus, 8 Plus, or any Pro/Pro Max models).
